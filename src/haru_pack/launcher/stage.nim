## haru-pack staging: per-user, content-addressed, atomic, verified on every reuse.
##
## THREAT MODEL boundary B10. The staged tree is what the launcher executes, so whoever
## can populate `<cache>/<key>/` before we do gets code execution under the launcher's
## identity (and, on Windows, behind its signature). The previous version of this file
## trusted a bare `.ready` existence check on a directory named after 64 bits of the
## footer digest, and — worse — returned a pre-existing `<cache>/<key>/` even with no
## `.ready` at all, because the atomic-move step silently skipped when the destination
## already existed. See INV-STAGE-01, INV-STAGE-02.
##
## What this file now guarantees:
##   * the stage directory name binds the caller's key AND 128 bits of the payload's own
##     sha256, so a tree staged from a different payload can never be reused for this one;
##   * `.ready` is a token, not a marker: stage format, key, payload digest, owning uid,
##     file count, and the digest of `.stage-files` (a sha256 per staged file);
##   * every file staged out of the payload is re-hashed on reuse and any mismatch,
##     removal, or unparseable token is fatal — the launcher never runs a tree it cannot
##     account for;
##   * the stage directory must be a real directory (not a symlink), owned by the calling
##     user, and not group- or world-writable; group/other write bits are stripped from
##     everything extracted;
##   * archive entry paths are checked here, before zippy sees them (defence in depth —
##     zippy 0.10.12 does check too, see `unsafeEntryPath`).
##
## What it does NOT guarantee, stated plainly: this does not stop an attacker already
## running as the same user. They can rewrite the tree and regenerate `.ready` to match,
## because every input to that token is readable from the binary they are attacking.
## What it does stop is a *different* user pre-creating or tampering with the cache, a
## stale/corrupt tree, and reuse across payloads. Closing the same-uid case needs an OS
## boundary (separate service account, or a root-owned read-only stage), not a checksum.
import std/[os, strutils, algorithm, times]
import zippy/ziparchives
import nimcrypto/sha2
import xzdec
when defined(posix): import std/posix
when defined(windows): import std/[osproc, winlean]

type StageError* = object of CatchableError

const
  ## Ceiling on a single expanded payload member. The only thing haru-pack compresses today
  ## is the `uv` binary (~56 MB linux, ~65 MB windows raw), so 512 MB is generous by an
  ## order of magnitude while still refusing the absurd values a corrupt or tampered
  ## `.size` sidecar can carry. Raise it deliberately if a bigger member is ever compressed.
  MaxExpandedBytes* = 512 * 1024 * 1024
  StageFormat* = "haru-pack-stage/2"
  ReadyName* = ".ready"
  FilesName* = ".stage-files"
  LinksName* = ".haru-links"
  ## Ceiling on entries in `.haru-links`. Measured, not guessed: a thick linux-x86_64
  ## payload with CPython 3.13 carries **1047** — four interpreter aliases plus `idle3`,
  ## `pydoc3`, the pkgconfig `.pc` pair, a man page, and roughly a thousand terminfo
  ## aliases. 16384 leaves room for a bigger terminfo database without being an open door:
  ## every entry costs a full file copy, so the count is what bounds how much disk a
  ## rewritten table can make the launcher write.
  MaxLinkEntries* = 16384
  KeyChars = {'0'..'9', 'a'..'f', 'A'..'F'}

proc baseDir*(): string =
  ## regenerable tree -> LOCALAPPDATA (win) / XDG_CACHE_HOME (linux) / Caches (mac)
  when defined(windows):
    result = getEnv("LOCALAPPDATA", getHomeDir() / "AppData" / "Local")
  elif defined(macosx):
    result = getEnv("HOME") / "Library" / "Caches"
  else:
    result = getEnv("XDG_CACHE_HOME", getHomeDir() / ".cache")
  result = result / "haru-pack"

# ------------------------------------------------ staging root: RAM-backed + safety refusal
#
# Phase 2 (docs/adr/0004-reap-ram-staging.md). The launcher resolves ONE staging root before
# it stages, then stages AND (if --reap) reaps a create-and-delete-own subtree beneath it.
# These are the primitives; main.nim composes the precedence and passes the chosen root to
# `stageZip`. Keeping the delete target = the subtree the launcher itself created this run is
# the whole safety story (INV-BASE-01 / INV-REAP-01): a hostile BASE_PATH can relocate staging
# but can never turn the reaper into an arbitrary-delete.

proc stripTrailingSep(p: string): string =
  ## Drop trailing '/' or '\' but never collapse a lone "/" to "".
  result = p
  while result.len > 1 and (result[^1] == '/' or result[^1] == '\\'):
    result.setLen(result.len - 1)

proc physicalPrefix(path: string): string {.used.} =
  ## Resolve symlinks on the longest EXISTING ancestor of `path`, then re-attach the
  ## not-yet-created tail lexically. A purely lexical root check is fooled by a symlink: a
  ## `BASE_PATH=/tmp/x` where `/tmp/x -> $HOME` (or `-> /`) passes every string comparison in
  ## `refuseUnsafeRoot` yet stages — and, with `--reap`, reaps — a subtree at the real,
  ## forbidden location. Only an EXISTING path can be resolved to its physical form, so we
  ## realpath the deepest existing ancestor and re-append whatever the launcher has not created
  ## yet (INV-BASE-01 symlink hardening, 2026-09-11).
  if path.len == 0: return path
  var existing = stripTrailingSep(path)
  var tail = ""
  while existing.len > 0 and
        not (fileExists(existing) or dirExists(existing) or symlinkExists(existing)):
    let (parent, name) = splitPath(existing)
    if parent.len == 0 or parent == existing: break
    tail = (if tail.len == 0: name else: name / tail)
    existing = stripTrailingSep(parent)
  if existing.len == 0: return path
  var real = existing
  try: real = expandFilename(existing)     # follows symlinks; requires existence
  except CatchableError: real = existing
  result = (if tail.len == 0: real else: real / tail)

proc refuseUnsafeRoot*(root: string): string =
  ## "" if `root` is an acceptable staging root; otherwise a one-line diagnostic. A staging
  ## root that is empty, the filesystem root '/', a Windows drive/UNC root, or the user's home
  ## directory root is REFUSED (INV-BASE-01). The launcher creates and later reaps a named
  ## subtree under this root, so the root must never be a location whose pollution or deletion
  ## would be catastrophic. This fires defensively at RUNTIME (the target's real '/' and $HOME
  ## are only knowable here); the build refuses the obvious shapes too (docs/adr/0004 §5).
  if root.len == 0: return "empty staging root"
  let p = stripTrailingSep(root)
  # Canonicalize `.`/`..` LEXICALLY (mirrors the build's os.path.normpath) before the root/home
  # comparisons. Without this a runtime BASE_PATH that RESOLVES to a refused root — e.g.
  # `$HOME/x/..` or `/tmp/..` — slips past the exact-string checks below and stages (and, with
  # --reap, reaps) a subtree directly under $HOME or '/'. That is the very thing this guard
  # exists to refuse; the string form alone made "can never name a bare root" untrue for the
  # attacker-controlled env value (INV-BASE-01, adversarial-review finding 2026-09-10).
  let pn = normalizedPath(p)
  if p == "/" or pn == "/": return "staging root is the filesystem root '/'"
  when defined(windows):
    # "C:", "C:\", "C:/" (drive root) and "\\", "//" (UNC root) are volume roots.
    if p.len >= 2 and p.len <= 3 and p[1] == ':':
      return "staging root is a drive root: " & root
    if p == "\\\\" or p == "//":
      return "staging root is a UNC root: " & root
    if pn.len >= 2 and pn.len <= 3 and pn[1] == ':':
      return "staging root is a drive root: " & root
  let home = stripTrailingSep(getHomeDir())
  if p == home or pn == normalizedPath(home):
    return "staging root is the home-directory root: " & root
  # Symlink / junction hardening. The lexical checks above are blind to reparse points, and
  # the resolution primitive differs by OS, so the two platforms are handled differently — but
  # BOTH refuse the attack (a `BASE_PATH` that reaches a forbidden root through a link). Proven
  # bypassable before this on POSIX (2026-09-11): `/tmp/x -> $HOME` returned ACCEPTED.
  when defined(windows):
    # `getFullPathNameW` — what `expandFilename` uses on Windows — does NOT follow symlinks or
    # junctions, and shipping untested `GetFinalPathNameByHandleW` FFI inside a delete-primitive
    # guard is the wrong risk. So Windows FAILS CLOSED: refuse a staging root whose existing
    # prefix passes through ANY reparse point (symlink OR junction; both set
    # FILE_ATTRIBUTE_REPARSE_POINT, which `symlinkExists` tests). A packager who needs that
    # location points `BASE_PATH` at a non-reparse path. Compile + review only on this host.
    var probe = p
    while true:
      if symlinkExists(probe):
        return "staging root passes through a symlink/junction (refused on Windows): " & root
      let parent = stripTrailingSep(parentDir(probe))
      if parent.len == 0 or parent == probe: break
      probe = parent
  else:
    # POSIX: `realpath` (via `expandFilename`) follows symlinks, so resolve the existing prefix
    # to its PHYSICAL location and re-run the refusals. A benign symlink is allowed; one that
    # resolves to '/' or the home root is refused.
    let phys = stripTrailingSep(physicalPrefix(p))
    if phys != p:
      let pp = normalizedPath(phys)
      if phys == "/" or pp == "/":
        return "staging root resolves through a symlink to the filesystem root '/': " & root
      if phys == home or pp == normalizedPath(home):
        return "staging root resolves through a symlink to the home-directory root: " & root
  return ""

proc isDirWritable(dir: string): bool {.used.} =   # {.used.}: consumed only on the Linux path
  ## Probe writability by creating and removing a private subdir — honest about whether we can
  ## actually stage here, rather than trusting existence alone.
  if not dirExists(dir): return false
  let probe = dir / ("haru-wtest-" & $getCurrentProcessId())
  try:
    createDir(probe)
    removeDir(probe)
    result = true
  except CatchableError:
    result = false

proc ramBackedRoot*(): string =
  ## Best-effort RAM-backed staging root (docs/adr/0004 §3).
  ##
  ## LINUX: /dev/shm is a tmpfs with REAL PATHS Python can import from, so it is the practical
  ## mechanism. memfd is deliberately NOT used: an anonymous memfd has no path, so a staged
  ## import tree cannot live there. If /dev/shm is missing or not writable, fall back to the
  ## persistent cache and say so on stderr — no silent promise.
  ##
  ## WINDOWS / macOS: there is no guaranteed RAM filesystem, so --ephemeral is best-effort only
  ## and NOT guaranteed; fall back to the persistent cache with an honest note.
  ##
  ## HONEST DISCLAIMER: --ephemeral governs only where the STUB stages the payload tree. It
  ## cannot control the packed application's OWN disk writes. No strong promises.
  when defined(linux):
    const shm = "/dev/shm"
    if isDirWritable(shm):
      return shm / "haru-pack"
    stderr.writeLine "haru-pack: --ephemeral requested but /dev/shm is unavailable or not " &
                     "writable; staging to the persistent cache instead."
    return baseDir()
  else:
    stderr.writeLine "haru-pack: --ephemeral is best-effort and not guaranteed on this OS " &
                     "(no RAM-backed filesystem); staging to the persistent cache instead."
    return baseDir()

# --------------------------------------------------- RAM-fit detection (docs/adr/0007)
#
# A machine with little free memory (a 512 MB CI runner, a small VPS) cannot hold a staged
# interpreter + payload in a tmpfs. Before auto-staging to /dev/shm the stub asks whether the
# tree PROVABLY fits; if it cannot prove it, it falls back to the persistent cache rather than
# filling RAM and dying mid-extract. Flat by design (early returns, one small proc per source),
# and fail-safe: anything unmeasurable answers "does not fit", never a gamble.

# `haruMemRoot` is a COMPILE-TIME path prefix for the memory-budget files, empty in every
# shipped build (so real paths are read). It exists only so a test can compile a launcher that
# reads fake `/proc/meminfo` and `/sys/fs/cgroup/*` files and prove the cgroup gate — it is not
# a runtime env surface, and statvfs("/dev/shm") is never redirected.
const MemRoot {.strdefine: "haruMemRoot".} = ""

proc readValueFile(path: string): string =
  ## First line of a small sysfs/procfs file, stripped, or "" when it cannot be read.
  try:
    return readFile(path).strip()
  except CatchableError:
    return ""

proc parseInt64OrNeg(s: string): int64 =
  if s.len == 0: return -1
  try: return int64(parseBiggestInt(s))
  except ValueError: return -1

proc shmFreeBytes(): int64 =
  ## Free bytes on the /dev/shm tmpfs, or -1 when it cannot be measured.
  when defined(linux):
    var st: Statvfs
    if statvfs("/dev/shm", st) != 0: return -1
    return int64(st.f_bavail) * int64(st.f_frsize)
  else:
    return -1

proc memAvailableBytes(): int64 =
  ## `/proc/meminfo` MemAvailable in bytes, or -1 when it cannot be read/parsed.
  when defined(linux):
    let text = readValueFile(MemRoot & "/proc/meminfo")
    if text.len == 0: return -1
    for line in text.splitLines():
      if not line.startsWith("MemAvailable:"): continue
      let parts = line.splitWhitespace()          # ["MemAvailable:", "12345", "kB"]
      if parts.len < 2: return -1
      let kb = parseInt64OrNeg(parts[1])
      if kb < 0: return -1
      return kb * 1024
    return -1
  else:
    return -1

proc cgroupAvailBytes(): int64 =
  ## Memory still available under a cgroup memory limit, or -1 when there is genuinely no
  ## cgroup memory limit in effect (the limit file is ABSENT, or, for v2, explicitly "max"). A
  ## container / CI runner caps memory here while /proc/meminfo still reports the HOST's RAM, so
  ## a fit check blind to the cgroup would OOM exactly the small box the gate protects
  ## (adversarial review W3). cgroup v2: `memory.max` ("max" = unlimited) minus `memory.current`.
  ## v1: `memory.limit_in_bytes` (a near-int64 sentinel = unlimited) minus `memory.usage_in_bytes`.
  ##
  ## Fail-CLOSED on corruption, matching shmFreeBytes/memAvailableBytes: a limit (or usage) file
  ## that EXISTS but does not parse returns 0 ("does not fit"), never -1 ("not gated"). -1 is
  ## reserved for a limit that is genuinely absent or explicitly unlimited. The previous version
  ## folded "absent" and "present but corrupt" into the same -1 (parseInt64OrNeg returns -1 for
  ## both an empty read and an unparseable one), so a corrupted-but-present sysfs file was
  ## silently treated as "no limit" and ALLOWED RAM staging (adversarial re-review finding).
  ## `fileExists` (not the parsed value) is what decides "absent" vs "present", so the two cases
  ## can no longer collide.
  when defined(linux):
    let maxPath = MemRoot & "/sys/fs/cgroup/memory.max"
    if fileExists(maxPath):                                   # v2
      let maxRaw = readValueFile(maxPath)
      if maxRaw == "max": return -1                           # explicit unlimited
      let limit = parseInt64OrNeg(maxRaw)
      if limit < 0: return 0                                  # present but unparseable -> closed
      let curPath = MemRoot & "/sys/fs/cgroup/memory.current"
      if not fileExists(curPath): return 0                    # limit known, usage unknown -> closed
      let cur = parseInt64OrNeg(readValueFile(curPath))
      if cur < 0: return 0                                    # usage present but unparseable -> closed
      return (if limit > cur: limit - cur else: 0'i64)
    let limPath = MemRoot & "/sys/fs/cgroup/memory/memory.limit_in_bytes"
    if fileExists(limPath):                                   # v1
      let limit = parseInt64OrNeg(readValueFile(limPath))
      if limit < 0: return 0                                  # present but unparseable -> closed
      if limit > (int64.high div 2): return -1                # v1 sentinel = "unlimited"
      let usagePath = MemRoot & "/sys/fs/cgroup/memory/memory.usage_in_bytes"
      if not fileExists(usagePath): return 0                  # limit known, usage unknown -> closed
      let usage = parseInt64OrNeg(readValueFile(usagePath))
      if usage < 0: return 0                                  # usage present but unparseable -> closed
      return (if limit > usage: limit - usage else: 0'i64)
    return -1                                                 # neither v2 nor v1 file present
  else:
    return -1

proc ramWouldFit*(unpackedBytes: int64): bool =
  ## Fail-safe RAM-fit check (docs/adr/0007): the staged tree plus 20% headroom must fit the
  ## /dev/shm tmpfs, MemAvailable, AND the cgroup budget when a finite one exists. An unknown
  ## size (0), a non-Linux host, or any unreadable measurement answers false — the stub never
  ## stages to RAM it cannot prove. This removes the PREDICTABLE OOM (a tree that never had room
  ## in the knowable budget); it is a size check, not a reservation, so it cannot promise "never
  ## OOM" against a race with another process (docs/adr/0007 §5).
  if unpackedBytes <= 0: return false
  # Overflow-safe headroom: never FORM `unpackedBytes + unpackedBytes div 5` if it could exceed
  # int64 — under -d:release that add raises an uncatchable OverflowDefect and crashes instead of
  # failing safe (adversarial review W2). The largest value whose ×1.2 still fits is
  # (int64.high div 6) * 5; above it, refuse. The test is a DIVISION, which cannot overflow.
  if unpackedBytes > (int64.high div 6) * 5: return false
  let need = unpackedBytes + unpackedBytes div 5      # x1.2, cannot overflow now
  let shm = shmFreeBytes()
  if shm < 0 or shm < need: return false
  let mem = memAvailableBytes()
  if mem < 0 or mem < need: return false
  let cg = cgroupAvailBytes()                          # -1 when no finite limit -> not gated
  if cg >= 0 and cg < need: return false
  return true

# --------------------------------------------------- shred-on-reap: matching-length overwrite
#
# --overwrite (docs/adr/0004 §5b, INV-SHRED-01). Before the reaper unlinks a staged file it
# overwrites the file's WHOLE logical extent with matching-length random bytes and fsyncs, so a
# proprietary model blob written to disk resists SIMPLE logical file-undelete (Recuva/PhotoRec/
# TestDisk) on a non-CoW filesystem on a spinning disk. This is NOT a secure erase and must not
# be sold as one: SSD FTL/wear-leveling (LBA != PBA), copy-on-write filesystems, snapshots/VSS,
# journals, and swap can all retain the original bytes. The durable defense is --encrypt +
# --ephemeral (decrypt only to /dev/shm, nothing to shred) — see THREAT_MODEL.md.
#
# Native Nim only: no PowerShell (locked on hardened targets), no shipped SDelete, no `cipher /w`
# (that wipes FREE SPACE, not a named file). The bare-target property (uvfetch) is preserved.

const ShredChunkBytes = 1024 * 1024
  ## The reused overwrite buffer size. One buffer is filled once and re-used for every file:
  ## crypto RNG is needless and slow for multi-GB — we are occupying LBAs, not resisting
  ## cryptanalysis. A megabyte keeps the write loop's syscall count low on large blobs.

proc newShredBuffer*(): string =
  ## A ShredChunkBytes buffer of fast, non-crypto pseudo-random bytes (INV-SHRED-01). xorshift64
  ## so there is no dependency and no per-byte RNG call; seeded from time+pid so two runs differ,
  ## which does not matter for correctness (the bytes only have to not be the plaintext).
  result = newString(ShredChunkBytes)
  var st = uint64(epochTime() * 1_000_000.0) xor
           (uint64(getCurrentProcessId()) shl 32) xor 0x9E3779B97F4A7C15'u64
  if st == 0'u64: st = 0x1234567'u64
  var i = 0
  while i < result.len:
    st = st xor (st shl 13); st = st xor (st shr 7); st = st xor (st shl 17)
    var v = st
    var j = 0
    while j < 8 and i < result.len:
      result[i] = char(v and 0xFF'u64)
      v = v shr 8; inc i; inc j

proc overwriteFile*(path: string; buf: string): bool =
  ## Overwrite the full logical extent of `path` IN PLACE with `buf`'s bytes, fsync, close.
  ## Returns true iff exactly getFileSize(path) bytes were written — the byte-count assertion
  ## that the whole logical extent was covered (INV-SHRED-01). Opened WITHOUT truncation
  ## (fmReadWriteExisting) and seeked to 0, so the on-disk length is unchanged: we occupy the
  ## same logical byte range the plaintext used (LBA, not PBA — see this section's header).
  ##
  ## fsync/FlushFileBuffers is MANDATORY and happens BEFORE the caller unlinks: without it the
  ## filesystem may drop the dirty overwrite and only the unlink lands, leaving the bytes.
  if buf.len == 0: return false
  var size: int64
  try: size = getFileSize(path)
  except OSError: return false
  var f: File
  if not open(f, path, fmReadWriteExisting): return false
  var written: int64 = 0
  try:
    setFilePos(f, 0)
    var remaining = size
    while remaining > 0:
      let n = int(min(remaining, int64(buf.len)))
      let w = f.writeBuffer(unsafeAddr buf[0], n)
      if w != n: return false
      written += int64(w)
      remaining -= int64(w)
    flushFile(f)                                   # C stdio buffer -> OS
    when defined(posix):
      if fsync(getFileHandle(f)) != 0: return false            # OS buffer -> disk, before unlink
    else:
      if flushFileBuffers(cast[Handle](getOsFileHandle(f))) == 0: return false   # Windows fsync
  finally:
    close(f)
  result = (written == size)                       # full logical extent covered

proc shredAndRemoveTree*(root: string) =
  ## Overwrite every regular file under `root` (INV-SHRED-01), fsync each, THEN remove the tree.
  ## Overwrite-BEFORE-unlink is the whole point; unlink alone leaves the bytes for undelete.
  ## Best-effort per file — a file we cannot open is skipped, not fatal (the tree is going away
  ## regardless). Symlinks are never followed (yieldFilter {pcFile}, followFilter {pcDir}); we
  ## overwrite content that lives INSIDE the tree, never a link target outside it.
  if root.len == 0: return
  let buf = newShredBuffer()
  for path in walkDirRec(root, yieldFilter = {pcFile}):
    try: discard overwriteFile(path, buf)
    except CatchableError: discard
  removeDir(root)

proc shredGuard*(target: string): string =
  ## "" if `target` is safe to shred-and-remove; else a one-line diagnostic. Defensive guard for
  ## the `--haru-shred` re-exec surface (Windows worker) so a hand-typed `--haru-shred <path>`
  ## can never become arbitrary-delete: the target must be an existing, non-symlink directory
  ## named like a stageZip subtree (`<hexkey>-<32-hex-digest>`), sitting UNDER a root that is not
  ## '/', a drive/UNC root, or $HOME, and never a HARUPACK_DEV_STAGE tree (INV-SHRED-01 shares
  ## INV-REAP-01 / INV-BASE-01's own-subtree-only story). The POSIX reaper gets the same property
  ## by construction — it only ever passes the exact subtree stageZip created this run.
  if target.len == 0: return "empty shred target"
  let p = stripTrailingSep(target)
  let selfBad = refuseUnsafeRoot(p)                # the subtree is never a root/drive/home itself
  if selfBad.len > 0: return selfBad
  when defined(posix):
    var st: Stat
    if lstat(p, st) != 0: return "shred target does not exist: " & target
    if not S_ISDIR(st.st_mode):
      return "shred target is not a directory (symlink or file?): " & target
  else:
    if not dirExists(p): return "shred target does not exist: " & target
  let parentBad = refuseUnsafeRoot(p.parentDir)    # the staging ROOT it lives under must be safe
  if parentBad.len > 0: return "shred target's parent is an unsafe root: " & parentBad
  let name = p.extractFilename                      # <key>-<digest> shape, nothing else
  let dash = name.find('-')
  if dash <= 0 or dash >= name.high:
    return "shred target is not a haru-pack stage subtree: " & name
  let key = name[0 ..< dash]
  let dig = name[dash + 1 .. ^1]
  if key.len < 1 or key.len > 64 or not key.allCharsInSet(KeyChars):
    return "shred target key is not hex: " & name
  if dig.len != 32 or not dig.allCharsInSet(KeyChars):
    return "shred target digest is not 32 hex: " & name
  let dev = getEnv("HARUPACK_DEV_STAGE")
  if dev.len > 0 and stripTrailingSep(dev) == p:
    return "refusing to shred a HARUPACK_DEV_STAGE tree"
  return ""

# ------------------------------------------------------------- detached reap (fire-and-forget)

proc reapDetached*(target: string; overwrite = false) =
  ## Spawn a DETACHED, fire-and-forget process that deletes `target`, then return WITHOUT
  ## waiting - deletion of many GB continues after the stub has died (docs/adr/0004 4/5b,
  ## INV-REAP-01 / INV-SHRED-01). `target` is ALWAYS the exact staged subtree the launcher
  ## created this run (`<root>/<key>-<digest>`), never a raw base_path or env value.
  ##
  ## With `overwrite`, the detached worker SHREDS first: it overwrites every staged file with
  ## matching-length random bytes and fsyncs before unlinking (native Nim, no shell - see the
  ## shred section header for the honest ceiling). Without it the behaviour is byte-for-byte the
  ## Phase-2 reap: a shell `rm -rf` (POSIX) / `rmdir` (Windows).
  if target.len == 0: return
  when defined(posix):
    if not overwrite:
      # Plain reap (unchanged). Double-fork + setsid: the grandchild is reparented to init and
      # OUTLIVES this stub. We wait only for the FIRST child (which exits immediately after
      # forking the deleter). The path is passed to sh as a POSITIONAL arg ($1), never
      # interpolated into the script text, so a staging root containing shell metacharacters
      # cannot inject a command into our own reaper. The deleter redirects its std fds to
      # /dev/null so a parent capturing our output sees EOF instead of BLOCKING on the delete.
      # A known-good PATH is set INSIDE the script so `rm` resolves even under an empty/hostile
      # inherited PATH - a security cleanup must not silently no-op.
      var argv = allocCStringArray(["/bin/sh", "-c",
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin; exec rm -rf -- \"$1\" </dev/null >/dev/null 2>&1",
        "haru-reap", target])
      let pid1 = fork()
      if pid1 < 0:
        deallocCStringArray(argv)
        return
      if pid1 == 0:
        discard setsid()
        let pid2 = fork()
        if pid2 == 0:
          discard execv("/bin/sh", argv)
          exitnow(127)
        else:
          exitnow(0)
      else:
        var status: cint
        discard waitpid(pid1, status, 0)
        deallocCStringArray(argv)
    else:
      # Shred-on-reap. Same double-fork/setsid detach, but the grandchild overwrites each staged
      # file (native Nim shredAndRemoveTree) before removing the tree - no shell, no PowerShell
      # (INV-SHRED-01). Running Nim post-fork is safe here: this launcher is single-threaded (it
      # spawns processes, never threads), so the child holds no locked allocator/GC state.
      let pid1 = fork()
      if pid1 < 0: return
      if pid1 == 0:
        discard setsid()
        let pid2 = fork()
        if pid2 == 0:
          # Detach std fds to /dev/null so a parent capturing our output sees EOF and does not
          # BLOCK on the multi-GB shred (same property the sh path gets via its redirection).
          let devnull = posix.open("/dev/null", O_RDWR)
          if devnull >= 0:
            discard dup2(devnull, 0); discard dup2(devnull, 1); discard dup2(devnull, 2)
            if devnull > 2: discard posix.close(devnull)
          shredAndRemoveTree(target)           # overwrite (fsync) every file, THEN remove
          exitnow(0)
        else:
          exitnow(0)
      else:
        var status: cint
        discard waitpid(pid1, status, 0)
  else:
    # Windows (compile + code-review only on this host).
    if not overwrite:
      # Plain reap (unchanged): `cmd /c start /b rmdir /s /q` launches rmdir without a window;
      # cmd returns at once, so the stub does not wait. poDaemon (DETACHED_PROCESS) keeps it off
      # our console. The empty "" after `start` is its title argument.
      try:
        let p = startProcess("cmd", args = ["/c", "start", "", "/b", "rmdir", "/s", "/q", target],
                             options = {poDaemon, poUsePath})
        p.close()
      except CatchableError:
        discard
    else:
      # Shred-on-reap: re-exec THIS launcher as a hidden `--haru-shred <target>` worker so the
      # overwrite loop is native Nim (no PowerShell - frequently locked on hardened targets via
      # Constrained Language Mode / AppLocker / ExecutionPolicy; no shipped SDelete). poDaemon
      # detaches it; we do not wait. main.nim guards the subcommand with shredGuard so it can
      # only ever shred a stage-shaped own-subtree (INV-SHRED-01).
      try:
        let self = getAppFilename()
        let p = startProcess(self, args = ["--haru-shred", target], options = {poDaemon})
        p.close()
      except CatchableError:
        discard

# ---------------------------------------------------------------- digests

proc sha256hex*(data: string): string =
  var ctx: sha256
  ctx.init()
  if data.len > 0: ctx.update(data.toOpenArrayByte(0, data.high))
  result = ($ctx.finish()).toLowerAscii
  ctx.clear()

proc sha256File*(path: string): string =
  ## streaming so a 200 MB bundled interpreter does not become a 200 MB allocation
  var ctx: sha256
  ctx.init()
  var f: File
  if not open(f, path, fmRead): raise newException(StageError, "cannot read staged file: " & path)
  try:
    var buf = newString(64 * 1024)
    while true:
      let n = f.readChars(buf)
      if n <= 0: break
      ctx.update(buf.toOpenArrayByte(0, n - 1))
  finally: f.close()
  result = ($ctx.finish()).toLowerAscii
  ctx.clear()

# ---------------------------------------------------------------- zip-slip

proc unsafeEntryPath*(p: string): bool =
  ## True if an archive entry could write outside the destination directory.
  ##
  ## zippy 0.10.12 runs its own `verifyPathIsSafeToExtract` (rejects absolute paths,
  ## a leading `../`, and an embedded `/../`) and empirically rejects `../escape.txt`
  ## — see tests/test_stage_hardening.py, which measures that rather than assuming it.
  ## This function exists because "the library handles it" was an unverified assumption
  ## in the 2026-09-09 review, and because it also catches shapes zippy's substring
  ## checks miss: a bare `..` entry, a Windows drive-relative `C:evil`, and NUL bytes.
  if p.len == 0: return true
  if '\0' in p: return true
  if p.isAbsolute: return true
  if p.startsWith("/") or p.startsWith("\\"): return true
  if p.len >= 2 and p[1] == ':': return true            # C:evil (drive-relative)
  for part in p.replace('\\', '/').split('/'):
    if part == "..": return true
  return false

proc assertArchiveEntriesSafe*(zipPath: string) =
  ## Reject the whole payload if any entry path is unsafe. Fail closed on the archive,
  ## not per-entry: a payload containing a traversal entry is not a payload we built.
  let reader = openZipArchive(zipPath)
  try:
    for entry in reader.walkFiles:
      if unsafeEntryPath(entry):
        raise newException(StageError, "refusing payload: unsafe archive entry path: " & entry)
  finally: reader.close()
  # NOTE: zippy exports no iterator over directory-only records, so a `../x/` entry that
  # only creates an empty directory is covered by zippy's check and not by this one.

# ---------------------------------------------------------------- ownership / mode

proc currentUid*(): int =
  when defined(posix): int(geteuid()) else: -1

proc assertSafePath(path: string, wantDir: bool) =
  ## POSIX: must exist, be the right kind, not be a symlink, be owned by us, and not be
  ## writable by group or other. Windows: not checked — there is no cheap ACL equivalent
  ## and LOCALAPPDATA is per-user by default. That gap is real; do not read this proc as
  ## covering Windows.
  when defined(posix):
    var st: Stat
    if lstat(path, st) != 0:
      raise newException(StageError, "cannot stat stage path: " & path)
    let mode = st.st_mode
    if wantDir and not S_ISDIR(mode):
      raise newException(StageError, "stage path is not a directory (symlink or file?): " & path)
    if not wantDir and not S_ISREG(mode):
      raise newException(StageError, "stage path is not a regular file (symlink?): " & path)
    if int(st.st_uid) != currentUid():
      raise newException(StageError,
        "refusing stage path owned by uid " & $int(st.st_uid) & " (we are uid " &
        $currentUid() & "): " & path)
    if (int(mode) and 0o022) != 0:
      raise newException(StageError, "refusing group/world-writable stage path: " & path)
  else:
    if wantDir and not dirExists(path):
      raise newException(StageError, "stage path is not a directory: " & path)
    if not wantDir and not fileExists(path):
      raise newException(StageError, "stage path is not a regular file: " & path)

proc hardenDir(path: string) =
  when defined(posix):
    try: setFilePermissions(path, {fpUserRead, fpUserWrite, fpUserExec})
    except OSError: discard
  else: discard

proc writeHardened(path, data: string) =
  ## 0600, explicitly: a umask of 0002 makes an ordinary writeFile group-writable, and
  ## the token that decides whether we execute this tree must not be group-writable.
  writeFile(path, data)
  when defined(posix):
    try: setFilePermissions(path, {fpUserRead, fpUserWrite})
    except OSError: discard

# ---------------------------------------------------------------- staged file set

proc isRuntimeMutable*(rel: string): bool =
  ## Paths that the launcher, uv, or CPython legitimately rewrite *after* staging, and
  ## which therefore cannot be part of the recorded set without bricking the second run.
  ## Files that merely appear later (a uv cache, a .venv, new __pycache__) need no
  ## exception: verification checks the recorded files and ignores unrecorded ones.
  let parts = rel.split('/')
  let base = parts[^1]
  if base in [ReadyName, FilesName, ".preinstall-done", ".postinstall-done",
              "uv.lock", ".DS_Store"]: return true
  for part in parts:
    if part == ".venv": return true
  if rel.startsWith("vendor/uv-dl-"): return true   # uvfetch's scratch dir, deleted on success
  return false

# NOT exempt, deliberately — each of these was an exemption once, and each was a hole:
#
#   vendor/uv, vendor/uv.exe
#     `main.findUv` executes this path before anything else, so exempting it handed a
#     same-uid attacker the one file guaranteed to run. It also needed no exemption:
#     verification only checks RECORDED files, so a thin-tier uv fetched after staging is
#     simply unrecorded and ignored, while a bundled uv (default/thick) is now covered.
#
#   *.pyc, *.pyo, __pycache__/
#     CPython validates a timestamp-mode .pyc against nothing but the source's mtime and
#     size, both of which a same-uid attacker can forge, so an exempt .pyc is executable
#     code outside the manifest. Nothing writes bytecode INTO the stage any more:
#     build._IGNORE strips __pycache__ and *.pyc from the payload, and main.nim points
#     PYTHONPYCACHEPREFIX at a directory outside the verified tree. A .pyc appearing
#     inside the stage is therefore not ours.

proc expandCompressedMembers(root: string) =
  ## Expand any `<name>.xz` the build stored compressed, then delete the `.xz`.
  ##
  ## ORDERING IS THE WHOLE POINT, and it is why this is called from `stageZip` between
  ## `extractAll` and `recordTree` rather than lazily at first use: after this runs the
  ## tree looks exactly like a tree from an uncompressed payload, so `recordTree` records a
  ## sha256 for the *expanded* `vendor/uv` in `.stage-files` and `verifyTree` re-checks it
  ## on every reuse — the same protection `vendor/uv` has always had (INV-STAGE-01).
  ## Expanding later would mean the one file `main.findUv` executes first was written into
  ## the tree after the manifest was sealed, i.e. outside it. That exemption existed once
  ## already and INV-STAGE-01's own note records why it was a hole.
  ##
  ## The `.xz` and its `.size` sidecar are removed before recording, so they never appear
  ## in the recorded set and cost nothing on reuse.
  # Collected before any mutation: this loop deletes the files it visits, and mutating a
  # tree while `walkDirRec` is iterating it is undefined.
  var members: seq[string]
  for path in walkDirRec(root, relative = true):
    let rel = path.replace('\\', '/')
    if rel.endsWith(".xz"): members.add rel
  for rel in members:
    let full = root / rel
    let sizePath = full & ".size"
    if not fileExists(sizePath):
      raise newException(StageError,
        "payload has " & rel & " with no .size sidecar; refusing to guess how large it " &
        "expands to. This payload was not produced by a matching haru-pack.")
    var want: int
    try:
      want = parseInt(readFile(sizePath).strip())
    except ValueError:
      raise newException(StageError, "unreadable size sidecar for " & rel)
    # The sidecar is a number from the payload. `main.launch` does verify the payload
    # against the digest in its own footer before we get here (INV-LAUNCH-01, now
    # `active`), but that is not a MAC: both halves come from the same attacker-writable
    # footer, so it catches corruption and naive edits, not a deliberate rewrite. The
    # invariant that would make a hostile size unreachable is a signature over the payload
    # — INV-LAUNCH-03, still `proposed`. So treat this number as untrusted. Feeding it
    # straight to `newString` means a tampered or corrupt value allocates that much:
    # measured 2026-09-11, `newString(1 shl 50)` aborts the process with a bare "out of
    # memory" — an OutOfMemDefect, which is not catchable, so none of the error handling
    # below would ever run. A ceiling turns that into a refusal with a reason.
    if want <= 0 or want > MaxExpandedBytes:
      raise newException(StageError,
        "size sidecar for " & rel & " says " & $want & " bytes, which is outside the " &
        "range this launcher will expand (1 .. " & $MaxExpandedBytes & "). The payload is " &
        "corrupt or was not produced by haru-pack.")
    let dest = full[0 ..< full.len - 3]           # strip ".xz"
    if fileExists(dest):
      raise newException(StageError,
        "payload contains both " & rel & " and its expanded form; refusing to choose")
    var data: string
    try:
      data = xzDecode(readFile(full), want)
    except XzError as e:
      raise newException(StageError, "could not expand " & rel & ": " & e.msg)

    # Confirm the expansion produced the bytes the build compressed (INV-PAYLOAD-04). The
    # build writes the digest of the ORIGINAL file beside the member, so this catches a
    # decoder bug, a silently-corrupted member, and a mismatched .size — the cases where
    # decompression "succeeds" and yields something else.
    #
    # What it does NOT do, stated plainly: defeat tampering. An attacker who can rewrite
    # `uv.xz` can rewrite `uv.xz.sha256` alongside it. The footer digest checked in
    # `main.launch` (INV-LAUNCH-01, `active`) does not close the gap either — it is the
    # same shape of check, payload against a digest an editor can recompute. Closing it
    # needs the digest in a signature-covered place the payload cannot reach — see
    # INV-LAUNCH-03, still `proposed`. This is an integrity check against corruption, not
    # an authenticity one.
    let shaPath = full & ".sha256"
    if fileExists(shaPath):
      let wantSha = readFile(shaPath).strip().toLowerAscii
      if wantSha.len != 64:
        raise newException(StageError,
          "digest sidecar for " & rel & " is not a sha256 hex digest")
      let gotSha = sha256hex(data)
      if gotSha != wantSha:
        raise newException(StageError,
          "expanded " & rel & " does not match its recorded digest (expected " &
          wantSha[0 ..< 16] & "…, got " & gotSha[0 ..< 16] & "…). The payload is corrupt.")
    writeFile(dest, data)
    when defined(posix):
      # uv is executed, so it needs the bit back. Group/other write is stripped by
      # `hardenDir`/`recordTree` afterwards, as for every other staged file.
      try: setFilePermissions(dest, {fpUserRead, fpUserWrite, fpUserExec})
      except OSError: discard
    removeFile(full)
    removeFile(sizePath)

proc materialiseLinks(root: string) =
  ## Re-create the files the build stored once, then delete the link table.
  ##
  ## python-build-standalone ships `bin/python` and `bin/python3` as symlinks to
  ## `python3.13`, and `libpython3.13.so` as one to `libpython3.13.so.1.0`. The build used
  ## to follow those and store five full copies of two files — 34.3 MB of an 84.5 MB thick
  ## payload, since DEFLATE cannot dedupe across members. Now it stores each once and lists
  ## the aliases in `.haru-links`.
  ##
  ## On POSIX they are re-created as relative SYMLINKS, so the alias costs a link entry
  ## rather than a full copy — the on-disk dedup (INV-STAGE-04), ~90 MB per staged thick
  ## payload. That is only safe because `recordTree` now yields `pcLinkToFile` and records
  ## each alias as a `symlink:<target> <rel>` line, and `verifyTree` re-checks on every reuse
  ## that the path is still a symlink still pointing at the SAME in-stage target — whose own
  ## bytes are hash-verified by its regular-file line. So the alias stays inside `.stage-files`
  ## and INV-STAGE-01 holds; a copy would only have been a way to get it recorded at all.
  ##
  ## On Windows, creating a symlink is privileged, so the alias stays a COPY and is recorded
  ## as an ordinary file. The two platforms' staged trees differ in size, not in content, and
  ## each is verified against a manifest generated on the same machine that staged it.
  ##
  ## Same ordering rule as `expandCompressedMembers`, for the same reason: this runs before
  ## `recordTree`, so the copies are inside the sealed manifest rather than written after it.
  let table = root / LinksName
  if not fileExists(table): return
  var entries: seq[(string, string)]
  for line in readFile(table).splitLines:
    if line.len == 0: continue
    let tab = line.find('\t')
    if tab <= 0:
      raise newException(StageError, "malformed " & LinksName & " entry: " & line)
    entries.add (line[0 ..< tab], line[tab + 1 .. ^1])
  if entries.len > MaxLinkEntries:
    raise newException(StageError,
      LinksName & " lists " & $entries.len & " entries, more than this launcher will " &
      "materialise (" & $MaxLinkEntries & "). The payload is corrupt or was not produced " &
      "by haru-pack.")
  for (linkRel, targetRel) in entries:
    # Both halves come out of the payload, which `main.launch` has checked against a digest
    # that is not a MAC (INV-LAUNCH-01's own note). Treat them as untrusted input: without
    # this, a rewritten table is an arbitrary-file-write primitive, and `..` in the target
    # would copy a file from outside the stage into it.
    if unsafeEntryPath(linkRel) or unsafeEntryPath(targetRel):
      raise newException(StageError,
        "refusing payload: unsafe path in " & LinksName & ": " & linkRel & " -> " & targetRel)
    let linkPath = root / linkRel
    let targetPath = root / targetRel
    if not fileExists(targetPath):
      raise newException(StageError,
        LinksName & " points " & linkRel & " at " & targetRel & ", which the payload does " &
        "not contain")
    if fileExists(linkPath) or dirExists(linkPath):
      raise newException(StageError,
        "payload contains both " & linkRel & " and a " & LinksName & " entry for it; " &
        "refusing to choose")
    createDir(parentDir(linkPath))
    when defined(posix):
      # A RELATIVE symlink, so the staged tree stays relocatable (the cache dir can move) and
      # the alias is deduplicated on disk instead of copied. recordTree records it as a symlink
      # line; verifyTree re-checks it still points here. (INV-STAGE-04)
      createSymlink(relativePath(targetPath, parentDir(linkPath)), linkPath)
    else:
      # Windows: symlink creation is privileged, so keep the copy. Permissions come with it —
      # `bin/python` is only useful if it is still executable — and recordTree records it as an
      # ordinary file.
      copyFileWithPermissions(targetPath, linkPath)
  removeFile(table)

proc recordTree(root: string): tuple[manifest: string, count: int] =
  var rels: seq[string]
  # `pcLinkToFile` too, now that materialiseLinks stages aliases as symlinks on POSIX: a
  # symlink absent from `.stage-files` would go unverified, which is exactly the hole the copy
  # path used to avoid. `followFilter` stays default (`{pcDir}`), so real directories are
  # recursed and symlinked directories are not.
  for p in walkDirRec(root, yieldFilter = {pcFile, pcLinkToFile}, relative = true):
    let rel = p.replace('\\', '/')
    if isRuntimeMutable(rel): continue
    rels.add rel
  sort(rels)
  var sb = ""
  for rel in rels:
    # The manifest is one entry per line, space-separated; a newline in a path would forge a
    # second entry. Real payload paths never contain one — refuse rather than record ambiguously.
    if '\n' in rel or '\r' in rel:
      raise newException(StageError, "refusing to record a path containing a newline: " & rel)
    let full = root / rel
    when defined(posix):
      if symlinkExists(full):
        # A deduplicated alias (INV-STAGE-04). Record it AS a symlink and its in-stage target,
        # not the followed bytes: the target is itself a recorded, hash-verified regular file,
        # so "still a symlink, still pointing here" is what keeps the alias accountable without
        # storing the bytes a second time. `expandSymlink` returns the relative value we wrote.
        let tgtRel = normalizedPath(parentDir(rel) / expandSymlink(full)).replace('\\', '/')
        if '\n' in tgtRel or '\r' in tgtRel:
          raise newException(StageError, "refusing to record a symlink target with a newline: " & rel)
        sb.add "symlink:" & tgtRel & " " & rel & "\n"
        continue
      try:
        let perms = getFilePermissions(full)
        setFilePermissions(full, perms - {fpGroupWrite, fpOthersWrite})
      except OSError: discard
    sb.add sha256File(full) & " " & rel & "\n"
  result = (sb, rels.len)

proc verifyTree(root, manifest: string) =
  for line in manifest.splitLines:
    if line.len == 0: continue
    let sp = line.find(' ')
    if sp <= 0: raise newException(StageError, "malformed " & FilesName & " entry: " & line)
    let tok = line[0 ..< sp]
    let rel = line[sp + 1 .. ^1]
    let full = root / rel
    if tok.startsWith("symlink:"):
      # A deduplicated alias (INV-STAGE-04). Three things must still hold, and none of them is
      # "follow it and hash whatever is there" — that silent follow is how this class of bug
      # comes back. `fileExists`/`sha256File` both follow symlinks, so a bare content check
      # would accept a file swapped in for the link, or a link repointed at matching bytes.
      let tgtRel = tok["symlink:".len .. ^1]
      when defined(posix):
        # (1) still a symlink — not a regular file (or dir) swapped in where the alias was.
        if not symlinkExists(full):
          raise newException(StageError, "staged alias is no longer a symlink: " & rel)
        # (2) still pointing at the SAME in-stage target. Recompute the stage-relative target
        #     from the link exactly as recordTree did; reject a repoint (at `/etc`, `..`, or a
        #     different member). `unsafeEntryPath` rejects any target that escapes the stage.
        let got = normalizedPath(parentDir(rel) / expandSymlink(full)).replace('\\', '/')
        if unsafeEntryPath(tgtRel) or got != tgtRel:
          raise newException(StageError,
            "staged alias points somewhere new: " & rel & " -> " & got &
            " (recorded " & tgtRel & ")")
        # (3) the target is a real, present regular file — its own manifest line hash-verifies
        #     its bytes, so the alias inherits that guarantee.
        let tgtFull = root / tgtRel
        if symlinkExists(tgtFull) or not fileExists(tgtFull):
          raise newException(StageError,
            "staged alias target is missing or not a regular file: " & rel & " -> " & tgtRel)
      else:
        # materialiseLinks never stages a symlink on Windows (it copies), so a symlink line here
        # is a manifest from another platform — refuse rather than guess at its meaning.
        raise newException(StageError, "unexpected symlink record on this platform: " & rel)
      continue
    if not fileExists(full):
      raise newException(StageError, "staged file is missing: " & rel)
    when defined(posix):
      # Recorded as a regular file but now a symlink: the file->symlink swap, refused before the
      # hash check (which would follow the link and could be satisfied by matching bytes).
      if symlinkExists(full):
        raise newException(StageError, "staged file is now a symlink: " & rel)
    if sha256File(full) != tok:
      raise newException(StageError, "staged file was modified since staging: " & rel)

# ---------------------------------------------------------------- .ready token

proc readyToken(key, payloadDigest, treeDigest: string, count: int): string =
  ## Deterministic on purpose: two processes staging the same payload produce byte
  ## identical tokens, which is what makes the lost-race check below meaningful.
  StageFormat & "\n" &
  "key=" & key & "\n" &
  "payload=" & payloadDigest & "\n" &
  "uid=" & $currentUid() & "\n" &
  "files=" & $count & "\n" &
  "tree=" & treeDigest & "\n"

proc verifyStagedDir(final, key, payloadDigest: string) =
  ## Everything between "the directory exists" and "we are willing to execute it".
  assertSafePath(final, wantDir = true)
  let ready = final / ReadyName
  if not fileExists(ready):
    raise newException(StageError,
      "stage directory exists but was never completed by haru-pack; refusing to run it. " &
      "Remove it and retry: " & final)
  assertSafePath(ready, wantDir = false)
  let filesPath = final / FilesName
  if not fileExists(filesPath):
    raise newException(StageError, "stage directory has no " & FilesName & "; remove it: " & final)
  assertSafePath(filesPath, wantDir = false)
  let mf = readFile(filesPath)
  var count = 0
  for line in mf.splitLines:
    if line.len > 0: count.inc
  let want = readyToken(key, payloadDigest, sha256hex(mf), count)
  if readFile(ready) != want:
    raise newException(StageError,
      "stage directory does not match this payload (bad or foreign " & ReadyName &
      "); refusing to run it. Remove it and retry: " & final)
  verifyTree(final, mf)

proc stageZip*(payload: string, key: string, root = baseDir()): string =
  ## Extract a zip payload to <root>/<key>-<payload-digest>/ atomically, and on every
  ## subsequent run verify the tree before handing it back. Raises `StageError` rather
  ## than reusing anything it cannot account for.
  ##
  ## `root` is the resolved staging root (docs/adr/0004: BASE_PATH env > stub base_path >
  ## RAM-backed-or-cache). It defaults to the persistent per-user cache, so a caller that
  ## passes nothing keeps today's behaviour byte-for-byte. The subtree name is derived only
  ## from `key` and the payload digest, so the reaped path is one the launcher OWNS.
  if key.len == 0 or key.len > 64 or not key.allCharsInSet(KeyChars):
    raise newException(StageError, "invalid stage key (expected hex): " & key)
  let payloadDigest = sha256hex(payload)
  # 64 bits of footer digest was grindable and said nothing about the bytes actually
  # staged; the name now carries 128 bits of the payload's own digest as well. The full
  # 64 hex chars would be better still, but Windows MAX_PATH plus a staged CPython tree
  # is a real constraint, so this is the deliberate trade.
  let final = root / (key.toLowerAscii & "-" & payloadDigest[0 ..< 32])

  if dirExists(final):
    verifyStagedDir(final, key.toLowerAscii, payloadDigest)
    return final

  createDir(root)
  hardenDir(root)
  assertSafePath(root, wantDir = true)

  let tmp = root / (key.toLowerAscii & ".tmp-" & $getCurrentProcessId())
  removeDir(tmp)
  createDir(tmp)
  hardenDir(tmp)
  assertSafePath(tmp, wantDir = true)
  let zipPath = tmp / "payload.zip"
  writeFile(zipPath, payload)
  assertArchiveEntriesSafe(zipPath)
  let root = tmp / "root"
  extractAll(zipPath, root)           # dest must not pre-exist
  removeFile(zipPath)
  expandCompressedMembers(root)       # BEFORE recordTree — see that proc's comment
  materialiseLinks(root)              # likewise: copies must be inside the sealed manifest
  hardenDir(root)
  let (mf, count) = recordTree(root)
  writeHardened(root / FilesName, mf)
  writeHardened(root / ReadyName, readyToken(key.toLowerAscii, payloadDigest, sha256hex(mf), count))

  if not dirExists(final):
    try: moveDir(root, final)
    except OSError:
      if not dirExists(final): raise
  removeDir(tmp)
  # We may have lost the race (or something else made `final` while we worked). Either
  # way the directory we are about to return is verified like any other reuse — the old
  # code returned it unexamined.
  verifyStagedDir(final, key.toLowerAscii, payloadDigest)
  return final

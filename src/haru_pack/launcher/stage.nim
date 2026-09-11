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
import std/[os, strutils, algorithm]
import zippy/ziparchives
import nimcrypto/sha2
import xzdec
when defined(posix): import std/posix
when defined(windows): import std/osproc

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
  ## WINDOWS / macOS: there is no guaranteed RAM filesystem, so --ram-only is best-effort only
  ## and NOT guaranteed; fall back to the persistent cache with an honest note.
  ##
  ## HONEST DISCLAIMER: --ram-only governs only where the STUB stages the payload tree. It
  ## cannot control the packed application's OWN disk writes. No strong promises.
  when defined(linux):
    const shm = "/dev/shm"
    if isDirWritable(shm):
      return shm / "haru-pack"
    stderr.writeLine "haru-pack: --ram-only requested but /dev/shm is unavailable or not " &
                     "writable; staging to the persistent cache instead."
    return baseDir()
  else:
    stderr.writeLine "haru-pack: --ram-only is best-effort and not guaranteed on this OS " &
                     "(no RAM-backed filesystem); staging to the persistent cache instead."
    return baseDir()

# ------------------------------------------------------------- detached reap (fire-and-forget)

proc reapDetached*(target: string) =
  ## Spawn a DETACHED, fire-and-forget process that deletes `target`, then return WITHOUT
  ## waiting — deletion of many GB continues after the stub has died (docs/adr/0004 §4,
  ## INV-REAP-01). `target` is ALWAYS the exact staged subtree the launcher created this run
  ## (`<root>/<key>-<digest>`), never a raw base_path or env value.
  if target.len == 0: return
  # TOCTOU defence: the launcher created `target` as a real directory, but the app ran for an
  # unbounded time between creation and this reap. If `target` is now a SYMLINK, a local
  # attacker swapped it — do not follow it. We only ever reap a real directory we made. (GNU
  # `rm -rf -- link` already removes the link rather than its target, but not every target's
  # `rm` is GNU, so refuse explicitly.) INV-BASE-01 / INV-REAP-01.
  if symlinkExists(target): return
  when defined(posix):
    # Double-fork + setsid: the grandchild is reparented to init and OUTLIVES this stub. We
    # wait only for the FIRST child (which exits immediately after forking the deleter), never
    # for the deletion itself. The path is passed to sh as a POSITIONAL arg ($1), never
    # interpolated into the script text, so a staging root containing shell metacharacters (a
    # hostile BASE_PATH that reached staging) cannot inject a command into our own reaper.
    #
    # The deleter redirects its own stdin/stdout/stderr to /dev/null: it INHERITS our fds, and
    # a parent capturing our output would otherwise not see EOF (so would BLOCK) until the
    # multi-GB delete finished — the exact "return without waiting" property we are promising.
    #
    # A known-good PATH is set INSIDE the script (a constant, not attacker input) so `rm`
    # resolves even when we were launched with an empty or hostile PATH — a security-sensitive
    # cleanup must not silently no-op because the inherited PATH could not find `rm`.
    var argv = allocCStringArray(["/bin/sh", "-c",
      "PATH=/usr/bin:/bin:/usr/sbin:/sbin; exec rm -rf -- \"$1\" </dev/null >/dev/null 2>&1",
      "haru-reap", target])
    let pid1 = fork()
    if pid1 < 0:
      deallocCStringArray(argv)
      return                                   # cannot fork -> best-effort cleanup gives up
    if pid1 == 0:
      discard setsid()                         # detach from our session / controlling tty
      let pid2 = fork()
      if pid2 == 0:
        discard execv("/bin/sh", argv)         # grandchild becomes `rm`; on success never returns
        exitnow(127)                           # exec failed
      else:
        exitnow(0)                             # first child exits -> grandchild orphaned to init
    else:
      var status: cint
      discard waitpid(pid1, status, 0)         # reap the IMMEDIATE child, not the deleter
      deallocCStringArray(argv)
  else:
    # Windows (compile + code-review only on this host): `cmd /c start /b rmdir /s /q` launches
    # rmdir without a window; cmd returns at once, so the stub does not wait for the deletion.
    # poDaemon (DETACHED_PROCESS) keeps it off our console. The empty "" after `start` is its
    # title argument, so a quoted target is not mistaken for the window title.
    try:
      let p = startProcess("cmd", args = ["/c", "start", "", "/b", "rmdir", "/s", "/q", target],
                           options = {poDaemon, poUsePath})
      p.close()                                # do NOT waitForExit — fire and forget
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
    # The sidecar is a number from the payload, and the payload is not verified at runtime
    # (INV-LAUNCH-01 is still `proposed`). Feeding it straight to `newString` means a
    # tampered or corrupt value allocates that much: measured 2026-09-11, `newString(1 shl
    # 50)` aborts the process with a bare "out of memory" — an OutOfMemDefect, which is not
    # catchable, so none of the error handling below would ever run. A ceiling turns that
    # into a refusal with a reason.
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
    # `uv.xz` can rewrite `uv.xz.sha256` alongside it. Closing that needs the digest in a
    # signature-covered place the payload cannot reach — see INV-LAUNCH-01, still
    # `proposed`. This is an integrity check against corruption, not an authenticity one.
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

proc recordTree(root: string): tuple[manifest: string, count: int] =
  var rels: seq[string]
  for p in walkDirRec(root, relative = true):
    let rel = p.replace('\\', '/')
    if isRuntimeMutable(rel): continue
    rels.add rel
  sort(rels)
  var sb = ""
  for rel in rels:
    when defined(posix):
      try:
        let perms = getFilePermissions(root / rel)
        setFilePermissions(root / rel, perms - {fpGroupWrite, fpOthersWrite})
      except OSError: discard
    sb.add sha256File(root / rel) & " " & rel & "\n"
  result = (sb, rels.len)

proc verifyTree(root, manifest: string) =
  for line in manifest.splitLines:
    if line.len == 0: continue
    let sp = line.find(' ')
    if sp <= 0: raise newException(StageError, "malformed " & FilesName & " entry: " & line)
    let want = line[0 ..< sp]
    let rel = line[sp + 1 .. ^1]
    let full = root / rel
    if not fileExists(full):
      raise newException(StageError, "staged file is missing: " & rel)
    if sha256File(full) != want:
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

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
when defined(posix): import std/posix

type StageError* = object of CatchableError

const
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

proc stageZip*(payload: string, key: string): string =
  ## Extract a zip payload to <base>/<key>-<payload-digest>/ atomically, and on every
  ## subsequent run verify the tree before handing it back. Raises `StageError` rather
  ## than reusing anything it cannot account for.
  if key.len == 0 or key.len > 64 or not key.allCharsInSet(KeyChars):
    raise newException(StageError, "invalid stage key (expected hex): " & key)
  let payloadDigest = sha256hex(payload)
  # 64 bits of footer digest was grindable and said nothing about the bytes actually
  # staged; the name now carries 128 bits of the payload's own digest as well. The full
  # 64 hex chars would be better still, but Windows MAX_PATH plus a staged CPython tree
  # is a real constraint, so this is the deliberate trade.
  let final = baseDir() / (key.toLowerAscii & "-" & payloadDigest[0 ..< 32])

  if dirExists(final):
    verifyStagedDir(final, key.toLowerAscii, payloadDigest)
    return final

  createDir(baseDir())
  hardenDir(baseDir())
  assertSafePath(baseDir(), wantDir = true)

  let tmp = baseDir() / (key.toLowerAscii & ".tmp-" & $getCurrentProcessId())
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

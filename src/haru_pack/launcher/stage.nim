## haru-pack staging: per-user, content-addressed, atomic, first-run-skip, self-evicting.
import std/[os, strutils, hashes, times, algorithm]
import zippy/ziparchives

const
  ReadyMarker* = ".ready"      # written last; its presence means "fully staged"
  UseMarker* = ".lastrun"      # touched every launch; drives LRU-by-time eviction
  DefaultKeepDays* = 30
  DefaultKeepMax* = 3

proc baseDir*(): string =
  ## regenerable tree -> LOCALAPPDATA (win) / XDG_CACHE_HOME (linux) / Caches (mac)
  when defined(windows):
    result = getEnv("LOCALAPPDATA", getHomeDir() / "AppData" / "Local")
  elif defined(macosx):
    result = getEnv("HOME") / "Library" / "Caches"
  else:
    result = getEnv("XDG_CACHE_HOME", getHomeDir() / ".cache")
  result = result / "haru-pack"

proc keyFor*(s: string): string =
  ## short stable key for the stage dir (M0: fast non-crypto hash of the payload/id)
  toHex(uint64(hash(s))).toLowerAscii

proc stageZip*(payload: string, key: string): string =
  ## extract a zip payload to <base>/<key>/ atomically; skip if already .ready.
  let final = baseDir() / key
  if fileExists(final / ".ready"): return final
  let tmp = baseDir() / (key & ".tmp-" & $getCurrentProcessId())
  removeDir(tmp)
  createDir(tmp)
  let zipPath = tmp / "payload.zip"
  writeFile(zipPath, payload)
  extractAll(zipPath, tmp / "root")   # dest must not pre-exist
  removeFile(zipPath)
  writeFile(tmp / "root" / ReadyMarker, "1")
  if not dirExists(final):
    try: moveDir(tmp / "root", final)
    except OSError:
      if not dirExists(final): raise
  removeDir(tmp)
  return final

proc touchStage*(dir: string) =
  ## Record last-use. Called on EVERY launch, including the fast .ready path, so a stage
  ## dir that is still in regular use never looks stale to the evictor.
  try: writeFile(dir / UseMarker, $getTime().toUnix)
  except CatchableError: discard      # read-only cache dir is not fatal

proc lastUse(dir: string): Time =
  ## Prefer the launch marker; fall back to the staging marker for dirs written by an
  ## older haru-pack that predates .lastrun.
  for marker in [UseMarker, ReadyMarker]:
    try:
      if fileExists(dir / marker): return getLastModificationTime(dir / marker)
    except OSError: discard
  result = fromUnix(0)

proc evictStale*(keepDir: string, keepDays = DefaultKeepDays, keepMax = DefaultKeepMax) =
  ## Delete stage dirs unused for `keepDays`, always retaining the live one and the
  ## `keepMax` most-recently-used. `keepDays <= 0` disables eviction entirely.
  ##
  ## Only directories carrying a ReadyMarker are candidates, which is what keeps the
  ## sibling `uv-cache` tree and any half-written `<key>.tmp-<pid>` dir out of scope.
  ## Removal failures are swallowed: on Windows a dir belonging to a concurrently running
  ## instance is locked, and retrying on a later launch is the correct behaviour.
  if keepDays <= 0: return
  let
    base = baseDir()
    live = keepDir.absolutePath.normalizedPath
    cutoff = getTime() - initDuration(days = keepDays)
  var cands: seq[tuple[used: Time, path: string]]
  try:
    for kind, path in walkDir(base):
      if kind != pcDir: continue
      if not fileExists(path / ReadyMarker): continue
      if path.absolutePath.normalizedPath == live: continue
      cands.add (lastUse(path), path)
  except OSError: return                      # cache dir vanished mid-scan; nothing to do
  cands.sort(proc (a, b: tuple[used: Time, path: string]): int = cmp(b.used, a.used))
  for i, c in cands:
    if i < keepMax: continue                  # newest keepMax are always retained
    if c.used > cutoff: continue              # still within the age window
    try: removeDir(c.path)
    except CatchableError: discard

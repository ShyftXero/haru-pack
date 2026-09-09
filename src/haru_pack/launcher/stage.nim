## haru-pack staging: per-user, content-addressed, atomic, first-run-skip.
import std/[os, strutils, hashes]
import zippy/ziparchives

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
  writeFile(tmp / "root" / ".ready", "1")
  if not dirExists(final):
    try: moveDir(tmp / "root", final)
    except OSError:
      if not dirExists(final): raise
  removeDir(tmp)
  return final

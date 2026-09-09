## haru-pack M0 launcher — actually runs `uv`.
## Modes:
##   packaged : payload zip appended to this exe (footer located by backward scan)
##   dev      : HARUPACK_DEV_STAGE=<dir> points at an already-unpacked payload tree
## Behaviour: stage once to appdata, wire uv env, run entrypoint with cwd = launch dir
## (run-in-place), exposing exe-dir + stage-dir to the child.
import std/[os, osproc, strutils, sequtils]
import overlay, stage, manifest, uvfetch, cryptbox
when defined(posix):
  import std/posix
  # A CUSTOM handler (not SIG_IGN) is reset to SIG_DFL across exec, so the child
  # (python) still gets normal Ctrl+C/KeyboardInterrupt while WE don't die early.
  proc ignoreInParent(sig: cint) {.noconv.} = discard

proc die(msg: string, code = 1) =
  stderr.writeLine "haru-pack: " & msg
  quit(code)

proc findUv(stageRoot: string, m: Manifest): string =
  # bundled (thick/default) -> PATH -> fetch on target (thin)
  let bundled = stageRoot / "vendor" / (when defined(windows): "uv.exe" else: "uv")
  if fileExists(bundled): return bundled
  let onPath = findExe("uv")
  if onPath.len > 0: return onPath
  if m.fetchUv:
    let got = ensureUv(stageRoot, m.uvVersion)
    if got.len > 0: return got
    die("thin tier: failed to fetch uv (need curl/powershell + network on first run)")
  die("no uv binary bundled and none on PATH")

proc findBundledPython(stageRoot: string): string =
  ## Scan the staged tree for a real interpreter (robust to uv's version-alias
  ## symlink dir, which the zip does not preserve).
  let base = stageRoot / "vendor" / "python"
  if not dirExists(base): return ""
  for p in walkDirRec(base):
    let fn = p.extractFilename
    when defined(windows):
      if fn == "python.exe": return p
    else:
      if (fn == "python3" or fn == "python") and p.parentDir.extractFilename == "bin":
        return p
  return ""

proc runChild(exe: string, args: seq[string], workDir: string): int =
  let p = startProcess(exe, workingDir = workDir, args = args,
                       options = {poParentStreams})
  result = p.waitForExit()
  p.close()

const currentOs =
  when defined(windows): "windows"
  elif defined(macosx): "macos"
  else: "linux"

proc osMatches(step: InstallStep): bool =
  step.os.len == 0 or "all" in step.os or currentOs in step.os

proc runInstallSteps(uv, appDir: string, m: Manifest, steps: seq[InstallStep],
                     sentinel: string) =
  if steps.len == 0 or fileExists(sentinel): return
  var ran = false
  for step in steps:
    if not osMatches(step): continue
    var a = @["run"]
    if m.offline: a.add "--offline"
    if m.kind == akProject: a.add @["--project", appDir]
    a.add "--"; a.add step.run
    stderr.writeLine "haru-pack: install step (" & currentOs & "): uv " & a.join(" ")
    let rc = runChild(uv, a, appDir)
    if rc != 0: die("install step failed (" & $rc & "): " & step.run.join(" "), rc)
    ran = true
  if ran or steps.len > 0: writeFile(sentinel, "1")

when isMainModule:
  let self = getAppFilename()
  let exeDir = getAppDir()
  let runDir = getCurrentDir()          # run-in-place root
  let userArgs = commandLineParams()

  # 1. locate staged payload root
  var stageRoot: string
  let dev = getEnv("HARUPACK_DEV_STAGE")
  if dev.len > 0:
    stageRoot = dev
  else:
    let (found, ft, _) = findFooter(self)
    if not found: die("no payload appended and HARUPACK_DEV_STAGE unset")
    var payload = readPayload(self, ft)
    var shahex = ""
    for b in ft.payloadSha: shahex.add toHex(int(b), 2).toLowerAscii
    if (ft.flags and 1'u16) != 0'u16 or isEncrypted(payload):
      payload = openContainer(payload)     # decrypt + license checks (dies on failure)
    stageRoot = stageZip(payload, shahex[0..15])

  # 2. manifest
  let mfPath = stageRoot / "manifest.toml"
  if not fileExists(mfPath): die("manifest.toml missing in payload: " & mfPath)
  let m = parseManifest(mfPath)
  let appDir = stageRoot / m.appSubdir

  # 3. env wiring (three roots + uv offline knobs)
  putEnv("HARUPACK_EXE_DIR", exeDir)
  putEnv("HARUPACK_STAGE", stageRoot)
  putEnv("UV_CACHE_DIR", if m.cacheDir.len > 0: stageRoot / m.cacheDir else: baseDir() / "uv-cache")
  for step in m.bundle:                       # re-apply declared bundle env, {into}->stage
    for (k, v) in step.env:
      putEnv(k, v.replace("{into}", stageRoot / step.into))
  if m.offline:
    putEnv("UV_OFFLINE", "1")
    putEnv("UV_PYTHON_DOWNLOADS", "never")
  # bundled interpreter (thick): explicit manifest path, else auto-detect on disk
  var py = if m.python.len > 0: stageRoot / m.python else: findBundledPython(stageRoot)
  if py.len > 0 and fileExists(py):
    putEnv("UV_PYTHON", py)
    putEnv("UV_PYTHON_INSTALL_DIR", stageRoot / "vendor" / "python")
    putEnv("UV_PYTHON_DOWNLOADS", "never")
  if m.projectEnv.len > 0:
    putEnv("UV_PROJECT_ENVIRONMENT", stageRoot / m.projectEnv)

  let uv = findUv(stageRoot, m)

  # 4. OS-specific pre/post-install hooks (run once each, in the uv env)
  runInstallSteps(uv, appDir, m, m.preInstall,  stageRoot / ".preinstall-done")
  runInstallSteps(uv, appDir, m, m.postInstall, stageRoot / ".postinstall-done")

  # 5. build the run command to mirror `python script.py <args>` exactly:
  #    args pass straight through, NO injected `--` (uv forwards them as-is).
  var a: seq[string]
  if not m.verboseUv: a.add "-q"     # suppress uv's own progress/logs
  a.add "run"
  a.add m.uvRunArgs
  if m.offline and "--offline" notin m.uvRunArgs: a.add "--offline"
  case m.kind
  of akScript:
    a.add "--script"
    a.add appDir / m.entrypoint[0]
  of akProject:
    # make the project importable regardless of run-in-place cwd, and resolve any
    # script token (foo.py) to an absolute path under the staged app dir.
    let prev = getEnv("PYTHONPATH")
    putEnv("PYTHONPATH", if prev.len > 0: appDir & (when defined(windows): ";" else: ":") & prev else: appDir)
    a.add @["--project", appDir]
    for tok in m.entrypoint:
      if tok.endsWith(".py") and not isAbsolute(tok): a.add appDir / tok
      else: a.add tok
  a.add userArgs                    # verbatim passthrough, like python

  # 6. cwd policy: "launch" (native, default) or "exe" (always the exe's folder,
  #    so a plain open('file.txt') always hits the file adjacent to the shipped exe)
  let childCwd = if m.cwdPolicy == "exe": exeDir else: runDir
  when defined(posix): signal(SIGINT, ignoreInParent)   # child owns Ctrl+C
  quit(runChild(uv, a, childCwd))

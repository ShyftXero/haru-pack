## uvcannon M0 launcher — actually runs `uv`.
## Modes:
##   packaged : payload zip appended to this exe (footer located by backward scan)
##   dev      : UVCANNON_DEV_STAGE=<dir> points at an already-unpacked payload tree
## Behaviour: stage once to appdata, wire uv env, run entrypoint with cwd = launch dir
## (run-in-place), exposing exe-dir + stage-dir to the child.
import std/[os, osproc, strutils, sequtils]
import overlay, stage, manifest

proc die(msg: string, code = 1) =
  stderr.writeLine "uvcannon: " & msg
  quit(code)

proc findUv(stageRoot: string, m: Manifest): string =
  # prefer a bundled uv, else PATH
  for c in [stageRoot / "vendor" / (when defined(windows): "uv.exe" else: "uv")]:
    if fileExists(c): return c
  let onPath = findExe("uv")
  if onPath.len > 0: return onPath
  die("no uv binary bundled and none on PATH")

proc runChild(exe: string, args: seq[string], workDir: string): int =
  let p = startProcess(exe, workingDir = workDir, args = args,
                       options = {poParentStreams})
  result = p.waitForExit()
  p.close()

when isMainModule:
  let self = getAppFilename()
  let exeDir = getAppDir()
  let runDir = getCurrentDir()          # run-in-place root
  let userArgs = commandLineParams()

  # 1. locate staged payload root
  var stageRoot: string
  let dev = getEnv("UVCANNON_DEV_STAGE")
  if dev.len > 0:
    stageRoot = dev
  else:
    let (found, ft, _) = findFooter(self)
    if not found: die("no payload appended and UVCANNON_DEV_STAGE unset")
    let payload = readPayload(self, ft)
    var shahex = ""
    for b in ft.payloadSha: shahex.add toHex(int(b), 2).toLowerAscii
    stageRoot = stageZip(payload, shahex[0..15])

  # 2. manifest
  let mfPath = stageRoot / "manifest.json"
  if not fileExists(mfPath): die("manifest.json missing in payload: " & mfPath)
  let m = parseManifest(mfPath)
  let appDir = stageRoot / m.appSubdir

  # 3. env wiring (three roots + uv offline knobs)
  putEnv("UVCANNON_EXE_DIR", exeDir)
  putEnv("UVCANNON_STAGE", stageRoot)
  putEnv("UV_CACHE_DIR", baseDir() / "uv-cache")
  if m.offline:
    putEnv("UV_OFFLINE", "1")
    putEnv("UV_PYTHON_DOWNLOADS", "never")
  if m.python.len > 0:
    putEnv("UV_PYTHON", stageRoot / m.python)
    putEnv("UV_PYTHON_INSTALL_DIR", stageRoot / "vendor" / "python")
  if m.projectEnv.len > 0:
    putEnv("UV_PROJECT_ENVIRONMENT", stageRoot / m.projectEnv)

  let uv = findUv(stageRoot, m)

  # 4. post-install hooks (run once, in the uv env; marked by a sentinel)
  let piSentinel = stageRoot / ".postinstall-done"
  if m.postInstall.len > 0 and not fileExists(piSentinel):
    for cmd in m.postInstall:
      var a = @["run"]
      if m.offline: a.add "--offline"
      if m.kind == akProject: a.add @["--project", appDir]
      a.add "--"
      a.add cmd
      stderr.writeLine "uvcannon: post-install: uv " & a.join(" ")
      let rc = runChild(uv, a, appDir)
      if rc != 0: die("post-install step failed (" & $rc & "): " & cmd.join(" "), rc)
    writeFile(piSentinel, "1")

  # 5. build the run command
  var a = @["run"]
  a.add m.uvRunArgs
  if m.offline and "--offline" notin m.uvRunArgs: a.add "--offline"
  case m.kind
  of akScript:
    a.add "--script"
    a.add appDir / m.entrypoint[0]
  of akProject:
    a.add @["--project", appDir]
    a.add m.entrypoint          # command argv (e.g. flask ... run)
  if userArgs.len > 0:
    a.add "--"
    a.add userArgs

  # 6. cwd policy: "launch" (native, default) or "exe" (always the exe's folder,
  #    so a plain open('file.txt') always hits the file adjacent to the shipped exe)
  let childCwd = if m.cwdPolicy == "exe": exeDir else: runDir
  quit(runChild(uv, a, childCwd))

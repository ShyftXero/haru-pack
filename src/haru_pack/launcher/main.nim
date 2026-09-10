## haru-pack M0 launcher — actually runs `uv`.
## Modes:
##   packaged : payload zip appended to this exe (footer located by backward scan)
##   dev      : HARUPACK_DEV_STAGE=<dir> points at an already-unpacked payload tree,
##              compiled in ONLY with -d:haruDev (INV-LAUNCH-02)
## Behaviour: stage once to appdata, wire uv env, run entrypoint with cwd = launch dir
## (run-in-place), exposing exe-dir + stage-dir to the child.
import std/[os, osproc, strutils, sequtils]
import nimcrypto/sha2
import overlay, stage, manifest, uvfetch, cryptbox
when defined(posix):
  import std/posix
  # A CUSTOM handler (not SIG_IGN) is reset to SIG_DFL across exec, so the child
  # (python) still gets normal Ctrl+C/KeyboardInterrupt while WE don't die early.
  proc ignoreInParent(sig: cint) {.noconv.} = discard

const
  ## Exit codes a caller can act on. 3/4/5 belong to cryptbox (expired / no secret /
  ## wrong secret or tampered container) — do not reuse them.
  ExitDigestMismatch* = 6   ## payload does not match the digest in our own footer
  ExitInternalError*  = 7   ## unexpected failure; a clean diagnostic, never a traceback
  ExitBadFooter*      = 8   ## footer's payload extent does not fit inside this file
  ExitNoUv*           = 9   ## no usable uv, and the tier forbids looking for one

proc die(msg: string, code = 1) =
  stderr.writeLine "haru-pack: " & msg
  quit(code)

proc findUv(stageRoot: string, m: Manifest): string =
  # bundled (thick/default) -> PATH -> fetch on target (thin)
  let bundled = stageRoot / "vendor" / (when defined(windows): "uv.exe" else: "uv")
  if fileExists(bundled): return bundled
  # INV-LAUNCH-04: the thick tier's whole claim is that it resolves and downloads
  # nothing. Falling back to findExe there would let anyone who can drop a file named
  # `uv` into PATH (or, on Windows, into the working directory — findExe checks it)
  # run code under this application's identity. A thick build uses its own copy or none.
  if m.tier == "thick":
    die("thick tier: no uv bundled in this payload. Refusing to run a uv resolved from " &
        "PATH or the working directory — a thick build resolves nothing off the host.",
        ExitNoUv)
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
    if "venv" in p.toLowerAscii: continue          # skip the stdlib venv-template python
    let fn = p.extractFilename
    when defined(windows):
      if fn == "python.exe": return p
    else:
      if (fn == "python3" or fn == "python") and p.parentDir.extractFilename == "bin":
        return p
  return ""

proc hexOf(digest: array[32, byte]): string =
  for b in digest: result.add toHex(int(b), 2).toLowerAscii

proc verifyPayloadDigest(payload: string, want: array[32, byte]) =
  ## INV-LAUNCH-01. The footer records SHA-256 over the bytes as ATTACHED. build.build
  ## encrypts first and hands overlay.attach() the container, so on an encrypted build
  ## this digest covers the CIPHERTEXT container, not the zip inside it. Verify here —
  ## before openContainer — or every encrypted build fails to launch.
  ##
  ## This is not a MAC: whoever edits the payload can recompute the footer. It stops
  ## corruption and naive edits, and it is the precondition for INV-LAUNCH-03 (a real
  ## signature over the payload) rather than a substitute for it.
  let got = sha256.digest(payload)
  var diff = 0'u8
  for i in 0 .. 31: diff = diff or (got.data[i] xor want[i])
  if diff != 0'u8:
    stderr.writeLine "haru-pack: payload integrity check FAILED — this executable has " &
                     "been modified since it was built."
    stderr.writeLine "haru-pack:   expected sha256 " & hexOf(want)
    stderr.writeLine "haru-pack:   actual   sha256 " & hexOf(got.data)
    quit(ExitDigestMismatch)

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

proc launch(): int =
  let self = getAppFilename()
  let exeDir = getAppDir()
  let runDir = getCurrentDir()          # run-in-place root
  let userArgs = commandLineParams()

  # 1. locate staged payload root
  var stageRoot = ""
  # INV-LAUNCH-02: HARUPACK_DEV_STAGE stages an arbitrary directory and skips the
  # overlay, the digest check, decryption and every license check. In a shipped, signed
  # binary that is a signed proxy for arbitrary code execution, available to anyone who
  # can set an environment variable. It exists only in -d:haruDev builds; a release
  # launcher never reads the variable.
  when defined(haruDev):
    let dev = getEnv("HARUPACK_DEV_STAGE")
    if dev.len > 0:
      stderr.writeLine "haru-pack: DEV BUILD — staging from HARUPACK_DEV_STAGE=" & dev
      stageRoot = dev
  if stageRoot.len == 0:
    let (found, ft, footerAt) = findFooter(self)
    if not found:
      when defined(haruDev):
        die("no payload appended and HARUPACK_DEV_STAGE unset")
      else:
        die("no payload appended to this executable")
    let fault = footerFault(ft, getFileSize(self).int, footerAt)   # W9
    if fault.len > 0: die("corrupt payload footer: " & fault, ExitBadFooter)
    var payload = readPayload(self, ft, footerAt)
    verifyPayloadDigest(payload, ft.payloadSha)   # INV-LAUNCH-01 — before we decrypt
    let shahex = hexOf(ft.payloadSha)
    if (ft.flags and 1'u16) != 0'u16 or isEncrypted(payload):
      payload = openContainer(payload)     # decrypt + license checks (dies on failure)
    stageRoot = stageZip(payload, shahex[0..15])

  # 2. manifest
  let mfPath = stageRoot / "manifest.toml"
  if not fileExists(mfPath): die("manifest.toml missing in payload: " & mfPath)
  let m = parseManifest(mfPath)
  if m.entrypoint.len == 0:                 # W16 — this used to be an unguarded [0]
    die("manifest declares no entrypoint: " & mfPath)
  let appDir = stageRoot / m.appSubdir

  # 3. env wiring (three roots + uv offline knobs)
  putEnv("HARUPACK_EXE_DIR", exeDir)
  putEnv("HARUPACK_STAGE", stageRoot)
  putEnv("UV_CACHE_DIR", if m.cacheDir.len > 0: stageRoot / m.cacheDir else: baseDir() / "uv-cache")
  # Keep CPython's bytecode cache OUT of the verified stage tree (INV-STAGE-01). A .pyc
  # written next to its source would either break verification on the second run or have to
  # be exempted from it — and an exempt .pyc is executable code outside the manifest that a
  # same-uid attacker can forge, because timestamp-mode bytecode is validated only against
  # the source's mtime and size.
  putEnv("PYTHONPYCACHEPREFIX", baseDir() / "pycache")
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
  elif m.tier == "thick":
    # INV-LAUNCH-04 again, for the other half of its statement. Without UV_PYTHON set,
    # uv resolves an interpreter from the host — so a thick build with no staged
    # interpreter would silently run the user's (or an attacker's) python3. Offline mode
    # only stops uv DOWNLOADING one; it does not stop it finding one on PATH.
    die("thick tier: no Python interpreter staged from this payload (looked for " &
        (if m.python.len > 0: m.python else: "vendor/python/**/bin/python3") &
        "). Refusing to resolve an interpreter off the host.", ExitNoUv)
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
    # --no-project is NOT optional. cwd is the launch directory (run-in-place), and uv walks
    # UP from there looking for a project. Run a packed binary from inside any Python project
    # — which is the normal case, since people run tools in their own repos — and uv adopts
    # that project, rebuilding ITS .venv against our staged interpreter.
    #
    # Found by busybody 2026-09-09, the hard way: a chaos case running from a work directory
    # inside this repository left haru-pack's own .venv/bin/python a dangling symlink into a
    # staged tree that was then deleted. A packaged application must not be able to damage
    # the environment of the directory it happens to be run from.
    a.add "--no-project"
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
  return runChild(uv, a, childCwd)

when isMainModule:
  # W16: parseManifest, parseJson and the expiry parse all raise, and zippy raises on a
  # malformed zip. Without this the end user of a shipped binary sees a raw Nim traceback
  # listing source paths from the machine that built it. `die`/`quit` are not exceptions,
  # so every deliberate exit above keeps its own code.
  try:
    quit(launch())
  except CatchableError as e:
    stderr.writeLine "haru-pack: could not start the packaged application."
    stderr.writeLine "haru-pack: " & $e.name & ": " & e.msg
    quit(ExitInternalError)

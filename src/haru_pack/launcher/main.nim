## haru-pack M0 launcher — actually runs `uv`.
## Modes:
##   packaged : payload zip appended to this exe (footer located by backward scan)
##   dev      : HARUPACK_DEV_STAGE=<dir> points at an already-unpacked payload tree,
##              compiled in ONLY with -d:haruDev (INV-LAUNCH-02)
## Behaviour: stage once to appdata, wire uv env, run entrypoint with cwd = launch dir
## (run-in-place), exposing exe-dir + stage-dir to the child.
import std/[os, osproc, strutils, sequtils]
import nimcrypto/sha2
import overlay, stage, manifest, uvfetch, cryptbox, stubconfig, ed25519
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
  ExitBadStub*        = 10  ## stub-config: digest mismatch, unparseable TOML, unsupported
                            ## stub_config_version, or an invalid/missing canary. One-line
                            ## diagnostic, never a traceback (INV-LAUNCH-06 / INV-STUB-01).
  ExitRemoteFetch*    = 11  ## remote-fetch delivery: the payload could not be fetched over
                            ## HTTP (network down, non-200, over the size cap, timeout). A
                            ## fetched-but-tampered payload is ExitDigestMismatch, not this —
                            ## this is transport-level, always fail-closed (INV-REMOTE-01).
  ExitPayloadFormat*  = 12  ## the payload declares a `payload_format` (manifest.toml) NEWER
                            ## than this launcher understands (INV-PAYLOAD-07). Refuse rather
                            ## than mis-stage a member/layout we do not know about. A payload
                            ## with no key is legacy/0 and accepted; this fires only above the
                            ## ceiling below.
  ExitBadSignature*   = 13  ## --self-signed (v3 footer): the embedded Ed25519 signature does
                            ## not verify over the footer's structural + digest fields under
                            ## the embedded public key (INV-SIGN-01). Checked AFTER the payload
                            ## and stub digests, so a failure means the signature and the
                            ## (digest-matched) content disagree — a post-build edit that did
                            ## not re-sign. NOT tamper-evidence: an editor who ALSO swaps the
                            ## embedded key re-signs and passes (documented honest limit).

  ## The highest payload_format this launcher can stage. Mirrors overlay.footerSizeFor and
  ## expandCompressedMembers: an unknown/newer version is refused, not guessed at. Bump in
  ## lockstep with payload.PAYLOAD_FORMAT whenever the launcher learns a new payload layout.
  MaxSupportedPayloadFormat* = 1

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
    # TODO(phase-uv): UV_VER knob — when getEnv(sc.envForKnob(kUvVer)) is set, override
    # m.uvVersion with it here (sc threaded in from launch()). Phase 1 only carries the knob.
    let got = ensureUv(stageRoot, m.uvVersion)
    if got.len > 0: return got
    die("thin tier: failed to fetch uv (need curl/powershell + network on first run)")
  die("no uv binary bundled and none on PATH")

proc findBundledPython(stageRoot: string): string =
  ## Scan the staged tree for a real interpreter. python-build-standalone ships `bin/python`
  ## and `bin/python3` as SYMLINKS to `python3.NN`; since INV-STAGE-04 the launcher stages
  ## those aliases as on-disk symlinks (POSIX), so `walkDirRec` must yield `pcLinkToFile` or
  ## the only names we match here (`python3`/`python`) are skipped and a thick payload looks
  ## interpreter-less. `fileExists(py)` at the call site follows the link. On Windows the alias
  ## stays a copy (a regular file), so the default filter would suffice there — but yielding
  ## links is harmless on Windows and keeps one code path.
  let base = stageRoot / "vendor" / "python"
  if not dirExists(base): return ""
  for p in walkDirRec(base, yieldFilter = {pcFile, pcLinkToFile}):
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

proc verifyStubDigest(stub: string, want: array[32, byte]) =
  ## INV-STUB-01. The v2 footer records SHA-256 over the cleartext stub-config bytes.
  ## Verify it BEFORE parsing the canary map, mirroring verifyPayloadDigest.
  ##
  ## Like the payload digest this is self-referential (both the bytes and the digest come
  ## from the same attacker-writable region), so it is NOT tamper-evidence: it detects
  ## corruption/truncation/naive edits and is the precondition for a real signature
  ## (INV-LAUNCH-03, still proposed).
  let got = sha256.digest(stub)
  var diff = 0'u8
  for i in 0 .. 31: diff = diff or (got.data[i] xor want[i])
  if diff != 0'u8:
    stderr.writeLine "haru-pack: stub-config integrity check FAILED — this executable has " &
                     "been modified since it was built."
    stderr.writeLine "haru-pack:   expected sha256 " & hexOf(want)
    stderr.writeLine "haru-pack:   actual   sha256 " & hexOf(got.data)
    quit(ExitBadStub)

proc verifyPayloadSignature(ft: Footer) =
  ## INV-SIGN-01 (--self-signed). Verify the Ed25519 signature over the footer's structural +
  ## digest fields (formatVer, flags, payloadOff/Len, payloadSha, stubOff/Len, stubSha) under
  ## the public key EMBEDDED in the v3 footer tail.
  ##
  ## Order matters: this runs AFTER verifyPayloadDigest and verifyStubDigest, which bind
  ## payloadSha/stubSha to the actual bytes on disk (INV-LAUNCH-01 / INV-STUB-01). Only then
  ## does a signature over those digests transitively cover the bytes. Verifying the signature
  ## first would prove nothing about the payload.
  ##
  ## HONEST LIMIT: the public key sits in the same file, OUTSIDE the signed region. This
  ## detects a post-build edit by anyone who does not ALSO rewrite the embedded key; it is NOT
  ## tamper-evidence unless the key fingerprint is pinned OUT OF BAND. It deliberately does not
  ## satisfy INV-LAUNCH-03 (which requires out-of-band-anchored verification).
  if not ed25519Verify(ft.sig, ft.signed, ft.pubKey):
    stderr.writeLine "haru-pack: self-signed signature check FAILED — this executable's " &
                     "payload no longer matches the embedded signature, or the signature " &
                     "was produced by a different key than the one embedded."
    quit(ExitBadSignature)

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

proc forceRamRequested(sc: StubConfig): bool =
  ## The runtime EPHEMERAL knob (docs/adr/0007) is 2-STATE: `<canary>_EPHEMERAL=1` forces the
  ## RAM-backed root and SKIPS the fit-check (target-autonomy enable, even on a binary not built
  ## `--ephemeral`). There is deliberately NO force-DISK value — an env toggle that pushed an
  ## `--encrypt --ephemeral` payload onto disk would be a confidentiality downgrade an attacker
  ## could set, so any non-"1" value (including "0") is treated as unset/auto, never a downgrade.
  getEnv(sc.envForKnob(kEphemeral)).strip() == "1"

proc autoEphemeralRoot(sc: StubConfig): string =
  ## Auto ephemeral (docs/adr/0007): stage to RAM only if the payload PROVABLY fits, else fall
  ## back to the persistent cache with an honest note. Never gambles RAM it cannot account for.
  when defined(linux):
    if ramWouldFit(sc.unpackedBytes): return ramBackedRoot()   # already int64 (stubconfig.nim)
    stderr.writeLine "haru-pack: --ephemeral: the staged payload does not fit the available " &
                     "RAM (/dev/shm + MemAvailable); staging to the persistent cache instead."
    return baseDir()
  else:
    return ramBackedRoot()          # no guaranteed RAM fs; ramBackedRoot() notes the fallback

proc resolveStagingRoot(sc: StubConfig): string =
  ## Staging-root precedence, computed BEFORE staging (docs/adr/0004 §3 + docs/adr/0007,
  ## INV-BASE-01 / INV-EPHEMERAL-01):
  ##
  ##   BASE_PATH env (explicit path)                                        [highest]
  ##     > EPHEMERAL env =1 -> RAM (skip fit-check; target-autonomy enable). No force-disk value.
  ##     > stub-config base_path (build-time default)
  ##     > ram_only ? (auto: RAM if it fits, else the cache) : the per-user cache
  ##
  ## Only the ROOT is chosen here; stageZip appends the create-and-delete-own subtree
  ## `<root>/<key>-<digest>`. The caller refuses an unsafe root (refuseUnsafeRoot) before it
  ## stages, so a hostile BASE_PATH can relocate staging but never becomes arbitrary-delete.
  let envVal = getEnv(sc.envForKnob(kBasePath))   # BASE_PATH knob (explicit path) wins
  if envVal.len > 0: return envVal
  if forceRamRequested(sc): return ramBackedRoot()  # =1: force RAM, even on a non-ephemeral binary
  if sc.basePath.len > 0: return sc.basePath      # baked path beats baked ram_only (explicit dir)
  if sc.ramOnly: return autoEphemeralRoot(sc)     # auto: RAM iff it fits, else cache
  return baseDir()

proc launch(): int =
  let self = getAppFilename()
  let exeDir = getAppDir()
  let runDir = getCurrentDir()          # run-in-place root
  # `var`: a `--<canary>-reinstall` reserved arg (#3) is consumed here and filtered OUT before the
  # child ever sees it, so the packaged app's own argv is unchanged.
  var userArgs = commandLineParams()

  # 1. locate staged payload root
  var stageRoot = ""
  # Phase-2 reap state (docs/adr/0004 §4). Only ever set on the overlay-staged path below —
  # a HARUPACK_DEV_STAGE tree belongs to the developer and is NEVER reaped (we did not create
  # it). reapTarget is the exact subtree stageZip created/verified this run (INV-REAP-01).
  var reapWanted = false
  var reapTarget = ""
  var reapOverwrite = false
  # The `--<canary>-shred` flag the Windows overwrite-reaper re-execs itself with (#3). Default is
  # the `--haru-shred` a HARU build uses; set to the build's canary once the stub is read.
  var reapShredArg = "--haru-shred"
  # True only when stageRoot came from HARUPACK_DEV_STAGE: like reap, stage-dir eviction is
  # skipped for a dev tree we did not create (INV-LAUNCH-02). Stays false on the overlay path.
  var devStaged = false
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
      devStaged = true
  if stageRoot.len == 0:
    let (found, ft, footerAt) = findFooter(self)
    if not found:
      when defined(haruDev):
        die("no payload appended and HARUPACK_DEV_STAGE unset")
      else:
        die("no payload appended to this executable")
    let fault = footerFault(ft, getFileSize(self).int, footerAt)   # W9 / INV-LAUNCH-05/08
    if fault.len > 0: die("corrupt payload footer: " & fault, ExitBadFooter)
    # Stub-config: cleartext, signature-covered, read BEFORE decrypt/stage so the per-knob
    # canary map decides which env name holds each knob. A v1 (single-payload) binary carries
    # no stub -> the all-HARU default. Only SECRET is consumed in Phase 1 (below); UV_VER /
    # SOURCE_URL / BASE_PATH ride in `sc` for later phases (TODOs at their future consumers).
    var sc = defaultStubConfig()
    if ft.hasStub:
      let stubBytes = readStub(self, ft, footerAt)
      verifyStubDigest(stubBytes, ft.stubSha)   # INV-STUB-01 — before we parse the map
      try:
        sc = parseStubConfig(stubBytes)
      except ValueError as e:
        die(e.msg, ExitBadStub)
    # Payload source (Phase 3 remote-fetch, INV-REMOTE-01). The DELIVERY MODE is fixed at build
    # time by the footer's remote flag; only the URL is a runtime knob. For a remote build the
    # SOURCE_URL knob supplies where to fetch — env `<canary>_SOURCE_URL` overrides the baked
    # `--source-url` (mirror/failover) — and the fetched bytes run through the SAME pipeline as
    # an appended payload: verifyPayloadDigest against the build-baked footer digest is the one
    # trust anchor, so a hostile URL can only cause a fail-closed refusal, never execution of
    # unverified bytes. An APPENDED build reads its overlay and ignores any SOURCE_URL env — a
    # baked-in payload is never redirected to the network by an environment variable.
    var payload: string
    if (ft.flags and FooterFlagRemote) != 0'u16:
      let srcUrl = block:
        let envUrl = getEnv(sc.envForKnob(kSourceUrl))
        if envUrl.len > 0: envUrl else: sc.sourceUrl
      if srcUrl.len == 0:
        die("this build fetches its payload remotely but no source URL is configured " &
            "(neither a baked --source-url nor the " & sc.envForKnob(kSourceUrl) &
            " environment variable)", ExitBadStub)
      stderr.writeLine "haru-pack: fetching payload ..."
      let (body, err) = fetchPayload(srcUrl)
      if err.len > 0:
        die("remote-fetch of the payload failed (" & srcUrl & "): " & err &
            " — a --source-url build needs network on first run.", ExitRemoteFetch)
      payload = body
    else:
      payload = readPayload(self, ft, footerAt)
    verifyPayloadDigest(payload, ft.payloadSha)   # INV-LAUNCH-01 / INV-REMOTE-01 — before decrypt
    # --self-signed (v3): the payload and stub digests are now bound to the real bytes, so a
    # signature over those digests transitively covers the content. Check it here, after the
    # digests and before staging/decrypt (INV-SIGN-01). A v1/v2 footer has hasSig=false and
    # skips this — v2 binaries keep loading unchanged.
    if ft.hasSig:
      verifyPayloadSignature(ft)
    let shahex = hexOf(ft.payloadSha)
    if (ft.flags and FooterFlagEncrypted) != 0'u16 or isEncrypted(payload):
      # SECRET knob (INV-CANARY-01): the decryption key's env NAME is sc.envForKnob(kSecret)
      # (default HARU_SECRET), replacing the retired hardcoded HARUPACK_SECRET.
      payload = openContainer(payload, sc.envForKnob(kSecret))   # dies on failure
    # BASE_PATH / ram_only (docs/adr/0004 §3, INV-BASE-01): resolve the staging ROOT by
    # precedence, then REFUSE an unsafe root (/, a drive/UNC root, or the home root) before we
    # create anything under it. stageZip appends the create-and-delete-own `<key>-<digest>`
    # subtree, which is the only path --reap ever deletes (INV-REAP-01).
    let root = resolveStagingRoot(sc)
    let rootFault = refuseUnsafeRoot(root)
    if rootFault.len > 0:
      die("refusing to stage under an unsafe base path — " & rootFault, ExitBadStub)
    # #3: `--<canary>-reinstall` is a DELIBERATE operator action — WIPE the staged own-subtree, then
    # re-extract. It is an ARG (not an env INPUT), so INV-CANARY-03 does not apply; the prefix is
    # canary-derived (argCanary) only for white-label consistency. The canary is known now that the
    # stub is read (INV-STUB-01). Consume it here and filter it OUT of userArgs so the packaged app
    # never sees it. stageZip wipes ONLY its own computed subtree, through the shared shredGuard, and
    # NEVER a path from arg/env (INV-REAP-01 / INV-BASE-01). A verify mismatch never triggers this —
    # only this explicit arg does (a mismatch stays fatal, INV-STAGE-01).
    let canary = argCanary(sc)
    let reinstallArg = "--" & canary & "-reinstall"
    var reinstall = false
    if reinstallArg in userArgs:
      reinstall = true
      userArgs = userArgs.filterIt(it != reinstallArg)
      stderr.writeLine "haru-pack: " & reinstallArg &
        ": wiping and re-extracting the staged tree (this discards stage state, including any " &
        "declared-writable app data — keep writable state OUTSIDE the stage, in a data dir)."
    stageRoot = stageZip(payload, shahex[0..15], root,
                         reinstall = reinstall, overwrite = sc.overwrite,
                         writable = sc.writable, canary = canary)
    reapWanted = sc.reap                 # build-time --reap; independent of ram_only
    reapTarget = stageRoot               # the exact subtree we just created/verified
    reapOverwrite = sc.overwrite         # build-time --overwrite: shred-on-reap (INV-SHRED-01)
    reapShredArg = "--" & canary & "-shred"   # white-label consistent with --<canary>-reinstall (#3)

  # 2. manifest
  let mfPath = stageRoot / "manifest.toml"
  if not fileExists(mfPath): die("manifest.toml missing in payload: " & mfPath)
  let m = parseManifest(mfPath)
  # INV-PAYLOAD-07: refuse a payload whose declared format is NEWER than we understand, before
  # we act on a manifest we cannot fully interpret. The .haru-links skew (#44) is the concrete
  # case — a launcher predating a member stages it wrong and runs a broken tree with no error;
  # a version gate turns "silent misbehaviour" into a clean refusal. payloadFormat == 0 means a
  # pre-#44 payload with no key, which is accepted; only a value ABOVE the ceiling refuses.
  if m.payloadFormat > MaxSupportedPayloadFormat:
    die("this payload's format (" & $m.payloadFormat & ") is newer than this launcher " &
        "understands (" & $MaxSupportedPayloadFormat & "); rebuild with a matching haru-pack.",
        ExitPayloadFormat)
  if m.entrypoint.len == 0:                 # W16 — this used to be an unguarded [0]
    die("manifest declares no entrypoint: " & mfPath)
  let appDir = stageRoot / m.appSubdir

  # 2b. mark this stage dir as in use, then retire ones nobody has run for a while.
  #     Skipped for a HARUPACK_DEV_STAGE tree: the developer's tree is not ours to
  #     garbage-collect (it is also never reaped, for the same reason). evictStale sweeps the
  #     SIBLINGS of stageRoot — whatever root we actually staged into — so it coexists with the
  #     BASE_PATH / --ephemeral staging roots (docs/adr/0004, 0007) without touching the cache
  #     when the live tree lives elsewhere.
  #
  #     Retention is manifest-only (m.keepDays / m.keepMax, set from haru_pack.toml by
  #     build/declare.py). There is deliberately NO env override: the launcher must not read a
  #     haru-named env INPUT outside the canary model (INV-CANARY), and eviction tuning is not
  #     worth a canary-protected knob — the build-time value is the single source of truth.
  if not devStaged:
    touchStage(stageRoot)
    evictStale(stageRoot, m.keepDays, m.keepMax)

  # 3. env wiring (inject first, then three roots + uv offline knobs)
  # inject (env-append) is applied FIRST so both uv AND the app inherit it, while every
  # reserved var the launcher sets below WINS on a collision — an inject cannot repoint
  # UV_PYTHON off the host and defeat the thick tier's hermeticity (INV-LAUNCH-04). The
  # build refuses reserved keys outright, so this ordering is belt-and-braces (ADR §4.2).
  for (k, v) in m.inject: putEnv(k, v)
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
  let rc = runChild(uv, a, childCwd)

  # 7. detached reap (build-time --reap, docs/adr/0004 §4, INV-REAP-01): after the app exits,
  # hand the staged subtree to a fire-and-forget deleter and return WITHOUT waiting — many GB
  # keep deleting after this stub has died. Only the subtree the launcher created this run is
  # reaped; a dev-stage tree (reapTarget == "") is never touched.
  if reapWanted and reapTarget.len > 0:
    reapDetached(reapTarget, reapOverwrite, reapShredArg)
  return rc

when isMainModule:
  when defined(windows):
    # Hidden shred worker (docs/adr/0004 5b, INV-SHRED-01). The --overwrite reaper on Windows
    # re-execs THIS launcher as `--<canary>-shred <subtree>` (stage.reapDetached), because there is
    # no native per-file secure-erase and PowerShell is frequently locked on hardened targets. The
    # prefix is canary-derived for white-label consistency (#3, `--haru-shred` on a default build);
    # it is cosmetic, and shredGuard is the actual boundary. This is a delete primitive, so it is
    # guarded to a stage-shaped own-subtree under a safe root and never a dev-stage tree
    # (stage.shredGuard); anything else is refused, never run. The stub is not read here (this runs
    # before launch()), so the prefix is matched by SHAPE — a valid canary token — and the target's
    # safety comes entirely from shredGuard, exactly as it did for the fixed `--haru-shred`.
    let shredArgs = commandLineParams()
    if shredArgs.len == 2 and shredArgs[0].startsWith("--") and shredArgs[0].endsWith("-shred") and
       isValidCanary(shredArgs[0][2 ..< shredArgs[0].len - "-shred".len]):
      let why = shredGuard(shredArgs[1])
      if why.len > 0:
        stderr.writeLine "haru-pack: refusing " & shredArgs[0] & ": " & why
        quit(2)
      shredAndRemoveTree(shredArgs[1])
      quit(0)
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

## Runtime uv fetch for the "thin" tier — ONE code path, no external tools.
## Download: puppy (native TLS per OS — WinHTTP/Schannel on Windows, libcurl on Linux/mac).
## Extract: zippy (zip + gzip'd tar). So a bare target needs no curl/wget/tar/powershell.
##
## This runs on the CUSTOMER's machine and the thing it downloads is then EXECUTED, so
## the review of 2026-09-09 (boundary B6) is the design brief for everything below:
## there was no digest, no timeout, no size cap, and the version string went straight
## from the manifest into the URL. Now:
##   * `isValidUvVersion` gates the only attacker-influenced part of the URL
##     (INV-SUPPLY-04);
##   * `checkUvArchive` enforces a hard size cap and, when the payload manifest carries
##     `uv_sha256`, the pinned digest — before a byte is written to disk or extracted
##     (INV-SUPPLY-05);
##   * every request carries an explicit timeout.
##
## HONEST LIMITS. (1) `uv_sha256` IS populated as of 2026-09-11: `build.assemble_payload`
## writes the pinned digest of the release asset for the target from `pins.toml` whenever
## the tier fetches uv, and refuses to build if no pin exists (INV-SUPPLY-01). Before that
## this was a mechanism with no pin behind it and the launcher warned on every fetch; the
## warning path below now only fires for a payload built by an older haru-pack. (2) puppy has
## no streaming API, so the cap can only be checked from a HEAD's content-length and then
## on the body once it is in memory; a hostile server can still make us buffer more than
## the cap before we reject it. (3) The cap is on the compressed archive; a zip bomb that
## fits under it is not caught here. (4) TLS is the OS's; there is no pinning.
import std/[os, strutils]
import zippy/ziparchives
import zippy/tarballs
import parsetoml
import puppy
import stage

const
  BaseUrl = "https://github.com/astral-sh/uv/releases/download/"
  MaxUvArchiveBytes* = 96 * 1024 * 1024   ## uv release archives are ~15-25 MB
  FetchTimeoutSecs* = 120'f32

proc uvAsset(): string =
  ## The uv release asset for the machine THIS launcher was compiled for.
  ##
  ## Selected from `hostCPU`, which Nim resolves at compile time to the --cpu the binary is
  ## being built for — so a launcher cross-compiled for a Raspberry Pi asks for the aarch64
  ## asset, not the build host's. This was hardcoded to x86_64 on all three platforms, which
  ## meant a thin-tier build for any ARM target downloaded an x86_64 uv at first run and died
  ## with "cannot execute binary file" on the customer's machine.
  ##
  ## Keep these names in step with targets._UV_ASSETS on the Python side; the pinned digests
  ## in bundle.UV_SHA256 are keyed by exactly these strings.
  when defined(windows):
    when hostCPU == "arm64": "uv-aarch64-pc-windows-msvc.zip"
    else:                    "uv-x86_64-pc-windows-msvc.zip"
  elif defined(macosx):
    when hostCPU == "arm64": "uv-aarch64-apple-darwin.tar.gz"
    else:                    "uv-x86_64-apple-darwin.tar.gz"
  else:
    when hostCPU == "arm64": "uv-aarch64-unknown-linux-gnu.tar.gz"
    elif hostCPU == "arm":   "uv-armv7-unknown-linux-gnueabihf.tar.gz"
    else:                    "uv-x86_64-unknown-linux-gnu.tar.gz"

proc isValidUvVersion*(v: string): bool =
  ## The manifest is inside the payload, so it is attacker-controlled the moment the
  ## payload is (and it is operator-controlled always). Anything but a bare version
  ## number would let it steer the download somewhere else entirely — `../../` out of
  ## the release path, a `@evil.example` authority, a `?`/`#` truncation.
  if v.len == 0 or v.len > 24: return false
  var s = v
  if s[0] == 'v': s = s[1 .. ^1]
  if s.len == 0: return false
  let parts = s.split('.')
  if parts.len < 1 or parts.len > 4: return false
  for p in parts:
    if p.len == 0 or p.len > 5: return false
    for c in p:
      if c notin {'0'..'9'}: return false
  return true

proc isSha256Hex(s: string): bool =
  s.len == 64 and s.allCharsInSet({'0'..'9', 'a'..'f'})

proc expectedUvSha*(stageRoot: string): string =
  ## The pinned digest has to travel with the payload — the thin tier fetches uv on a
  ## machine we never see — so it lives in the staged `manifest.toml` as `uv_sha256`,
  ## a lowercase sha256 of the release asset for this platform.
  ## Returns "" when the field is absent; returns the raw value when present so a
  ## malformed one is rejected loudly by `checkUvArchive` instead of silently ignored.
  let mf = stageRoot / "manifest.toml"
  if not fileExists(mf): return ""
  try:
    let t = parsetoml.parseFile(mf)
    if not t.contains("uv_sha256"): return ""
    return t["uv_sha256"].getStr("").strip().toLowerAscii
  except CatchableError:
    return ""

proc checkUvArchive*(data: string, expectedSha: string): string =
  ## "" if the bytes may be extracted and executed; otherwise the refusal reason.
  if data.len == 0: return "empty download"
  if data.len > MaxUvArchiveBytes:
    return "archive is " & $data.len & " bytes, over the " & $MaxUvArchiveBytes & " byte cap"
  if expectedSha.len == 0: return ""            # unpinned; caller has already warned
  if not isSha256Hex(expectedSha):
    return "manifest uv_sha256 is not a lowercase sha256 hex digest: " & expectedSha
  let got = sha256hex(data)
  if got != expectedSha:
    return "digest mismatch: manifest pins " & expectedSha & ", download is " & got
  return ""

proc contentLengthOver(url: string): bool =
  ## Advisory pre-flight: refuse an obviously oversized asset before pulling it into
  ## memory. A server that lies or omits content-length just falls through to the
  ## post-download check in `checkUvArchive`.
  try:
    let h = head(url, timeout = FetchTimeoutSecs)
    let cl = h.headers["content-length"]
    if cl.len == 0: return false
    return parseBiggestInt(cl) > MaxUvArchiveBytes
  except CatchableError:
    return false

proc ensureUv*(stageRoot, uvVersion: string, expectedShaOverride = ""): string =
  ## returns a usable uv path, downloading it if needed. "" on failure.
  let exeName = when defined(windows): "uv.exe" else: "uv"
  let target = stageRoot / "vendor" / exeName
  if fileExists(target): return target
  if not isValidUvVersion(uvVersion):
    stderr.writeLine "haru-pack: refusing to fetch uv: manifest uv_version is not a version: " & uvVersion
    return ""
  let expected =
    if expectedShaOverride.len > 0: expectedShaOverride.strip().toLowerAscii
    else: expectedUvSha(stageRoot)
  if expected.len == 0:
    stderr.writeLine "haru-pack: WARNING: the payload manifest records no uv_sha256, so the " &
      "uv binary about to be downloaded and executed is unverified (INV-SUPPLY-01)."
  createDir(stageRoot / "vendor")
  let asset = uvAsset()
  let url = BaseUrl & uvVersion & "/" & asset
  let tmp = stageRoot / "vendor" / ("uv-dl-" & $getCurrentProcessId())
  createDir(tmp)
  let arc = tmp / asset
  stderr.writeLine "haru-pack: fetching uv " & uvVersion & " ..."
  try:
    if contentLengthOver(url):
      stderr.writeLine "haru-pack: refusing uv download: server advertises more than the " &
        $MaxUvArchiveBytes & " byte cap"
      return ""
    let res = get(url, timeout = FetchTimeoutSecs)
    if res.code != 200:
      stderr.writeLine "haru-pack: uv download failed: HTTP " & $res.code
      return ""
    let why = checkUvArchive(res.body, expected)
    if why.len > 0:
      stderr.writeLine "haru-pack: refusing downloaded uv archive: " & why
      return ""
    writeFile(arc, res.body)
    let xdir = tmp / "x"
    if asset.endsWith(".zip"): ziparchives.extractAll(arc, xdir)
    else:                      tarballs.extractAll(arc, xdir)
    for path in walkDirRec(xdir):
      if path.extractFilename == exeName:
        moveFile(path, target)
        when not defined(windows):
          inclFilePermissions(target, {fpUserExec, fpGroupExec, fpOthersExec})
        return target
    stderr.writeLine "haru-pack: uv archive contained no " & exeName
    return ""
  except CatchableError as e:
    stderr.writeLine "haru-pack: uv download failed: " & e.msg
    return ""
  finally:
    removeDir(tmp)       # was leaked on every failure path before

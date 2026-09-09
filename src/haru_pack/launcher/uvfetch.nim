## Runtime uv fetch for the "thin" tier — ONE code path, no external tools.
## Download: puppy (native TLS per OS — WinHTTP/Schannel on Windows, libcurl on Linux/mac).
## Extract: zippy (zip + gzip'd tar). So a bare target needs no curl/wget/tar/powershell.
import std/[os, strutils]
import zippy/ziparchives
import zippy/tarballs
import puppy

proc uvAsset(): string =
  when defined(windows): "uv-x86_64-pc-windows-msvc.zip"
  elif defined(macosx):  "uv-x86_64-apple-darwin.tar.gz"
  else:                  "uv-x86_64-unknown-linux-gnu.tar.gz"

proc ensureUv*(stageRoot, uvVersion: string): string =
  ## returns a usable uv path, downloading it if needed. "" on failure.
  let exeName = when defined(windows): "uv.exe" else: "uv"
  let target = stageRoot / "vendor" / exeName
  if fileExists(target): return target
  createDir(stageRoot / "vendor")
  let asset = uvAsset()
  let url = "https://github.com/astral-sh/uv/releases/download/" & uvVersion & "/" & asset
  let tmp = stageRoot / "vendor" / ("uv-dl-" & $getCurrentProcessId())
  createDir(tmp)
  let arc = tmp / asset
  stderr.writeLine "haru-pack: fetching uv " & uvVersion & " ..."
  try:
    writeFile(arc, fetch(url))              # puppy: returns body, raises on non-2xx, follows redirects
    let xdir = tmp / "x"
    if asset.endsWith(".zip"): ziparchives.extractAll(arc, xdir)
    else:                      tarballs.extractAll(arc, xdir)
    for path in walkDirRec(xdir):
      if path.extractFilename == exeName:
        moveFile(path, target)
        when not defined(windows):
          inclFilePermissions(target, {fpUserExec, fpGroupExec, fpOthersExec})
        removeDir(tmp)
        return target
  except CatchableError:
    return ""
  return ""

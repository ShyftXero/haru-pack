## XZ/LZMA2 decompression for the staged payload — decode only.
##
## Why this exists: the payload is a DEFLATE zip, and `uv` is by far its largest member. On
## uv 0.10.4 the linux-x86_64 binary is 55.59 MB raw, 22.25 MB deflated — and 14.17 MB as
## XZ/LZMA2. So storing uv as `.xz` inside the zip and expanding it here takes 8.08 MB off
## every default- and thick-tier binary (INV-PAYLOAD-04).
##
## The alternative was UPX, and it was rejected: packing modifies the executable, which
## destroys uv's own Authenticode signature, makes the payload bytes match no publisher
## digest, trips AV packer heuristics on exactly the enterprise targets this project is
## built for, and pays the decompression cost on *every* launch. Compressing the payload
## member instead leaves the staged uv **byte-identical to Astral's release** and pays the
## cost once, at stage time.
##
## Cross-compilation notes, both learned the hard way:
##
##  * The include path is built with explicit `/` rather than `parentDir()` and the `/`
##    operator. Those use the TARGET's `DirSep`, so under `-d:mingw` they emit
##    `-I\home\you\...` and mingw cannot find `xz.h`. gcc takes forward slashes everywhere.
##  * `XZ_DEC_BCJ` is not defined and `xz_dec_bcj.c` is not vendored, so the build side must
##    not use a BCJ filter. See `xz/PROVENANCE.md`.
import std/strutils

const xzInc = currentSourcePath().rsplit({'/', '\\'}, 1)[0].replace('\\', '/') & "/xz"
{.passC: "-I" & xzInc.}
{.compile: "xz/xz_crc32.c".}
{.compile: "xz/xz_dec_lzma2.c".}
{.compile: "xz/xz_dec_stream.c".}

type
  XzError* = object of CatchableError

  XzMode {.importc: "enum xz_mode", header: "xz.h".} = cint
  XzRet {.importc: "enum xz_ret", header: "xz.h".} = cint
  XzBuf {.importc: "struct xz_buf", header: "xz.h", bycopy.} = object
    inp {.importc: "in".}: ptr uint8
    inPos {.importc: "in_pos".}: csize_t
    inSize {.importc: "in_size".}: csize_t
    outp {.importc: "out".}: ptr uint8
    outPos {.importc: "out_pos".}: csize_t
    outSize {.importc: "out_size".}: csize_t
  XzDec {.importc: "struct xz_dec", header: "xz.h", incompleteStruct.} = object

proc xz_crc32_init() {.importc, cdecl, header: "xz.h".}
proc xz_dec_init(mode: XzMode, dictMax: uint32): ptr XzDec
  {.importc, cdecl, header: "xz.h".}
proc xz_dec_run(s: ptr XzDec, b: ptr XzBuf): XzRet {.importc, cdecl, header: "xz.h".}
proc xz_dec_end(s: ptr XzDec) {.importc, cdecl, header: "xz.h".}

let
  XZ_SINGLE {.importc, nodecl.}: XzMode
  XZ_STREAM_END {.importc, nodecl.}: XzRet

proc xzDecode*(src: string, outSize: int): string =
  ## One-shot decode of a complete `.xz` stream whose uncompressed size is already known.
  ##
  ## `XZ_SINGLE` is chosen over the streaming modes on purpose: it uses the *output buffer*
  ## as its own dictionary, so there is no separate multi-megabyte dictionary allocation.
  ## A preset-9 stream would otherwise want a 64 MB dictionary, which is a real cost on the
  ## Raspberry Pi targets this project supports. Peak here is output + input instead.
  if outSize <= 0:
    raise newException(XzError, "refusing to decode with a non-positive output size")
  xz_crc32_init()
  let s = xz_dec_init(XZ_SINGLE, 0)
  if s == nil:
    raise newException(XzError, "xz_dec_init failed (out of memory?)")
  result = newString(outSize)
  var b = XzBuf(
    inp: cast[ptr uint8](src[0].addr), inPos: 0, inSize: src.len.csize_t,
    outp: cast[ptr uint8](result[0].addr), outPos: 0, outSize: outSize.csize_t)
  let rc = xz_dec_run(s, b.addr)
  xz_dec_end(s)
  if rc != XZ_STREAM_END:
    # Deliberately not "corrupt payload": the likeliest cause of a non-END return here is a
    # build that compressed with a filter this decoder was not vendored for (BCJ), and that
    # is a haru-pack bug, not a damaged download.
    raise newException(XzError,
      "xz stream did not decode (xz_dec_run returned " & $rc & ", produced " &
      $b.outPos.int & " of " & $outSize & " bytes). If this build used a BCJ filter, " &
      "xz_dec_bcj.c was not vendored — see launcher/xz/PROVENANCE.md.")
  if b.outPos.int != outSize:
    raise newException(XzError,
      "xz stream decoded to " & $b.outPos.int & " bytes, expected " & $outSize)

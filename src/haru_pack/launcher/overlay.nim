## haru-pack overlay: locate an appended payload inside our own signed PE.
## Footer is fixed-size and located by scanning BACKWARD for the start magic,
## so an Authenticode cert table appended at EOF (post-signing) does not hide it.
import std/[os, streams]

const
  FooterMagic* = "HARUPACK"   # 8B start sentinel
  FooterTail*  = "KCAPURAH"   # 8B end sentinel
  FooterSize*  = 8 + 2 + 2 + 8 + 8 + 32 + 8   # = 68
  ScanWindow*  = 256 * 1024   # bytes from EOF to search

type Footer* = object
  formatVer*: uint16
  flags*: uint16
  payloadOff*: uint64
  payloadLen*: uint64
  payloadSha*: array[32, byte]

proc rdU16(b: openArray[byte], o: int): uint16 =
  uint16(b[o]) or (uint16(b[o+1]) shl 8)
proc rdU64(b: openArray[byte], o: int): uint64 =
  var v: uint64 = 0
  for i in 0..7: v = v or (uint64(b[o+i]) shl (8*i))
  v

proc findFooter*(exePath: string): (bool, Footer, int) =
  ## returns (found, footer, absoluteFooterOffset)
  var f = newFileStream(exePath, fmRead)
  defer: f.close()
  let size = getFileSize(exePath).int
  let winStart = max(0, size - ScanWindow)
  f.setPosition(winStart)
  let win = f.readStr(size - winStart)
  # scan backward for start magic
  var i = win.len - FooterSize
  while i >= 0:
    if win[i ..< i+8] == FooterMagic and
       win[i+60 ..< i+68] == FooterTail:
      var raw: array[FooterSize, byte]
      for k in 0 ..< FooterSize: raw[k] = byte(win[i+k])
      var ft: Footer
      ft.formatVer = rdU16(raw, 8)
      ft.flags     = rdU16(raw, 10)
      ft.payloadOff = rdU64(raw, 12)
      ft.payloadLen = rdU64(raw, 20)
      for k in 0..31: ft.payloadSha[k] = raw[28+k]
      return (true, ft, winStart + i)
    dec i
  var empty: Footer
  return (false, empty, -1)

proc footerFault*(ft: Footer, fileSize, footerAt: int): string =
  ## "" when the footer's declared payload extent is representable and actually lies
  ## inside the file, ahead of the footer. Anything else is a diagnostic string.
  ##
  ## payloadOff/payloadLen come off disk, i.e. from whoever last wrote to the binary.
  ## Casting them straight to `int` and handing them to setPosition/readStr asks the
  ## runtime to allocate an attacker-chosen length; -d:release keeps Nim's bounds and
  ## range checks so the result is a crash or an OOM rather than memory corruption,
  ## but a launcher that aborts on a hostile footer with a raw Nim error is still
  ## doing input validation by accident. Do it on purpose.
  if fileSize <= 0: return "cannot determine the size of the executable"
  if footerAt < 0 or footerAt > fileSize: return "footer offset is outside the file"
  let fs = uint64(fileSize)
  if ft.payloadLen == 0'u64: return "footer declares a zero-length payload"
  # Compare each term against the file size BEFORE adding them, so the sum cannot wrap.
  if ft.payloadOff > fs: return "payload offset lies past the end of the file"
  if ft.payloadLen > fs: return "payload length exceeds the size of the file"
  if ft.payloadOff + ft.payloadLen > fs:
    return "payload extends past the end of the file"
  if ft.payloadOff + ft.payloadLen > uint64(footerAt):
    return "payload overlaps its own footer"
  return ""

proc readPayload*(exePath: string, ft: Footer, footerAt: int): string =
  ## Read the raw payload bytes described by the footer, refusing a footer whose
  ## extent does not fit inside this file (see footerFault).
  let fault = footerFault(ft, getFileSize(exePath).int, footerAt)
  if fault.len > 0: raise newException(ValueError, "corrupt payload footer: " & fault)
  var f = newFileStream(exePath, fmRead)
  defer: f.close()
  f.setPosition(int(ft.payloadOff))
  result = f.readStr(int(ft.payloadLen))
  if result.len != int(ft.payloadLen):
    raise newException(ValueError, "payload is shorter than its footer declares")

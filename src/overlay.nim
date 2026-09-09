## uvcannon overlay: locate an appended payload inside our own signed PE.
## Footer is fixed-size and located by scanning BACKWARD for the start magic,
## so an Authenticode cert table appended at EOF (post-signing) does not hide it.
import std/[os, streams]

const
  FooterMagic* = "UVCANON1"   # 8B start sentinel
  FooterTail*  = "1NONACVU"   # 8B end sentinel
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

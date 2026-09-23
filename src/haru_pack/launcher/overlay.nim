## haru-pack overlay: locate an appended payload (and, on a v2 build, a cleartext
## stub-config section) inside our own signed PE. The footer is fixed-size and located by
## scanning BACKWARD for the start magic, so an Authenticode cert table appended at EOF
## (post-signing) does not hide it (INV-LAUNCH-01/05).
##
## Versioned footer (docs/adr/0003-stub-config-and-canary.md §1): the reader dispatches on
## `format_ver`, so a v1 (68B, single-payload) binary keeps loading byte-for-byte while a
## v2 (116B) binary additionally carries the stub-config locator. The shared prefix [0:60]
## is identical across versions; TAIL is always the final 8 bytes.
import std/[os, streams]

const
  FooterMagic* = "HARUPACK"   # 8B start sentinel
  FooterTail*  = "KCAPURAH"   # 8B end sentinel
  FooterV1Size* = 8 + 2 + 2 + 8 + 8 + 32 + 8            # = 68  (payload only)
  FooterV2Size* = 8 + 2 + 2 + 8 + 8 + 32 + 8 + 8 + 32 + 8  # = 116 (payload + stub locator)
  FooterV3Size* = FooterV2Size + 32 + 64                # = 212 (v2 + Ed25519 pubkey + sig)
  SignedRegionLen* = 100      # footer[8:108]: formatVer..stubSha, the --self-signed bytes
  ScanWindow*  = 256 * 1024   # bytes from EOF to search
  FooterFlagEncrypted* = 1'u16 ## bit0: payload is an encrypted container (matches crypto.py)
  FooterFlagRemote*    = 2'u16 ## bit1: payload is FETCHED at runtime, not appended (Phase 3,
                               ## INV-REMOTE-01). payloadLen is 0 and no payload bytes are
                               ## embedded; payloadSha remains the trust anchor for the bytes
                               ## fetched from the SOURCE_URL knob.

type Footer* = object
  formatVer*: uint16
  flags*: uint16
  payloadOff*: uint64
  payloadLen*: uint64
  payloadSha*: array[32, byte]
  hasStub*: bool              # true for a v2 or v3 footer
  stubOff*: uint64
  stubLen*: uint64
  stubSha*: array[32, byte]
  hasSig*: bool               # true only for a v3 (--self-signed) footer
  signed*: array[100, byte]   # footer[8:108], the bytes the signature covers (v2/v3)
  pubKey*: array[32, byte]    # v3: embedded Ed25519 public key (OUTSIDE the signed region)
  sig*: array[64, byte]       # v3: Ed25519 signature over `signed`

proc rdU16(b: openArray[byte], o: int): uint16 =
  uint16(b[o]) or (uint16(b[o+1]) shl 8)
proc rdU64(b: openArray[byte], o: int): uint64 =
  var v: uint64 = 0
  for i in 0..7: v = v or (uint64(b[o+i]) shl (8*i))
  v

proc footerSizeFor(ver: uint16): int =
  ## Byte size of a footer at this version, or 0 for a version this launcher does not
  ## understand — an unknown version is treated as a false-positive MAGIC, never parsed.
  case ver
  of 1'u16: FooterV1Size
  of 2'u16: FooterV2Size
  of 3'u16: FooterV3Size
  else: 0

proc findFooter*(exePath: string): (bool, Footer, int) =
  ## returns (found, footer, absoluteFooterOffset). Dispatches on format_ver: the real
  ## footer's MAGIC is the highest-indexed one, so a MAGIC that happens to occur inside the
  ## payload or stub-config has a lower index and is not reached first.
  var f = newFileStream(exePath, fmRead)
  defer: f.close()
  let size = getFileSize(exePath).int
  let winStart = max(0, size - ScanWindow)
  f.setPosition(winStart)
  let win = f.readStr(size - winStart)
  # start where an 8-byte MAGIC plus its 2-byte format_ver can still be read in-window
  var i = win.len - 10
  while i >= 0:
    if win[i ..< i+8] == FooterMagic:
      let ver = uint16(byte(win[i+8])) or (uint16(byte(win[i+9])) shl 8)
      let fsize = footerSizeFor(ver)
      # An unknown version here is NOT our footer (fail closed by scanning on); a known
      # version must fit in-window AND carry TAIL at its own end, or it is a false positive.
      if fsize > 0 and i + fsize <= win.len and
         win[i+fsize-8 ..< i+fsize] == FooterTail:
        var raw = newSeq[byte](fsize)
        for k in 0 ..< fsize: raw[k] = byte(win[i+k])
        var ft: Footer
        ft.formatVer  = rdU16(raw, 8)
        ft.flags      = rdU16(raw, 10)
        ft.payloadOff = rdU64(raw, 12)
        ft.payloadLen = rdU64(raw, 20)
        for k in 0..31: ft.payloadSha[k] = raw[28+k]
        if ver == 2'u16 or ver == 3'u16:
          ft.hasStub = true
          ft.stubOff = rdU64(raw, 60)
          ft.stubLen = rdU64(raw, 68)
          for k in 0..31: ft.stubSha[k] = raw[76+k]
          # Capture the signed region (footer[8:108]) for v2 and v3 alike; only v3 carries a
          # signature over it, but the bytes are identical, so it is cheap to always keep.
          for k in 0 ..< SignedRegionLen: ft.signed[k] = raw[8+k]
        if ver == 3'u16:
          # v3 --self-signed: the Ed25519 public key and signature ride AFTER the signed
          # region and before TAIL (raw[108:140] pubkey, raw[140:204] sig). They are outside
          # `signed` on purpose — a signature cannot authenticate itself.
          ft.hasSig = true
          for k in 0..31: ft.pubKey[k] = raw[108+k]
          for k in 0..63: ft.sig[k] = raw[140+k]
        return (true, ft, winStart + i)
    dec i
  var empty: Footer
  return (false, empty, -1)

proc footerFault*(ft: Footer, fileSize, footerAt: int): string =
  ## "" when the footer's declared extents are representable and actually lie inside the
  ## file, ahead of the footer. Anything else is a diagnostic string.
  ##
  ## payloadOff/payloadLen (and, on v2, stubOff/stubLen) come off disk, i.e. from whoever
  ## last wrote to the binary. Casting them straight to `int` and handing them to
  ## setPosition/readStr asks the runtime to allocate an attacker-chosen length; -d:release
  ## keeps Nim's bounds and range checks so the result is a crash or an OOM rather than
  ## memory corruption, but a launcher that aborts on a hostile footer with a raw Nim error
  ## is still doing input validation by accident. Do it on purpose (INV-LAUNCH-05).
  if fileSize <= 0: return "cannot determine the size of the executable"
  if footerAt < 0 or footerAt > fileSize: return "footer offset is outside the file"
  let fs = uint64(fileSize)
  # Phase 3 remote-fetch (INV-REMOTE-01): a remote build embeds NO payload bytes, so the
  # payload extent is legitimately empty (payloadLen == 0). Skip the payload-extent checks
  # for such a footer; readPayload is never called on it (main.launch fetches instead), and
  # the stub-config — which is mandatory for a remote build (it carries source_url) — still
  # gets the full validation below. An APPENDED build (the default) is unchanged.
  let remote = (ft.flags and FooterFlagRemote) != 0'u16
  if remote:
    # A remote footer embeds no payload: its extent MUST be empty. readPayload is never called
    # on this path, but pin the fields to their only valid values so no future reader inherits
    # an unvalidated, attacker-writable offset/length from a remote-flagged footer.
    if ft.payloadLen != 0'u64:
      return "remote footer declares a non-zero payload length"
    if ft.payloadOff > fs:
      return "remote footer payload offset lies past the end of the file"
  if not remote:
    if ft.payloadLen == 0'u64: return "footer declares a zero-length payload"
    # Compare each term against the file size BEFORE adding them, so the sum cannot wrap.
    if ft.payloadOff > fs: return "payload offset lies past the end of the file"
    if ft.payloadLen > fs: return "payload length exceeds the size of the file"
    if ft.payloadOff + ft.payloadLen > fs:
      return "payload extends past the end of the file"
    if ft.payloadOff + ft.payloadLen > uint64(footerAt):
      return "payload overlaps its own footer"
  # v2 only: the stub-config locator gets the same up-front validation (INV-LAUNCH-08).
  if ft.hasStub:
    if ft.stubLen == 0'u64: return "footer declares a zero-length stub-config"
    if ft.stubOff > fs: return "stub-config offset lies past the end of the file"
    if ft.stubLen > fs: return "stub-config length exceeds the size of the file"
    if ft.stubOff + ft.stubLen > fs:
      return "stub-config extends past the end of the file"
    if ft.payloadOff + ft.payloadLen > ft.stubOff:
      return "payload overlaps the stub-config"
    if ft.stubOff + ft.stubLen > uint64(footerAt):
      return "stub-config overlaps its own footer"
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

proc readStub*(exePath: string, ft: Footer, footerAt: int): string =
  ## Read the raw stub-config bytes described by a v2 footer. Its extent is validated by
  ## the same footerFault the payload uses (INV-LAUNCH-05/08 discipline); the digest over
  ## these bytes is checked by the caller before parse (INV-STUB-01).
  let fault = footerFault(ft, getFileSize(exePath).int, footerAt)
  if fault.len > 0: raise newException(ValueError, "corrupt stub-config footer: " & fault)
  var f = newFileStream(exePath, fmRead)
  defer: f.close()
  f.setPosition(int(ft.stubOff))
  result = f.readStr(int(ft.stubLen))
  if result.len != int(ft.stubLen):
    raise newException(ValueError, "stub-config is shorter than its footer declares")

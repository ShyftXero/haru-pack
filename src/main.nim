## uvcannon M0 spike: prove we can locate our appended payload inside the
## running exe even after it has been Authenticode-signed.
import std/[os, strutils]
import overlay

when isMainModule:
  let self = getAppFilename()
  let (found, ft, off) = findFooter(self)
  if not found:
    stderr.writeLine "uvcannon: no payload footer found"
    quit(2)
  echo "exe            = ", self
  echo "footer offset  = ", off
  echo "format_ver     = ", ft.formatVer
  echo "flags          = ", ft.flags
  echo "payload_off    = ", ft.payloadOff
  echo "payload_len    = ", ft.payloadLen
  var shahex = ""
  for b in ft.payloadSha: shahex.add toHex(int(b), 2).toLowerAscii
  echo "payload_sha256 = ", shahex
  quit(0)

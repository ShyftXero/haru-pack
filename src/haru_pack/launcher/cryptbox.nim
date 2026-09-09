## Runtime decryption + license checks for --encrypt payloads. Matches crypto.py.
## Container: magic"HPAKENC1"|ver u16|flags u16|iters u32|salt16|nonce12|tag16|
##            esecret_len u16|esecret|policy_len u32|policy|ciphertext
## key = PBKDF2-HMAC-SHA256(secret [+0x1f+machine][+0x1f+user], salt, iters, 32)
## policy (JSON) is the GCM AAD -> tamper-evident. No PKI.
import std/[os, osproc, strutils, times, json, terminal]
import nimcrypto/[pbkdf2, bcmode, rijndael, sha2]

const
  Magic = "HPAKENC1"
  Obfus = "haru-pack/embedded-secret/v1"
  BindMachine = 1'u16
  BindUser = 2'u16
  EmbedSecret = 4'u16

type Box = object
  flags: uint16
  iters: int
  salt, nonce, tag: seq[byte]
  esecret, policy, ciphertext: seq[byte]

proc rdU16(b: seq[byte], o: int): uint16 = uint16(b[o]) or (uint16(b[o+1]) shl 8)
proc rdU32(b: seq[byte], o: int): int =
  int(uint32(b[o]) or (uint32(b[o+1]) shl 8) or (uint32(b[o+2]) shl 16) or (uint32(b[o+3]) shl 24))

proc isEncrypted*(raw: string): bool =
  raw.len >= 8 and raw[0..7] == Magic

proc parseBox(raw: string): Box =
  var b = newSeq[byte](raw.len)
  for i in 0 ..< raw.len: b[i] = byte(raw[i])
  result.flags = rdU16(b, 10)
  result.iters = rdU32(b, 12)
  result.salt = b[16 ..< 32]
  result.nonce = b[32 ..< 44]
  result.tag = b[44 ..< 60]
  let eslen = int(rdU16(b, 60))
  var o = 62
  result.esecret = b[o ..< o+eslen]; o += eslen
  let plen = rdU32(b, o); o += 4
  result.policy = b[o ..< o+plen]; o += plen
  result.ciphertext = b[o ..< b.len]

proc machineId(): string =
  when defined(linux):
    for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
      if fileExists(p): return readFile(p).strip
  elif defined(windows):
    let (o, rc) = execCmdEx("reg query \"HKLM\\SOFTWARE\\Microsoft\\Cryptography\" /v MachineGuid")
    if rc == 0:
      for line in o.splitLines:
        if "MachineGuid" in line: return line.splitWhitespace[^1]
  elif defined(macosx):
    let (o, rc) = execCmdEx("ioreg -rd1 -c IOPlatformExpertDevice")
    if rc == 0:
      for line in o.splitLines:
        if "IOPlatformUUID" in line: return line.split('"')[^2]
  return ""

proc currentUser(): string =
  result = getEnv("USER")
  if result.len == 0: result = getEnv("USERNAME")

proc xorBytes(b: seq[byte], pad: string): string =
  for i in 0 ..< b.len: result.add char(b[i] xor byte(pad[i mod pad.len]))

proc resolveSecret(box: Box): string =
  ## env HARUPACK_SECRET -> embedded (weak) -> interactive prompt
  result = getEnv("HARUPACK_SECRET")
  if result.len > 0: return
  if (box.flags and EmbedSecret) != 0'u16 and box.esecret.len > 0:
    return xorBytes(box.esecret, Obfus)
  if stdin.isatty():
    stderr.write "License secret: "
    result = stdin.readLine()

proc checkPolicy(box: Box) =
  ## date + geo (machine/user are cryptographically bound via the key)
  let j = parseJson(cast[string](box.policy))
  let expires = j{"expires"}.getStr("")
  if expires.len > 0:
    let exp = parse(expires, "yyyy-MM-dd", utc())
    if now().utc > exp + initDuration(days = 1):
      quit("haru-pack: license expired (" & expires & ")", 3)
  let geo = j{"geo"}
  if not geo.isNil and geo.len > 0:
    let cur = getEnv("HARUPACK_GEO")   # offline geo is weak; online lookup is future work
    var ok = false
    for g in geo:
      if g.getStr == cur and cur.len > 0: ok = true
    if not ok:
      quit("haru-pack: not licensed for this location (allowed: " & $geo & ")", 3)

proc openContainer*(raw: string): string =
  ## verify policy, derive key, GCM-decrypt -> returns the plaintext payload zip.
  let box = parseBox(raw)
  checkPolicy(box)
  let secret = resolveSecret(box)
  if secret.len == 0:
    quit("haru-pack: this build is encrypted — set HARUPACK_SECRET (or run interactively)", 4)
  var pw = newSeq[byte](secret.len)
  for i in 0 ..< secret.len: pw[i] = byte(secret[i])
  if (box.flags and BindMachine) != 0'u16:
    pw.add byte(0x1f); (for c in machineId(): pw.add byte(c))
  if (box.flags and BindUser) != 0'u16:
    pw.add byte(0x1f); (for c in currentUser(): pw.add byte(c))
  let key = pbkdf2(sha256, pw, box.salt, box.iters, 32)
  var gcm: GCM[aes256]
  gcm.init(key, box.nonce, box.policy)
  var pt = newSeq[byte](box.ciphertext.len)
  gcm.decrypt(box.ciphertext, pt)
  let tag = gcm.getTag()
  gcm.clear()
  for i in 0 ..< 16:
    if tag[i] != box.tag[i]:
      quit("haru-pack: wrong secret / not authorized for this machine / tampered payload", 5)
  result = newString(pt.len)
  for i in 0 ..< pt.len: result[i] = char(pt[i])

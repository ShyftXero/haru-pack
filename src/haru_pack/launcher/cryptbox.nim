## Runtime decryption + license checks for --encrypt payloads. Matches crypto.py.
## Container v2: magic"HPAKENC1"|ver u16|flags u16|iters u32|salt16|nonce12|tag16|
##               esecret_len u16|esecret|ciphertext
## where ciphertext = AES-256-GCM( policy_len u32 | policy | payload.zip ) and the AAD is
## every header byte preceding the ciphertext except the tag field itself:
##   aad = b[0 ..< 44] & b[60 ..< 62+esecret_len]
## so ver/flags/iters/salt/nonce/esecret_len/esecret are tamper-EVIDENT, not merely
## fail-closed (INV-CRYPTO-04). The tag is elided because it cannot authenticate itself;
## editing it is what tag verification catches. Container version 1 (AAD = bare magic) is
## rejected by version, before a secret is ever asked for.
## key = PBKDF2-HMAC-SHA256(secret [+0x1f+hostname][+0x1f+loginUser], salt, iters, 32), where
## the hostname is canonicalized IDENTICALLY to crypto.canon_hostname before the fold
## (INV-BIND-01). The machine value is the OS hostname (cross-platform), the user value is the
## OS login username — NOT $USER/$USERNAME.
##
## The policy is INSIDE the ciphertext, not the AAD, and not in the header — a
## reverse-engineer sees no expiry/geo/machine/user, and cannot edit them without the key.
## (Two earlier revisions of this comment said the policy was the AAD, and said it sat in
## the header. Both were wrong; the code has always done what is written above. See
## INV-CRYPTO-01.)
## No PKI.
import std/[os, strutils, times, json, terminal, nativesockets]
import nimcrypto/[pbkdf2, bcmode, rijndael, sha2]
import execgate
when defined(windows):
  import std/winlean            # GetComputerNameExW / GetUserNameW FFI (precedent: stage.nim)
else:
  import std/posix              # getpwuid / getuid for the OS login username

const
  Magic = "HPAKENC1"
  ContainerVersion = 2'u16      # must equal crypto.CONTAINER_VERSION
  TagOff = 44                   # tag[16] lives at [44 ..< 60]; elided from the AAD
  HdrFixed = 62                 # magic..esecret_len; esecret follows, then the ciphertext
  Obfus = "haru-pack/embedded-secret/v1"
  BindMachine = 1'u16
  BindUser = 2'u16
  EmbedSecret = 4'u16

type Box = object
  version, flags: uint16
  iters: int
  salt, nonce, tag: seq[byte]
  esecret, ciphertext, aad: seq[byte]

proc rdU16(b: seq[byte], o: int): uint16 = uint16(b[o]) or (uint16(b[o+1]) shl 8)
proc rdU32(b: seq[byte], o: int): int =
  int(uint32(b[o]) or (uint32(b[o+1]) shl 8) or (uint32(b[o+2]) shl 16) or (uint32(b[o+3]) shl 24))

proc isEncrypted*(raw: string): bool =
  raw.len >= 8 and raw[0..7] == Magic

proc parseBox(raw: string): Box =
  if raw.len < HdrFixed:
    quit("haru-pack: corrupt encrypted container (truncated header)", 5)
  var b = newSeq[byte](raw.len)
  for i in 0 ..< raw.len: b[i] = byte(raw[i])
  result.version = rdU16(b, 8)
  result.flags = rdU16(b, 10)
  result.iters = rdU32(b, 12)
  result.salt = b[16 ..< 32]
  result.nonce = b[32 ..< 44]
  result.tag = b[44 ..< 60]
  let eslen = int(rdU16(b, 60))
  var o = 62
  if b.len < o + eslen:
    quit("haru-pack: corrupt encrypted container (truncated embedded secret)", 5)
  result.esecret = b[o ..< o+eslen]; o += eslen
  result.ciphertext = b[o ..< b.len]
  # AAD = whole header except the tag field: b[0 ..< 44] & b[60 ..< 62+eslen]
  result.aad = b[0 ..< TagOff]
  result.aad.add b[TagOff+16 ..< HdrFixed+eslen]

proc canonHostname*(name: string): string =
  ## Canonicalized IDENTICALLY to crypto.canon_hostname before the 0x1f KDF fold: ASCII
  ## lowercase, then strip a SINGLE trailing dot. `WS1.CORP.` and `ws1.corp` both collapse to
  ## `ws1.corp`. The KDF is EXACT-MATCH, so one differing byte bricks the licence on the RIGHT
  ## host — this MUST byte-match the Python writer (INV-BIND-01, tests/test_binding.py).
  result = name.toLowerAscii()
  if result.len > 0 and result[^1] == '.':
    result.setLen(result.len - 1)

when defined(windows):
  # WinAPI hostname/username readers via winlean FFI. GetComputerNameExW lives in kernel32,
  # GetUserNameW in advapi32 — both are linked by the FFI's `dynlib` pragma.
  type ComputerNameFormat = int32
  const
    ComputerNameDnsHostname: ComputerNameFormat = 1
    ComputerNameDnsFullyQualified: ComputerNameFormat = 3
  proc getComputerNameExW(nameType: ComputerNameFormat, lpBuffer: WideCString,
                          nSize: ptr int32): int32
    {.stdcall, dynlib: "kernel32", importc: "GetComputerNameExW".}
  proc getUserNameW(lpBuffer: WideCString, pcbBuffer: ptr int32): int32
    {.stdcall, dynlib: "advapi32", importc: "GetUserNameW".}

  proc winComputerName(fmt: ComputerNameFormat): string =
    var size: int32 = 0
    discard getComputerNameExW(fmt, cast[WideCString](nil), addr size)  # ask for the length
    if size <= 0: return ""
    var buf = newWideCString(int(size))
    if getComputerNameExW(fmt, buf, addr size) != 0:
      result = $buf

  proc winUserName(): string =
    ## GetUserNameW writes the length (incl. the NUL) into pcbBuffer. NOTE: under the
    ## NETWORK SERVICE account this returns "<HOSTNAME>$" — desktop-irrelevant, but noted in
    ## THREAT_MODEL.md so a service-account binding is not a surprise.
    var size: int32 = 0
    discard getUserNameW(cast[WideCString](nil), addr size)             # ask for the length
    if size <= 0: return ""
    var buf = newWideCString(int(size))
    if getUserNameW(buf, addr size) != 0:
      result = $buf

proc hostnameCanon(): string =
  ## The RUNTIME hostname, canonicalized for the KDF (INV-BIND-01).
  ##   * Windows: GetComputerNameExW(DnsFullyQualified), falling back to DnsHostname.
  ##   * POSIX/macOS: std/nativesockets getHostname (short OR FQDN depending on DNS).
  ## FQDN is absent on off-domain/WORKGROUP boxes, so a binary BOUND to the FQDN fails closed
  ## on a host that reports only the short name — the exact-match footgun THREAT_MODEL.md
  ## documents and tests/test_binding.py pins as KNOWN behaviour.
  var raw = ""
  when defined(windows):
    raw = winComputerName(ComputerNameDnsFullyQualified)
    if raw.len == 0: raw = winComputerName(ComputerNameDnsHostname)
  else:
    try: raw = getHostname()
    except CatchableError: raw = ""
  result = canonHostname(raw)

proc loginUser(): string =
  ## The OS LOGIN username — NOT getEnv("USER")/getEnv("USERNAME"), which the person being
  ## restricted sets (INV-BIND-01). Windows: GetUserNameW. POSIX/macOS:
  ## getpwuid(getuid()).pw_name.
  when defined(windows):
    result = winUserName()
  else:
    let pw = getpwuid(getuid())
    if pw != nil: result = $pw.pw_name

proc xorBytes(b: seq[byte], pad: string): string =
  for i in 0 ..< b.len: result.add char(b[i] xor byte(pad[i mod pad.len]))

proc resolveSecret(box: Box, secretEnv: string): string =
  ## env <secretEnv> -> embedded (weak) -> interactive prompt.
  ## The env NAME is resolved by the launcher from the SECRET knob's canary
  ## (docs/adr/0003-stub-config-and-canary.md §3.3, INV-CANARY-01); the all-HARU default
  ## makes it HARU_SECRET, which replaces the retired HARUPACK_SECRET.
  result = getEnv(secretEnv)
  if result.len > 0: return
  if (box.flags and EmbedSecret) != 0'u16 and box.esecret.len > 0:
    return xorBytes(box.esecret, Obfus)
  if stdin.isatty():
    # no-echo read: the secret must not land in the terminal, a recorded session, or a CI
    # log (INV-SECRET-01). The prompt goes to stderr so it never pollutes app stdout.
    stderr.write "License secret: "
    result = readPasswordFromStdin("")

proc checkPolicy(policy: seq[byte]) =
  ## The execution gates (INV-GATE-01). Uniform shape: resolve a current value, match an
  ## allow-policy, fail closed. Runs POST-decrypt, so the policy itself is never visible in
  ## cleartext to a reverse-engineer holding only the binary.
  ##   * date  (expiry)                         — checked here
  ##   * geo/ip (location/address)              — checked online by execgate.checkGeoGate
  ##   * machine/user                           — cryptographically bound via the key: a wrong
  ##                                              value means the payload never decrypts, so
  ##                                              reaching this proc already proves them (strictly
  ##                                              stronger than a checked rule).
  ##
  ## What "no env bypass" does and does not mean. This comment used to claim NO environment
  ## variable can satisfy or bypass a gate. That is true only of the two gates decided here,
  ## and it is worth keeping the line honest because an overstated gate is how a packager ends
  ## up shipping to someone they meant to exclude:
  ##   * expiry comes from the clock, and geo reads no env at all — the HARUPACK_GEO
  ##     honor-system bypass is retired and nothing replaced it (INV-GEO-01, INV-CANARY-03).
  ##   * user binding reads the OS LOGIN username (`loginUser` above: getpwuid(getuid()).pw_name
  ##     on POSIX, GetUserNameW on Windows) and folds it into the key derivation below. It is
  ##     NO LONGER $USER/$USERNAME, so `USER=alice ./app` no longer changes it — but it is still
  ##     a string tied to a login the licensee controls on their own machine, so treat it as a
  ##     second passphrase component, NOT an identity check. Machine binding
  ##     (`hostnameCanon` — the OS hostname, canonicalized) reads the host, not the environment.
  ##   * geo is ADVISORY against a determined local adversary, because the resolver call is made
  ##     on the end user's own machine: https_proxy, SSL_CERT_FILE/SSL_CERT_DIR, DNS or
  ##     /etc/hosts let them MITM it and forge an allowed country, and endpoint consensus does
  ##     not help — one on-path position intercepts every endpoint identically. It is real
  ##     against a casual user and against honest network faults (fail-closed offline). See
  ##     INV-GEO-01's HONEST LIMIT note and docs/adr/0006 §"Honest limits".
  let j = parseJson(cast[string](policy))
  let expires = j{"expires"}.getStr("")
  if expires.len > 0:
    let exp = parse(expires, "yyyy-MM-dd", utc())
    if now().utc > exp + initDuration(days = 1):
      quit("haru-pack: license expired (" & expires & ")", 3)
  # geo/ip execution gate (INV-GEO-01). Current builds emit a JSON OBJECT
  # {endpoints, consensus, allow[]} that execgate resolves online and fails closed on. The
  # retired HARUPACK_GEO env bypass is GONE — no env can set the location. A pre-Phase-4
  # array-form geo policy depended on that bypass and can no longer be honored, so a non-empty
  # array is refused rather than silently ignored (a dropped location restriction is a breach).
  let geo = j{"geo"}
  # The online-consensus execution gate (execgate.checkGeoGate, INV-GATE-01/INV-GEO-01, ADR
  # 0006) has since landed on main, superseding the offline fail-closed placeholder this branch
  # wrote before that gate existed. It reads NO environment variable (no honor-system bypass —
  # INV-CANARY-03 stays satisfied), resolves the caller's IP+geo from a consensus of resolvers,
  # and fails closed exactly like the placeholder did on anything it cannot verify. A pre-Phase-4
  # ARRAY-form geo policy (which depended on the retired HARUPACK_GEO bypass) can no longer be
  # honored at all, so it is refused outright rather than silently ignored.
  if geo != nil:
    case geo.kind
    of JObject: checkGeoGate(geo)
    of JArray:
      if geo.len > 0:
        quit("haru-pack: this build carries a retired geo-policy format; rebuild with a " &
             "current haru-pack (INV-GEO-01)", 3)
    else: discard

proc openContainer*(raw: string, secretEnv: string): string =
  ## derive key, GCM-decrypt, THEN parse+check the (hidden) policy -> returns payload zip.
  ## `secretEnv` is the env NAME the SECRET knob resolves to (default HARU_SECRET); the
  ## caller passes `sc.envForKnob(kSecret)`. The container byte format is UNCHANGED — only
  ## the source of the secret's env name moved (INV-CANARY-01).
  let box = parseBox(raw)
  if box.version != ContainerVersion:
    quit("haru-pack: unsupported encrypted container version " & $box.version &
         " (this launcher reads version " & $ContainerVersion & " — rebuild the binary)", 5)
  let secret = resolveSecret(box, secretEnv)
  if secret.len == 0:
    quit("haru-pack: this build is encrypted — set " & secretEnv &
         " (or run interactively)", 4)
  var pw = newSeq[byte](secret.len)
  for i in 0 ..< secret.len: pw[i] = byte(secret[i])
  if (box.flags and BindMachine) != 0'u16:
    pw.add byte(0x1f); (for c in hostnameCanon(): pw.add byte(c))
  if (box.flags and BindUser) != 0'u16:
    pw.add byte(0x1f); (for c in loginUser(): pw.add byte(c))
  let key = pbkdf2(sha256, pw, box.salt, box.iters, 32)
  var gcm: GCM[aes256]
  gcm.init(key, box.nonce, box.aad)      # AAD covers the header (INV-CRYPTO-04)
  var pt = newSeq[byte](box.ciphertext.len)
  gcm.decrypt(box.ciphertext, pt)
  let tag = gcm.getTag()
  gcm.clear()
  # constant-time tag comparison: every byte is examined, no early exit (W10)
  var diff = 0'u8
  for i in 0 ..< 16: diff = diff or (tag[i] xor box.tag[i])
  if diff != 0'u8:
    quit("haru-pack: wrong secret / not authorized for this machine / tampered payload", 5)
  # plaintext = policy_len(4) | policy | zip — checks happen AFTER decrypt.
  # Post-authentication, so only a secret-holder gets here; still bounds-checked, because
  # an unvalidated plen is a crash or a negative-length allocation, not a failed open.
  if pt.len < 4:
    quit("haru-pack: corrupt payload (plaintext shorter than its length prefix)", 5)
  let plen = rdU32(pt, 0)
  if plen < 0 or plen > pt.len - 4:
    quit("haru-pack: corrupt payload (policy length " & $plen & " exceeds " &
         $(pt.len - 4) & " bytes of plaintext)", 5)
  checkPolicy(pt[4 ..< 4+plen])
  result = newString(pt.len - 4 - plen)
  for i in 0 ..< result.len: result[i] = char(pt[4+plen+i])

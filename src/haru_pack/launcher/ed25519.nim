## Ed25519 signature VERIFICATION for the launcher (RFC 8032).
##
## Why this file exists: nimcrypto (the launcher's crypto dependency) ships SHA-2, HMAC,
## PBKDF2 and AES but NO public-key primitives — there is no Ed25519 in it (checked against
## nimcrypto 0.7.3, the pinned version). Rather than add a second unpinned nimble dependency
## whose exact bytes we could not fix (INV-SUPPLY-02 is already `proposed` because
## `compile_launcher` runs a bare `nim c`), the verifier is VENDORED here: it is in-repo,
## auditable, and identical on every build. Signing lives on the Python side (the
## `cryptography` library, a project dep); this side only VERIFIES.
##
## Provenance: a direct port of the Ed25519 verification path of TweetNaCl
## (`crypto_sign_open`), Daniel J. Bernstein / Bern van Gastel / Wesley Janssen / Peter
## Schwabe / Sjaak Smetsers — released into the PUBLIC DOMAIN (https://tweetnacl.cr.yp.to/).
## The field arithmetic (gf = 16 x int64 limbs) and the reduce/modL group-order reduction are
## unchanged; only SHA-512 is taken from nimcrypto instead of TweetNaCl's own, since RFC 8032
## fixes the hash to SHA-512 and nimcrypto already provides it. Verified against the RFC 8032
## §7.1 test vectors and against signatures produced by the Python side
## (tests/test_self_signed.py, tests/launcher_ed25519_test.nim).
##
## Ed25519 is DETERMINISTIC (RFC 8032): the same key over the same message yields the same
## signature, which is exactly what haru-pack's byte-identical-rebuild property needs — no
## per-signature randomness, no salt. This module is verify-only, so it has no randomness at
## all.

import nimcrypto/sha2

type
  Gf = array[16, int64]      ## a GF(2^255-19) field element, 16 signed 16-bit-ish limbs
  Point = array[4, Gf]       ## an extended-coordinate curve point (X, Y, Z, T)

const
  gf0: Gf = [0'i64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  gf1: Gf = [1'i64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  D: Gf = [0x78a3'i64, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
           0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]
  D2: Gf = [0xf159'i64, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
            0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]
  X: Gf = [0xd51a'i64, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
           0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]
  Y: Gf = [0x6658'i64, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
           0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]
  I: Gf = [0xa0b0'i64, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
           0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83]
  ## L = 2^252 + 27742317777372353535851937790883648493, the group order, little-endian.
  L: array[32, int64] = [
    0xed'i64, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x10]

proc ctEq32(a, b: array[32, byte]): bool =
  ## constant-time equality of two 32-byte strings
  var d: byte = 0
  for i in 0 .. 31: d = d or (a[i] xor b[i])
  d == 0'u8

proc set25519(r: var Gf, a: Gf) =
  for i in 0 .. 15: r[i] = a[i]

proc car25519(o: var Gf) =
  for i in 0 .. 15:
    o[i] += (1'i64 shl 16)
    let c = o[i] shr 16
    if i < 15:
      o[i + 1] += c - 1
    else:
      o[0] += 38 * (c - 1)          # (c-1) + 37*(c-1) = 38*(c-1); wrap of the top limb
    o[i] -= c shl 16

proc sel25519(p, q: var Gf, b: int) =
  ## constant-time conditional swap of p and q when b == 1
  let c = not (int64(b) - 1)        # b==1 -> all ones; b==0 -> zero
  for i in 0 .. 15:
    let t = c and (p[i] xor q[i])
    p[i] = p[i] xor t
    q[i] = q[i] xor t

proc pack25519(o: var array[32, byte], n: Gf) =
  var t, m: Gf
  for i in 0 .. 15: t[i] = n[i]
  car25519(t); car25519(t); car25519(t)
  for _ in 0 .. 1:
    m[0] = t[0] - 0xffed
    for i in 1 .. 14:
      m[i] = t[i] - 0xffff - ((m[i - 1] shr 16) and 1)
      m[i - 1] = m[i - 1] and 0xffff
    m[15] = t[15] - 0x7fff - ((m[14] shr 16) and 1)
    let b = (m[15] shr 16) and 1
    m[14] = m[14] and 0xffff
    sel25519(t, m, int(1 - b))
  for i in 0 .. 15:
    o[2 * i] = byte(t[i] and 0xff)
    o[2 * i + 1] = byte((t[i] shr 8) and 0xff)

proc neq25519(a, b: Gf): bool =
  var c, d: array[32, byte]
  pack25519(c, a); pack25519(d, b)
  not ctEq32(c, d)

proc par25519(a: Gf): byte =
  var d: array[32, byte]
  pack25519(d, a)
  d[0] and 1'u8

proc unpack25519(o: var Gf, n: array[32, byte]) =
  for i in 0 .. 15:
    o[i] = int64(n[2 * i]) + (int64(n[2 * i + 1]) shl 8)
  o[15] = o[15] and 0x7fff

proc fadd(o: var Gf, a, b: Gf) =
  for i in 0 .. 15: o[i] = a[i] + b[i]

proc fsub(o: var Gf, a, b: Gf) =
  for i in 0 .. 15: o[i] = a[i] - b[i]

proc fmul(o: var Gf, a, b: Gf) =
  var t: array[31, int64]
  for i in 0 .. 15:
    for j in 0 .. 15:
      t[i + j] += a[i] * b[j]
  for i in 0 .. 14:
    t[i] += 38 * t[i + 16]
  for i in 0 .. 15:
    o[i] = t[i]
  car25519(o); car25519(o)

proc fsqr(o: var Gf, a: Gf) = fmul(o, a, a)

proc inv25519(o: var Gf, i: Gf) =
  var c: Gf
  for a in 0 .. 15: c[a] = i[a]
  for a in countdown(253, 0):
    fsqr(c, c)
    if a != 2 and a != 4: fmul(c, c, i)
  for a in 0 .. 15: o[a] = c[a]

proc pow2523(o: var Gf, i: Gf) =
  var c: Gf
  for a in 0 .. 15: c[a] = i[a]
  for a in countdown(250, 0):
    fsqr(c, c)
    if a != 1: fmul(c, c, i)
  for a in 0 .. 15: o[a] = c[a]

proc addPoint(p: var Point, q: Point) =
  var a, b, c, d, t, e, f, g, h: Gf
  fsub(a, p[1], p[0])
  fsub(t, q[1], q[0])
  fmul(a, a, t)
  fadd(b, p[0], p[1])
  fadd(t, q[0], q[1])
  fmul(b, b, t)
  fmul(c, p[3], q[3])
  fmul(c, c, D2)
  fmul(d, p[2], q[2])
  fadd(d, d, d)
  fsub(e, b, a)
  fsub(f, d, c)
  fadd(g, d, c)
  fadd(h, b, a)
  fmul(p[0], e, f)
  fmul(p[1], h, g)
  fmul(p[2], g, f)
  fmul(p[3], e, h)

proc cswap(p, q: var Point, b: byte) =
  for i in 0 .. 3:
    sel25519(p[i], q[i], int(b))

proc packPoint(r: var array[32, byte], p: Point) =
  var tx, ty, zi: Gf
  inv25519(zi, p[2])
  fmul(tx, p[0], zi)
  fmul(ty, p[1], zi)
  pack25519(r, ty)
  r[31] = r[31] xor (par25519(tx) shl 7)

proc scalarmult(p: var Point, q: var Point, s: array[32, byte]) =
  set25519(p[0], gf0)
  set25519(p[1], gf1)
  set25519(p[2], gf1)
  set25519(p[3], gf0)
  for i in countdown(255, 0):
    let b = (s[i div 8] shr (i and 7)) and 1'u8
    cswap(p, q, b)
    addPoint(q, p)
    addPoint(p, p)
    cswap(p, q, b)

proc scalarbase(p: var Point, s: array[32, byte]) =
  var q: Point
  set25519(q[0], X)
  set25519(q[1], Y)
  set25519(q[2], gf1)
  fmul(q[3], X, Y)
  scalarmult(p, q, s)

proc unpackneg(r: var Point, p: array[32, byte]): bool =
  ## Decompress a public key into -A (the negation is what verification uses). Returns true
  ## on success; false if the encoding is not a valid curve point.
  var t, chk, num, den, den2, den4, den6: Gf
  set25519(r[2], gf1)
  unpack25519(r[1], p)
  fsqr(num, r[1])
  fmul(den, num, D)
  fsub(num, num, r[2])
  fadd(den, r[2], den)
  fsqr(den2, den)
  fsqr(den4, den2)
  fmul(den6, den4, den2)
  fmul(t, den6, num)
  fmul(t, t, den)
  pow2523(t, t)
  fmul(t, t, num)
  fmul(t, t, den)
  fmul(t, t, den)
  fmul(r[0], t, den)
  fsqr(chk, r[0])
  fmul(chk, chk, den)
  if neq25519(chk, num): fmul(r[0], r[0], I)
  fsqr(chk, r[0])
  fmul(chk, chk, den)
  if neq25519(chk, num): return false
  if par25519(r[0]) == (p[31] shr 7):
    fsub(r[0], gf0, r[0])
  fmul(r[3], r[0], r[1])
  return true

proc modL(r: var array[32, byte], x: var array[64, int64]) =
  var carry: int64
  var i = 63
  while i >= 32:
    carry = 0
    var j = i - 32
    while j < i - 12:
      x[j] += carry - 16 * x[i] * L[j - (i - 32)]
      carry = (x[j] + 128) shr 8
      x[j] -= carry shl 8
      inc j
    x[j] += carry              # j == i-12 after the loop
    x[i] = 0
    dec i
  carry = 0
  for j in 0 .. 31:
    x[j] += carry - (x[31] shr 4) * L[j]
    carry = x[j] shr 8
    x[j] = x[j] and 255
  for j in 0 .. 31:
    x[j] -= carry * L[j]
  for k in 0 .. 31:
    x[k + 1] += x[k] shr 8
    r[k] = byte(x[k] and 255)

proc reduce(h: array[64, byte]): array[32, byte] =
  ## reduce a 64-byte little-endian integer modulo L, into a 32-byte scalar
  var x: array[64, int64]
  for i in 0 .. 63: x[i] = int64(h[i])
  modL(result, x)

proc ed25519Verify*(sig: array[64, byte], msg: openArray[byte],
                    pk: array[32, byte]): bool =
  ## RFC 8032 Ed25519 verification. Returns true iff `sig` is a valid signature over `msg`
  ## under public key `pk`. Detached form (signature separate from the message).
  var q: Point
  if not unpackneg(q, pk):
    return false                      # public key is not a valid curve point
  # h = SHA-512(R || A || M), where R = sig[0:32], A = pk, M = msg
  var buf = newSeq[byte](64 + msg.len)
  for i in 0 .. 31: buf[i] = sig[i]
  for i in 0 .. 31: buf[32 + i] = pk[i]
  for i in 0 ..< msg.len: buf[64 + i] = byte(msg[i])
  let hd = sha512.digest(buf)
  var h: array[64, byte]
  for i in 0 .. 63: h[i] = hd.data[i]
  let s = reduce(h)
  var p: Point
  scalarmult(p, q, s)                 # p = h * (-A)
  var sB: array[32, byte]
  for i in 0 .. 31: sB[i] = sig[32 + i]
  var r2: Point
  scalarbase(r2, sB)                  # r2 = S * B
  addPoint(p, r2)                     # p = S*B - h*A  (== R for a valid signature)
  var t: array[32, byte]
  packPoint(t, p)
  var R: array[32, byte]
  for i in 0 .. 31: R[i] = sig[i]
  ctEq32(t, R)

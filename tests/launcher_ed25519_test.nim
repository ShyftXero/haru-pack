## Standalone check of the vendored launcher Ed25519 verifier against the RFC 8032 §7.1
## test vectors, plus a negative case (a flipped signature byte must NOT verify). Compiled
## and run by tests/test_self_signed.py::test_launcher_ed25519_matches_rfc8032; kept as a
## .nim so the port can be walked in isolation from the footer plumbing.
import std/strutils
import "../src/haru_pack/launcher/ed25519"

proc h(s: string): seq[byte] =
  for i in countup(0, s.len - 2, 2):
    result.add byte(parseHexInt(s[i .. i + 1]))

proc arr32(s: seq[byte]): array[32, byte] =
  for i in 0 .. 31: result[i] = s[i]

proc arr64(s: seq[byte]): array[64, byte] =
  for i in 0 .. 63: result[i] = s[i]

var failures = 0

proc check(name: string, cond: bool) =
  if cond:
    echo "ok   ", name
  else:
    echo "FAIL ", name
    inc failures

# RFC 8032 TEST 1 (empty message)
block:
  let pk = arr32(h"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
  let sig = arr64(h"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
  var msg: seq[byte] = @[]
  check "rfc8032 test1 (empty msg) verifies", ed25519Verify(sig, msg, pk)

# RFC 8032 TEST 2 (1-byte message 0x72)
block:
  let pk = arr32(h"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
  let sig = arr64(h"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
  let msg = @[byte(0x72)]
  check "rfc8032 test2 (1-byte msg) verifies", ed25519Verify(sig, msg, pk)
  # negative: flip one signature byte -> must not verify
  var bad = sig
  bad[0] = bad[0] xor 0x01
  check "rfc8032 test2 flipped-sig REJECTED", not ed25519Verify(bad, msg, pk)
  # negative: wrong message -> must not verify
  check "rfc8032 test2 wrong-msg REJECTED", not ed25519Verify(sig, @[byte(0x73)], pk)

if failures == 0:
  echo "ALL OK"
  quit(0)
else:
  echo failures, " FAILURES"
  quit(1)

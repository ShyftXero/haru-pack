"""INV-CRYPTO-01/02/03 — the encrypted container is what both sides think it is.

The Nim launcher is the only decryptor, so these tests read `cryptbox.nim` as data and
assert the Python writer agrees with it. That is weaker than running the Nim, and it is
stated as such: it catches offset drift, not an implementation bug in either AES-GCM.
`docs/ENCRYPTION_LICENSING.md` previously asserted byte-for-byte interop under a dated
"Verified" heading with nothing behind it at all.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from haru_pack import crypto

NIM_CRYPTBOX = Path(__file__).resolve().parent.parent / "src/haru_pack/launcher/cryptbox.nim"

# The layout crypto.encrypt() writes:
#   0  magic[8] | 8 ver u16 | 10 flags u16 | 12 iters u32 |
#   16 salt[16] | 32 nonce[12] | 44 tag[16] | 60 esecret_len u16 | 62 esecret | ct
OFFSETS = {"flags": 10, "iters": 12, "salt": 16, "nonce": 32, "tag": 44, "esecret_len": 60}

POLICY = dict(expires="2031-07-04", geo=["US", "CA"], machine="MACHINE-ABCDEF",
              user="alice-the-licensee")


@pytest.fixture
def container():
    return crypto.encrypt(b"PK\x03\x04payload-zip-bytes", b"s3cret",
                          expires=POLICY["expires"], geo=POLICY["geo"],
                          machine=POLICY["machine"], user=POLICY["user"])


@pytest.mark.invariant("INV-CRYPTO-01")
def test_policy_is_not_readable_in_the_container(container):
    """A licensee who opens the binary in a hex editor must not find their expiry date."""
    for field in (POLICY["expires"], POLICY["machine"], POLICY["user"], *POLICY["geo"]):
        assert field.encode() not in container, (
            f"license policy field {field!r} is in cleartext — the whole point of putting "
            f"the policy inside the ciphertext is that a reverse-engineer cannot see it"
        )
    assert b"expires" not in container and b"geo" not in container


@pytest.mark.invariant("INV-CRYPTO-01")
def test_policy_is_recoverable_only_after_authenticated_decryption(container):
    """The mirror of the above: the policy is genuinely in there, inside the GCM plaintext.

    This also pins the mechanism. `docs/ENCRYPTION_LICENSING.md` and `cryptbox.nim` both
    claimed the policy was the GCM *AAD*; it is not, and a maintainer "fixing" the code to
    match those comments would have moved the policy into the clear.
    """
    iters = struct.unpack_from("<I", container, OFFSETS["iters"])[0]
    salt = container[16:32]
    nonce = container[32:44]
    tag = container[44:60]
    eslen = struct.unpack_from("<H", container, OFFSETS["esecret_len"])[0]
    ct = container[62 + eslen:]

    key = crypto.derive_key(b"s3cret", salt, iters, POLICY["machine"], POLICY["user"])
    plain = AESGCM(key).decrypt(nonce, ct + tag, crypto.MAGIC)   # AAD is the fixed magic
    plen = struct.unpack_from("<I", plain, 0)[0]
    policy = plain[4:4 + plen]
    for field in (POLICY["expires"], POLICY["machine"], POLICY["user"]):
        assert field.encode() in policy
    assert plain[4 + plen:] == b"PK\x03\x04payload-zip-bytes"


def _open_like_nim(blob: bytes, secret: bytes, machine: str, user: str) -> bytes:
    """Decrypt the way cryptbox.nim does — honouring the flags field when deriving the key.

    Modelling the reader faithfully matters here: a test that ignores `flags` would report
    the flags region as unprotected, and a test that ignores the header entirely would
    report it as protected. Neither is true. See test_header_is_unauthenticated_but_fail_closed.
    """
    flags = struct.unpack_from("<H", blob, OFFSETS["flags"])[0]
    iters = struct.unpack_from("<I", blob, OFFSETS["iters"])[0]
    salt, nonce, tag = blob[16:32], blob[32:44], blob[44:60]
    eslen = struct.unpack_from("<H", blob, OFFSETS["esecret_len"])[0]
    ct = blob[62 + eslen:]
    key = crypto.derive_key(
        secret, salt, iters,
        machine if flags & crypto.BIND_MACHINE else None,
        user if flags & crypto.BIND_USER else None,
    )
    return AESGCM(key).decrypt(nonce, ct + tag, crypto.MAGIC)


@pytest.mark.invariant("INV-CRYPTO-03")
@pytest.mark.parametrize("region,offset", [
    ("flags", 10), ("iters", 12), ("salt", 16), ("nonce", 32),
    ("tag", 44), ("ciphertext", 70),
])
def test_tampering_with_any_region_breaks_the_open(container, region, offset):
    """Flip one bit in each region and require the open to fail. If a region stops being
    covered, only that parametrization goes red — which tells you exactly what regressed."""
    mutated = bytearray(container)
    mutated[offset] ^= 0x01
    with pytest.raises((InvalidTag, ValueError, OverflowError, struct.error)):
        _open_like_nim(bytes(mutated), b"s3cret", POLICY["machine"], POLICY["user"])


@pytest.mark.invariant("INV-CRYPTO-03")
def test_header_is_unauthenticated_but_fail_closed(container):
    """Pin the actual property, which is narrower than "the container is authenticated".

    The AAD is the fixed magic, so `ver`, `flags`, `iters`, `salt`, `nonce` and
    `esecret_len` are NOT covered by the GCM tag. Editing them is not *detected*; it
    changes key derivation and the open fails anyway. That is fail-closed, not
    tamper-evident, and the distinction is the difference between "an attacker cannot
    change this" and "an attacker gains nothing by changing this".

    INV-CRYPTO-04 (proposed) is the fix: put the whole header in the AAD.
    """
    mutated = bytearray(container)
    mutated[OFFSETS["flags"]] ^= crypto.BIND_MACHINE      # clear machine binding

    # the tag still matches its own (unchanged) ciphertext — the header was never covered
    flags = struct.unpack_from("<H", mutated, OFFSETS["flags"])[0]
    assert not flags & crypto.BIND_MACHINE, "precondition: the flag really was flipped"

    # ...but the reader now derives a different key, so the open still fails
    with pytest.raises(InvalidTag):
        _open_like_nim(bytes(mutated), b"s3cret", POLICY["machine"], POLICY["user"])


@pytest.mark.invariant("INV-CRYPTO-03")
def test_wrong_machine_cannot_derive_the_key(container):
    iters = struct.unpack_from("<I", container, OFFSETS["iters"])[0]
    salt, nonce, tag = container[16:32], container[32:44], container[44:60]
    eslen = struct.unpack_from("<H", container, OFFSETS["esecret_len"])[0]
    ct = container[62 + eslen:]
    key = crypto.derive_key(b"s3cret", salt, iters, "SOME-OTHER-MACHINE", POLICY["user"])
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(nonce, ct + tag, crypto.MAGIC)


def _nim_offsets() -> dict[str, int]:
    """Read the offsets cryptbox.nim parses at, straight out of the Nim source."""
    src = NIM_CRYPTBOX.read_text()
    body = src[src.index("proc parseBox"):]
    body = body[:body.index("proc machineId")]
    out = {}
    for name, pat in [
        ("flags", r"result\.flags\s*=\s*rdU16\(b,\s*(\d+)\)"),
        ("iters", r"result\.iters\s*=\s*rdU32\(b,\s*(\d+)\)"),
        ("salt", r"result\.salt\s*=\s*b\[(\d+)\s*\.\.<"),
        ("nonce", r"result\.nonce\s*=\s*b\[(\d+)\s*\.\.<"),
        ("tag", r"result\.tag\s*=\s*b\[(\d+)\s*\.\.<"),
        ("esecret_len", r"rdU16\(b,\s*(\d+)\)\)"),
    ]:
        m = re.search(pat, body)
        assert m, f"could not find the {name} offset in cryptbox.nim parseBox"
        out[name] = int(m.group(1))
    return out


@pytest.mark.invariant("INV-CRYPTO-02")
def test_nim_reader_offsets_match_the_python_writer():
    assert _nim_offsets() == OFFSETS, (
        "the Nim decryptor and the Python encryptor disagree about the container layout. "
        "Every encrypted build produced from this commit would fail at runtime with a "
        "message that reads as 'wrong secret'."
    )


@pytest.mark.invariant("INV-CRYPTO-02")
def test_magic_and_obfuscation_pad_agree_across_implementations():
    src = NIM_CRYPTBOX.read_text()
    nim_magic = re.search(r'Magic\s*=\s*"([^"]+)"', src).group(1)
    nim_obfus = re.search(r'Obfus\s*=\s*"([^"]+)"', src).group(1)
    assert nim_magic.encode() == crypto.MAGIC
    assert nim_obfus.encode() == crypto.OBFUS


@pytest.mark.invariant("INV-CRYPTO-02")
def test_flag_bits_agree_across_implementations():
    src = NIM_CRYPTBOX.read_text()
    got = {name: int(re.search(rf"{name}\s*=\s*(\d+)'u16", src).group(1))
           for name in ("BindMachine", "BindUser", "EmbedSecret")}
    assert got == {"BindMachine": crypto.BIND_MACHINE,
                   "BindUser": crypto.BIND_USER,
                   "EmbedSecret": crypto.EMBED_SECRET}

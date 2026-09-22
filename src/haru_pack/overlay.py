from __future__ import annotations
import hashlib, struct
from pathlib import Path

MAGIC = b"HARUPACK"   # 8B start sentinel (matches launcher/overlay.nim FooterMagic)
TAIL  = b"KCAPURAH"   # 8B end sentinel   (FooterTail)
FOOTER_V1_SIZE = 8 + 2 + 2 + 8 + 8 + 32 + 8               # = 68  (payload only)
FOOTER_V2_SIZE = 8 + 2 + 2 + 8 + 8 + 32 + 8 + 8 + 32 + 8  # = 116 (payload + stub locator)
# v3 = v2 + a signature tail: an Ed25519 public key (32) + signature (64), placed OUTSIDE
# the signed bytes and BEFORE the TAIL, so the backward scan locates it by the same MAGIC.
FOOTER_V3_SIZE = FOOTER_V2_SIZE + 32 + 64                 # = 212 (v2 + pubkey + signature)
FOOTER_SIZE = FOOTER_V1_SIZE                              # back-compat alias (v1)

# The signed region of a v2/v3 footer: everything BETWEEN the MAGIC and the TAIL that is
# structural or a digest — formatVer, flags, payloadOff, payloadLen, payloadSha, stubOff,
# stubLen, stubSha. That is footer[8:108], 100 bytes. --self-signed signs exactly these
# bytes; the pubkey + signature that follow are deliberately NOT covered (a signature cannot
# authenticate itself). Because formatVer is inside the signed region, the signature also
# binds the format version.
_SIGNED_OFF, _SIGNED_END = 8, 108        # footer[8:108]
_PUBKEY_OFF, _PUBKEY_END = 108, 140      # footer[108:140]
_SIG_OFF, _SIG_END = 140, 204            # footer[140:204]

# Footer flag bits — MUST match launcher/overlay.nim FooterFlag* constants.
FOOTER_FLAG_ENCRYPTED = 1   # bit0: payload is an encrypted container (crypto.MAGIC)
FOOTER_FLAG_REMOTE = 2      # bit1: payload is fetched at runtime, not appended (Phase 3)

_FOOTER_SIZES = {1: FOOTER_V1_SIZE, 2: FOOTER_V2_SIZE, 3: FOOTER_V3_SIZE}


def _stub_footer(flags: int, off: int, paylen: int, paysha: bytes,
                 stub_off: int, stub_len: int, stub_sha: bytes, sign_key) -> tuple:
    """Build a stub-carrying footer (v2, or v3 when `sign_key` is given) and return
    (footer_bytes, extra_dict). The signed region is byte-identical between v2 and v3 apart
    from the format-version field, so the launcher's v2 reader and v3 reader share offsets.

    `sign_key` is a cryptography Ed25519 private key or None. When given, the footer is v3:
    the 100-byte signed region (with format_ver=3) is signed, and the public key + signature
    are appended after it, ahead of the TAIL — outside the signed bytes on purpose."""
    ver = 3 if sign_key is not None else 2
    signed = (struct.pack("<HHQQ", ver, flags, off, paylen) + paysha
              + struct.pack("<QQ", stub_off, stub_len) + stub_sha)
    assert len(signed) == _SIGNED_END - _SIGNED_OFF, len(signed)
    if sign_key is None:
        footer = MAGIC + signed + TAIL
        assert len(footer) == FOOTER_V2_SIZE, len(footer)
        return footer, {"format_ver": 2}
    pub = sign_key.public_key().public_bytes_raw()
    sig = sign_key.sign(signed)                     # Ed25519 is deterministic (RFC 8032)
    assert len(pub) == 32 and len(sig) == 64
    footer = MAGIC + signed + pub + sig + TAIL
    assert len(footer) == FOOTER_V3_SIZE, len(footer)
    return footer, {"format_ver": 3, "self_signed": True,
                    "pubkey": pub.hex(),
                    "pubkey_sha256": hashlib.sha256(pub).hexdigest()}


def attach(launcher: Path, payload: bytes, out: Path, flags: int = 0,
           stub_config: bytes | None = None, remote: bool = False, sign_key=None) -> dict:
    """Append `payload` (+ optional cleartext `stub_config`) + a versioned footer to the
    launcher PE/ELF. Run BEFORE signing: an Authenticode cert table appended afterward sits
    past the footer, which the launcher relocates by scanning backward for MAGIC.

    `stub_config=None` emits a v1 (68B) footer, byte-identical to the single-payload format
    every existing build and v1 test corpus loads. Passing bytes emits a v2 (116B) footer
    and lays the file out as [launcher][payload][stub-config][footer], the stub-config
    covered by the signature and located only by the footer (docs/adr/0003 §1).

    `remote=True` (Phase 3 remote-fetch, INV-REMOTE-01) records the payload DIGEST as the
    trust anchor but embeds NO payload bytes: the file is laid out [launcher][stub-config]
    [footer] with payload_len=0 and the remote flag bit set. The caller hosts `payload` at the
    stub-config's source_url; the launcher fetches it and verifies it against this digest, so
    the byte SOURCE is the only difference from an appended build. A remote build MUST carry a
    stub-config (it holds source_url).

    `sign_key` (a cryptography Ed25519 private key, or None) turns a stub-carrying build into a
    v3 --self-signed binary: the footer's structural + digest fields are signed and the public
    key + signature ride in a new footer tail (see `_stub_footer`). Signing REQUIRES a
    stub-config, because the signed region includes the stub locator; a v1 (no-stub) build
    cannot be self-signed. HONEST LIMIT: the public key is embedded in the same file, so this
    detects post-build edits by anyone who does not ALSO rewrite the key — it is not
    tamper-evidence unless the fingerprint is pinned out of band (docs/SIGNING.md)."""
    if sign_key is not None and stub_config is None:
        raise ValueError("--self-signed requires a stub-config: the signature covers the "
                         "stub locator, so a v1 (single-payload) footer cannot be signed")
    stub = Path(launcher).read_bytes()
    off = len(stub)
    paysha = hashlib.sha256(payload).digest()
    if remote:
        if stub_config is None:
            raise ValueError("remote build requires a stub_config (it carries source_url)")
        flags |= FOOTER_FLAG_REMOTE
        stub_off = off                     # stub-config right after the launcher; no payload between
        stub_sha = hashlib.sha256(stub_config).digest()
        footer, extra = _stub_footer(flags, off, 0, paysha, stub_off, len(stub_config),
                                     stub_sha, sign_key)
        Path(out).write_bytes(stub + stub_config + footer)
        info = {"remote": True, "payload_off": off, "payload_len": 0,
                "sha256": paysha.hex(), "stub_off": stub_off, "stub_len": len(stub_config),
                "stub_sha256": stub_sha.hex()}
        info.update(extra)
        return info
    if stub_config is None:
        footer = MAGIC + struct.pack("<HHQQ", 1, flags, off, len(payload)) + paysha + TAIL
        assert len(footer) == FOOTER_V1_SIZE, len(footer)
        Path(out).write_bytes(stub + payload + footer)
        return {"format_ver": 1, "payload_off": off, "payload_len": len(payload),
                "sha256": paysha.hex()}
    stub_off = off + len(payload)          # stub-config immediately after the payload
    stub_sha = hashlib.sha256(stub_config).digest()
    footer, extra = _stub_footer(flags, off, len(payload), paysha, stub_off, len(stub_config),
                                 stub_sha, sign_key)
    Path(out).write_bytes(stub + payload + stub_config + footer)
    info = {"payload_off": off, "payload_len": len(payload),
            "sha256": paysha.hex(), "stub_off": stub_off, "stub_len": len(stub_config),
            "stub_sha256": stub_sha.hex()}
    info.update(extra)
    return info


def verify(exe: Path) -> dict:
    """Locate the footer by backward scan (survives an appended signature), dispatch on
    format_ver, and confirm the payload (and, for v2, the stub-config) sha256 still match."""
    data = Path(exe).read_bytes()
    i = data.rfind(MAGIC)
    if i == -1:
        raise ValueError("no haru-pack footer found")
    ver = struct.unpack_from("<H", data, i + 8)[0]
    size = _FOOTER_SIZES.get(ver)
    if size is None:
        raise ValueError(f"unsupported footer version {ver}")
    footer = data[i:i + size]
    if len(footer) != size or footer[size - 8:size] != TAIL:
        raise ValueError("footer tail sentinel mismatch")
    _, flags, off, ln = struct.unpack("<HHQQ", footer[8:28])
    paysha = footer[28:60]
    payload = data[off:off + ln]
    out = {"footer_at": i, "format_ver": ver, "flags": flags,
           "payload_off": off, "payload_len": ln,
           "sha_ok": hashlib.sha256(payload).digest() == paysha,
           "bytes_after_footer": len(data) - (i + size)}
    if ver in (2, 3):
        stub_off, stub_len = struct.unpack("<QQ", footer[60:76])
        stub_sha = footer[76:108]
        stub = data[stub_off:stub_off + stub_len]
        out.update({"stub_off": stub_off, "stub_len": stub_len,
                    "stub_ok": hashlib.sha256(stub).digest() == stub_sha,
                    "stub_config": stub.decode("utf-8", "replace")})
    if ver == 3:
        # v3 --self-signed: verify the Ed25519 signature over the footer's signed region
        # against the EMBEDDED public key. sig_ok=True means "these structural+digest fields
        # were signed by whoever's key is embedded here" — NOT that the key is trusted. That
        # is the documented honest limit (INV-SIGN-01); pin pubkey_sha256 out of band for it
        # to mean anything about provenance.
        signed = footer[_SIGNED_OFF:_SIGNED_END]
        pub = footer[_PUBKEY_OFF:_PUBKEY_END]
        sig = footer[_SIG_OFF:_SIG_END]
        out.update({"self_signed": True, "pubkey": pub.hex(),
                    "pubkey_sha256": hashlib.sha256(pub).hexdigest(),
                    "sig_ok": _ed25519_verify(pub, sig, signed)})
    return out


def _ed25519_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """True iff `sig` is a valid Ed25519 signature over `msg` under raw public key `pub`.
    Imported lazily so a caller that only builds v1/v2 binaries pays nothing for it."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False

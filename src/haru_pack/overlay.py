from __future__ import annotations
import hashlib, struct
from pathlib import Path

MAGIC = b"HARUPACK"   # 8B start sentinel (matches launcher/overlay.nim FooterMagic)
TAIL  = b"KCAPURAH"   # 8B end sentinel   (FooterTail)
FOOTER_V1_SIZE = 8 + 2 + 2 + 8 + 8 + 32 + 8               # = 68  (payload only)
FOOTER_V2_SIZE = 8 + 2 + 2 + 8 + 8 + 32 + 8 + 8 + 32 + 8  # = 116 (payload + stub locator)
FOOTER_SIZE = FOOTER_V1_SIZE                              # back-compat alias (v1)

_FOOTER_SIZES = {1: FOOTER_V1_SIZE, 2: FOOTER_V2_SIZE}


def attach(launcher: Path, payload: bytes, out: Path, flags: int = 0,
           stub_config: bytes | None = None) -> dict:
    """Append `payload` (+ optional cleartext `stub_config`) + a versioned footer to the
    launcher PE/ELF. Run BEFORE signing: an Authenticode cert table appended afterward sits
    past the footer, which the launcher relocates by scanning backward for MAGIC.

    `stub_config=None` emits a v1 (68B) footer, byte-identical to the single-payload format
    every existing build and v1 test corpus loads. Passing bytes emits a v2 (116B) footer
    and lays the file out as [launcher][payload][stub-config][footer], the stub-config
    covered by the signature and located only by the footer (docs/adr/0003 §1)."""
    stub = Path(launcher).read_bytes()
    off = len(stub)
    paysha = hashlib.sha256(payload).digest()
    if stub_config is None:
        footer = MAGIC + struct.pack("<HHQQ", 1, flags, off, len(payload)) + paysha + TAIL
        assert len(footer) == FOOTER_V1_SIZE, len(footer)
        Path(out).write_bytes(stub + payload + footer)
        return {"format_ver": 1, "payload_off": off, "payload_len": len(payload),
                "sha256": paysha.hex()}
    stub_off = off + len(payload)          # stub-config immediately after the payload
    stub_sha = hashlib.sha256(stub_config).digest()
    footer = (MAGIC + struct.pack("<HHQQ", 2, flags, off, len(payload)) + paysha
              + struct.pack("<QQ", stub_off, len(stub_config)) + stub_sha + TAIL)
    assert len(footer) == FOOTER_V2_SIZE, len(footer)
    Path(out).write_bytes(stub + payload + stub_config + footer)
    return {"format_ver": 2, "payload_off": off, "payload_len": len(payload),
            "sha256": paysha.hex(), "stub_off": stub_off, "stub_len": len(stub_config),
            "stub_sha256": stub_sha.hex()}


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
    if ver == 2:
        stub_off, stub_len = struct.unpack("<QQ", footer[60:76])
        stub_sha = footer[76:108]
        stub = data[stub_off:stub_off + stub_len]
        out.update({"stub_off": stub_off, "stub_len": stub_len,
                    "stub_ok": hashlib.sha256(stub).digest() == stub_sha,
                    "stub_config": stub.decode("utf-8", "replace")})
    return out

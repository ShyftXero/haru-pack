from __future__ import annotations
import hashlib, struct
from pathlib import Path

MAGIC = b"HARUPACK"   # 8B start sentinel (matches launcher/overlay.nim FooterMagic)
TAIL  = b"KCAPURAH"   # 8B end sentinel   (FooterTail)
FOOTER_SIZE = 8 + 2 + 2 + 8 + 8 + 32 + 8   # = 68

def attach(launcher: Path, payload: bytes, out: Path, flags: int = 0) -> dict:
    """Append `payload` + a fixed footer to the launcher PE/ELF. Run BEFORE signing:
    an Authenticode cert table appended afterward sits past the footer, which the
    launcher relocates by scanning backward for MAGIC."""
    stub = Path(launcher).read_bytes()
    off = len(stub)
    sha = hashlib.sha256(payload).digest()
    footer = MAGIC + struct.pack("<HHQQ", 1, flags, off, len(payload)) + sha + TAIL
    assert len(footer) == FOOTER_SIZE, len(footer)
    Path(out).write_bytes(stub + payload + footer)
    return {"payload_off": off, "payload_len": len(payload), "sha256": sha.hex()}

def verify(exe: Path) -> dict:
    """Locate the footer by backward scan (survives an appended signature) and
    confirm the payload sha256 still matches."""
    data = Path(exe).read_bytes()
    i = data.rfind(MAGIC)
    if i == -1:
        raise ValueError("no haru-pack footer found")
    footer = data[i:i + FOOTER_SIZE]
    if footer[60:68] != TAIL:
        raise ValueError("footer tail sentinel mismatch")
    ver, flags, off, ln = struct.unpack("<HHQQ", footer[8:28])
    sha = footer[28:60]
    payload = data[off:off + ln]
    ok = hashlib.sha256(payload).digest() == sha
    return {"footer_at": i, "format_ver": ver, "flags": flags,
            "payload_off": off, "payload_len": ln, "sha_ok": ok,
            "bytes_after_footer": len(data) - (i + FOOTER_SIZE)}

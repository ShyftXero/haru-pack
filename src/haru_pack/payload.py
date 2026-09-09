from __future__ import annotations
import io, zipfile
from . import tomlio
from pathlib import Path

def build_payload_zip(payload_dir: Path) -> bytes:
    payload_dir = Path(payload_dir)
    mf = payload_dir / "manifest.toml"
    if not mf.exists():
        raise FileNotFoundError(f"manifest.toml missing in {payload_dir}")
    tomlio.load(mf)  # validate TOML early
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(payload_dir.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(payload_dir).as_posix())
    return buf.getvalue()

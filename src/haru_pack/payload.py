from __future__ import annotations
import io, json, zipfile
from pathlib import Path

def build_payload_zip(payload_dir: Path) -> bytes:
    payload_dir = Path(payload_dir)
    mf = payload_dir / "manifest.json"
    if not mf.exists():
        raise FileNotFoundError(f"manifest.json missing in {payload_dir}")
    json.loads(mf.read_text())  # validate JSON early
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(payload_dir.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(payload_dir).as_posix())
    return buf.getvalue()

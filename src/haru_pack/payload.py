from __future__ import annotations
import io, shutil, time, zipfile
from . import tomlio
from pathlib import Path

# The zip/DOS date format cannot encode a year before 1980. Real payloads carry files that
# predate it — an sdist shipped with mtime 0 (1970), a vendored artifact with a zeroed
# timestamp — and `ZipFile.write`, which reads each file's mtime, then dies with
# "ZIP does not support timestamps before 1980" and fails the whole build. Clamp such
# timestamps to the epoch instead; a packaging tool must not refuse to package a file because
# it has an old date.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

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
                arc = p.relative_to(payload_dir).as_posix()
                st = p.stat()
                # Build the ZipInfo by hand: ZipInfo.from_file raises in its OWN constructor on a
                # pre-1980 mtime, so there is no chance to clamp it afterwards — clamp the date
                # BEFORE constructing, and carry the mode across ourselves (the exec bit matters:
                # a payload's vendored uv/python must stay executable).
                dt = time.localtime(st.st_mtime)[:6]
                if dt < _ZIP_EPOCH:
                    dt = _ZIP_EPOCH
                zi = zipfile.ZipInfo(arc, date_time=dt)
                zi.external_attr = (st.st_mode & 0xFFFF) << 16
                zi.compress_type = zipfile.ZIP_DEFLATED
                with p.open("rb") as src, z.open(zi, "w") as dst:
                    shutil.copyfileobj(src, dst)
    return buf.getvalue()

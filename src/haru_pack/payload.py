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

LINKS_NAME = ".haru-links"
"""Where the payload records file symlinks it stored once instead of N times.

Format: one `<link>\\t<target>` per line, both payload-relative POSIX paths, sorted. The
launcher materialises these between `extractAll` and `recordTree` (`stage.materialiseLinks`)
so the staged tree is byte-identical to one built before this existed, and is deleted before
the tree is recorded.
"""


def _dedupe_target(p: Path, root: Path) -> str | None:
    """Payload-relative target of `p` if it is a file symlink pointing inside `root`.

    `None` means "store this the way it has always been stored", which is the answer for a
    directory symlink, a dangling one, and one escaping the payload. Only the case we can
    reproduce exactly at stage time is deduplicated; everything else keeps the old
    behaviour rather than trading bytes for a shape the launcher cannot rebuild.
    """
    if not p.is_symlink() or not p.is_file():       # is_file() follows: also excludes dangling
        return None
    try:
        target = p.resolve(strict=True)
        return target.relative_to(root).as_posix()
    except (OSError, ValueError, RuntimeError):     # unresolvable, outside root, or a cycle
        return None


def build_payload_zip(payload_dir: Path) -> bytes:
    """Zip the staged payload, storing each file symlink's bytes once.

    python-build-standalone ships `bin/python` and `bin/python3` as symlinks to
    `python3.13`, and `libpython3.13.so` as one to `libpython3.13.so.1.0`. `Path.is_file()`
    follows symlinks and `ZipFile.write` reads through them, so those five names used to
    store five full copies of two files: 34.3 MB of an 84.5 MB thick payload, because
    DEFLATE compresses each member independently and cannot dedupe across them.
    """
    payload_dir = Path(payload_dir)
    mf = payload_dir / "manifest.toml"
    if not mf.exists():
        raise FileNotFoundError(f"manifest.toml missing in {payload_dir}")
    tomlio.load(mf)  # validate TOML early
    root = payload_dir.resolve()
    links: list[tuple[str, str]] = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(payload_dir.rglob("*")):
            rel = p.relative_to(payload_dir).as_posix()
            if rel == LINKS_NAME:
                raise ValueError(
                    f"payload contains a file named {LINKS_NAME}, which haru-pack reserves "
                    "for its own link table")
            target = _dedupe_target(p, root)
            if target is not None:
                links.append((rel, target))
                continue
            if p.is_file():
                st = p.stat()
                # Build the ZipInfo by hand: ZipInfo.from_file raises in its OWN constructor on a
                # pre-1980 mtime, so there is no chance to clamp it afterwards — clamp the date
                # BEFORE constructing, and carry the mode across ourselves (the exec bit matters:
                # a payload's vendored uv/python must stay executable).
                dt = time.localtime(st.st_mtime)[:6]
                if dt < _ZIP_EPOCH:
                    dt = _ZIP_EPOCH
                zi = zipfile.ZipInfo(rel, date_time=dt)
                zi.external_attr = (st.st_mode & 0xFFFF) << 16
                zi.compress_type = zipfile.ZIP_DEFLATED
                with p.open("rb") as src, z.open(zi, "w") as dst:
                    shutil.copyfileobj(src, dst)
        if links:
            links.sort()
            z.writestr(LINKS_NAME, "".join(f"{a}\t{b}\n" for a, b in links))
    return buf.getvalue()

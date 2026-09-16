"""The payload stores a file symlink's bytes once, not once per name.

python-build-standalone ships `bin/python` and `bin/python3` as symlinks to `python3.13`,
and `libpython3.13.so` as one to `libpython3.13.so.1.0`. `Path.is_file()` follows symlinks
and `ZipFile.write` reads through them, so five names used to mean five full copies of two
files — measured at 34.3 MB of an 84.5 MB thick payload, because DEFLATE compresses each
member independently and cannot dedupe across them.

What is deliberately NOT deduplicated is anything the launcher cannot rebuild exactly:
a directory symlink, a dangling one, one escaping the payload. Those keep the old
behaviour rather than trading bytes for a shape `stage.materialiseLinks` would have to
guess at.
"""
from __future__ import annotations

import io
import os
import zipfile

import pytest

from haru_pack.payload import LINKS_NAME, build_payload_zip

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="POSIX symlink semantics; Windows payloads carry no symlinks"
)

BODY = b"\x7fELF" + b"payload-bytes" * 5000


def _payload(tmp_path):
    d = tmp_path / "payload"
    (d / "vendor" / "python" / "bin").mkdir(parents=True)
    (d / "manifest.toml").write_text('name = "x"\n')
    return d


def _members(blob):
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        return {i.filename: i for i in z.infolist()}


def _links(blob):
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        if LINKS_NAME not in z.namelist():
            return {}
        rows = z.read(LINKS_NAME).decode().splitlines()
    return dict(line.split("\t", 1) for line in rows if line)


@pytest.mark.invariant("INV-PAYLOAD-06")
def test_a_file_symlink_is_stored_once_and_listed(tmp_path):
    d = _payload(tmp_path)
    real = d / "vendor" / "python" / "bin" / "python3.13"
    real.write_bytes(BODY)
    os.symlink("python3.13", d / "vendor" / "python" / "bin" / "python")
    os.symlink("python3.13", d / "vendor" / "python" / "bin" / "python3")

    blob = build_payload_zip(d)
    names = _members(blob)

    assert "vendor/python/bin/python3.13" in names
    assert "vendor/python/bin/python" not in names
    assert "vendor/python/bin/python3" not in names
    assert _links(blob) == {
        "vendor/python/bin/python": "vendor/python/bin/python3.13",
        "vendor/python/bin/python3": "vendor/python/bin/python3.13",
    }


@pytest.mark.invariant("INV-PAYLOAD-06")
def test_the_bytes_are_actually_saved(tmp_path):
    """The point is the size, so measure the size rather than the member list."""
    d = _payload(tmp_path)
    bin_dir = d / "vendor" / "python" / "bin"
    (bin_dir / "python3.13").write_bytes(BODY)
    deduped_names = build_payload_zip(d)

    os.symlink("python3.13", bin_dir / "python")
    os.symlink("python3.13", bin_dir / "python3")
    with_links = build_payload_zip(d)

    # Two extra names cost the link table, not two extra copies of the body.
    assert len(with_links) - len(deduped_names) < len(BODY) // 4

    stored = sum(
        i.compress_size
        for n, i in _members(with_links).items()
        if n.endswith("python3.13")
    )
    assert stored == sum(
        i.compress_size
        for n, i in _members(deduped_names).items()
        if n.endswith("python3.13")
    )


@pytest.mark.invariant("INV-PAYLOAD-06")
def test_a_symlink_escaping_the_payload_keeps_the_old_behaviour(tmp_path):
    outside = tmp_path / "outside.bin"
    outside.write_bytes(BODY)
    d = _payload(tmp_path)
    os.symlink(outside, d / "vendor" / "escapee")

    blob = build_payload_zip(d)
    assert "vendor/escapee" in _members(blob)   # content copied in, as before
    assert _links(blob) == {}


def test_a_dangling_symlink_is_not_listed(tmp_path):
    d = _payload(tmp_path)
    os.symlink("nowhere", d / "vendor" / "broken")
    blob = build_payload_zip(d)
    assert _links(blob) == {}
    assert "vendor/broken" not in _members(blob)


def test_a_directory_symlink_is_not_listed(tmp_path):
    d = _payload(tmp_path)
    (d / "real-dir").mkdir()
    (d / "real-dir" / "f.txt").write_bytes(b"hello")
    os.symlink("real-dir", d / "alias-dir")

    blob = build_payload_zip(d)
    assert _links(blob) == {}
    assert "real-dir/f.txt" in _members(blob)


def test_the_link_table_name_is_reserved(tmp_path):
    d = _payload(tmp_path)
    (d / LINKS_NAME).write_text("not yours\n")
    with pytest.raises(ValueError, match="reserves"):
        build_payload_zip(d)


def test_a_payload_with_no_symlinks_has_no_link_table(tmp_path):
    d = _payload(tmp_path)
    (d / "vendor" / "plain").write_bytes(BODY)
    assert LINKS_NAME not in _members(build_payload_zip(d))

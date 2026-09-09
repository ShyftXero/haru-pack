"""Archive extraction that cannot write outside the destination directory.

INV-SUPPLY-03. Every tar we open came off the network without a digest check
(INV-SUPPLY-01 is still `proposed`), so the extractor is the only thing standing
between a tampered release asset and the build host's filesystem.

`tarfile.extractall(filter="data")` is the right answer, but it only exists on
3.12+ and the backports (3.9.17+, 3.10.12+, 3.11.4+). This project declares
`requires-python = ">=3.9"`, so we verify support at runtime and fall back to an
explicit member check rather than silently extracting unfiltered.
"""
from __future__ import annotations

import tarfile
from pathlib import Path

__all__ = ["safe_extract_tar"]


def _is_within(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def _reject_unsafe_members(tf: tarfile.TarFile, dest: Path) -> None:
    for member in tf.getmembers():
        if member.issym() or member.islnk():
            link = (dest / member.name).parent / member.linkname
            if not _is_within(dest, link):
                raise ValueError(f"unsafe link in archive: {member.name} -> {member.linkname}")
        if not _is_within(dest, dest / member.name):
            raise ValueError(f"unsafe path in archive: {member.name}")
        if member.isdev():
            raise ValueError(f"device node in archive: {member.name}")


def safe_extract_tar(archive: Path | str, dest: Path | str) -> None:
    """Extract `archive` into `dest`, refusing any member that escapes it."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tf:
        if hasattr(tarfile, "data_filter"):
            tf.extractall(dest, filter="data")
        else:                                   # pre-backport 3.9/3.10/3.11
            _reject_unsafe_members(tf, dest)
            tf.extractall(dest)

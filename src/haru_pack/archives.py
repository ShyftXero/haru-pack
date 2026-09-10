"""Fetching and extracting third-party archives.

Two invariants live in this module.

**INV-SUPPLY-01** — every artifact haru-pack downloads and then executes is checked
against a digest pinned *in this repository* before it is extracted. `fetch_verified`
is the only download entry point the rest of the package may use, and it refuses to
fetch an artifact it has no pin for rather than falling back to "TLS said it was
fine". TLS authenticates a host, not a file: it says nothing about a mutable release
asset, a compromised publisher account, or a mirror.

**INV-SUPPLY-03** — no extraction may write outside the destination directory.
`tarfile.extractall(filter="data")` is the right answer, but it only exists on 3.12+
and the backports (3.9.17+, 3.10.12+, 3.11.4+). This project declares
`requires-python = ">=3.9"`, so we verify support at runtime and fall back to an
explicit member check rather than silently extracting unfiltered.
"""
from __future__ import annotations

import hashlib, os, tarfile, urllib.request
from pathlib import Path

__all__ = [
    "safe_extract_tar", "sha256_file", "verify_sha256", "fetch_verified",
    "DigestMismatch", "UnpinnedArtifact",
]

_HEXDIGITS = frozenset("0123456789abcdef")


class DigestMismatch(RuntimeError):
    """A downloaded artifact did not hash to the digest this repo pinned."""


class UnpinnedArtifact(RuntimeError):
    """We were asked to fetch/use an artifact for which no digest is pinned.

    Raised instead of downloading. A missing pin is a gap to be filled with a real
    digest from the publisher, never by relaxing the check.
    """


# ---------- digests (INV-SUPPLY-01) ----------
def sha256_file(path: Path | str, _chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_chunk), b""):
            h.update(block)
    return h.hexdigest()


def require_pin(expected: str | None, what: str) -> str:
    """Normalize a pinned digest, or refuse. Never returns a placeholder."""
    if not expected or not isinstance(expected, str):
        raise UnpinnedArtifact(
            f"no pinned sha256 for {what}; refusing to download or use it. "
            "Add the publisher's digest to the pin table — do not remove this check.")
    e = expected.strip().lower()
    if len(e) != 64 or not set(e) <= _HEXDIGITS:
        raise UnpinnedArtifact(f"pinned digest for {what} is not a sha256 hex digest: {expected!r}")
    return e


def verify_sha256(path: Path | str, expected: str | None, what: str = "artifact") -> str:
    """Hash `path` and compare against the pinned digest. Raises on any mismatch."""
    e = require_pin(expected, what)
    actual = sha256_file(path)
    if actual != e:
        raise DigestMismatch(
            f"digest mismatch for {what}\n"
            f"  expected {e}\n"
            f"  actual   {actual}\n"
            "The bytes we received are not the bytes this repo pinned; refusing to use them.")
    return actual


def fetch_verified(url: str, dest: Path | str, expected_sha256: str | None,
                   what: str | None = None) -> Path:
    """Download `url` to `dest` and verify it before any caller can touch it.

    A missing pin fails *before* the network call. A mismatching artifact is deleted,
    so a later step cannot pick it up off disk.
    """
    what = what or url
    expected = require_pin(expected_sha256, what)       # refuse before touching the network
    dest = Path(dest)
    urllib.request.urlretrieve(url, dest)
    try:
        verify_sha256(dest, expected, what=what)
    except BaseException:
        try:
            os.unlink(dest)
        except OSError:
            pass
        raise
    return dest


# ---------- extraction (INV-SUPPLY-03) ----------
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

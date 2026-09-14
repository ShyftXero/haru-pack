"""Where the launcher is allowed to stage, and where it may fetch its payload from.

Both checks here are build-time refusals whose whole purpose is to fail before a binary
exists (docs/PRINCIPLES.md: a build-time refusal beats a runtime failure). The launcher
re-refuses the same shapes at runtime against the TARGET's real roots, so neither half
trusts the other.

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import os
import re as _re

from pathlib import Path

from ..overlay import attach
from .errors import BuildError


# ── base_path safety (docs/adr/0004 §5, INV-BASE-01) ──────────────────────────────────────
# A staging root that is a filesystem/drive/UNC root or a home-directory root is refused. The
# launcher creates AND (with --reap) deletes a create-and-delete-own subtree beneath this
# root, so the root must never be a place whose pollution or deletion would be catastrophic.
# The build refuses the obvious shapes here (fail fast, cross-OS aware — a --target windows
# build on Linux must still reject `C:\`); the launcher re-refuses defensively at runtime,
# where the target's real "/" and $HOME are knowable (refuseUnsafeRoot in stage.nim).
_DRIVE_ROOT_RE = _re.compile(r"[A-Za-z]:[\\/]?\Z")     # C:  C:\  C:/
_FS_ROOT_RE = _re.compile(r"[\\/]+\Z")                 # /  \  //  \\  (posix root / UNC-ish)


def _is_root_like(path: str) -> bool:
    p = path.rstrip("/\\") or path            # keep a lone "/" as "/"
    if p in ("/", "\\"):
        return True
    if _FS_ROOT_RE.fullmatch(path):           # bare separators only -> a root
        return True
    if _DRIVE_ROOT_RE.fullmatch(path):        # Windows drive root, any build OS
        return True
    home = os.path.expanduser("~")
    return bool(home and home != "~" and os.path.normpath(p) == os.path.normpath(home))


def resolve_base_path(base_path: str) -> str:
    """Validate the --base-path staging root (docs/adr/0004 §3/§5). '' means 'normal cache'
    (the default, no refusal). A non-empty value that is empty-after-strip, a filesystem/drive/
    UNC root, or the build host's home root is REFUSED at build time (INV-BASE-01). The value
    is stored verbatim in the cleartext stub-config; the launcher applies the same refusal
    against the TARGET's real roots at runtime."""
    if not base_path:
        return ""
    if not base_path.strip():
        raise BuildError("--base-path is blank. Omit it for the normal per-user cache, or "
                         "give a real staging directory.")
    if _is_root_like(base_path):
        raise BuildError(
            f"--base-path {base_path!r} resolves to a filesystem, drive, or home-directory "
            f"root. The launcher stages AND (with --reap) deletes a subtree under this path, "
            f"so it must be a dedicated directory, never a root (docs/adr/0004 §5).")
    return base_path


def resolve_source_url(source_url: str) -> str:
    """Validate the Phase-3 remote-fetch URL (docs/adr/0005, INV-REMOTE-01). "" = appended
    delivery (the default). This is a build-time sanity check to catch a typo, NOT a security
    boundary: the launcher does not trust the URL at all — it fetches from it and verifies the
    bytes against the build-baked footer digest, so a hostile URL can only cause a fail-closed
    refusal. We require an http/https scheme (the launcher's puppy HTTP client speaks those)
    and a non-empty host, and reject leading/trailing whitespace that would smuggle into TOML."""
    if not source_url:
        return ""
    if source_url != source_url.strip():
        raise BuildError("--source-url has leading or trailing whitespace.")
    lo = source_url.lower()
    if not (lo.startswith("http://") or lo.startswith("https://")):
        raise BuildError(
            f"--source-url {source_url!r} must be an http:// or https:// URL — the launcher "
            f"fetches the payload over HTTP (and verifies it against the baked digest). "
            f"Host the payload sidecar this build writes at that URL.")
    rest = source_url.split("://", 1)[1]
    host = rest.split("/", 1)[0]
    if not host:
        raise BuildError(f"--source-url {source_url!r} has no host.")
    return source_url


def _attach_payload(*, launcher: Path, payload: bytes, out: Path, flags: int,
                    sc_bytes: bytes, source_url: str, say) -> dict:
    """Write the finished binary — either with the payload appended, or with a sidecar."""
    if not source_url:
        return attach(launcher, payload, out, flags=flags, stub_config=sc_bytes)
    # Phase 3 remote-fetch (INV-REMOTE-01): the payload is NOT embedded. attach records
    # its digest as the trust anchor and sets the remote flag; we write the exact
    # container bytes to a sidecar the packager hosts at source_url. The binary carries
    # only [launcher][stub-config][footer].
    info = attach(launcher, payload, out, flags=flags, stub_config=sc_bytes, remote=True)
    sidecar = out.with_name(out.name + ".haru-payload")
    sidecar.write_bytes(payload)
    info["source_url"] = source_url
    info["payload_sidecar"] = str(sidecar)
    say(f"--source-url: remote-fetch delivery. The binary carries NO payload — host these "
        f"exact bytes at {source_url}:\n  {sidecar}\n  ({len(payload)} bytes, sha256 "
        f"{info['sha256']}). The launcher fetches the URL and refuses any bytes whose "
        f"sha256 is not exactly that digest (INV-REMOTE-01), so a mirror or CDN must "
        f"serve these bytes unchanged.")
    return info

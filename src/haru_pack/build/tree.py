"""Copying the project into the payload, and measuring what the launcher will stage.

The exclusion list is the interesting part of this module. A payload is appended to a
binary that gets distributed, and often signed — anything credential-shaped that lands in
it is published. Build directories routinely sit next to a working `.env`, so exclusion is
the DEFAULT, not the operator's job (INV-PAYLOAD-01).

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Behaviour unchanged.
"""
from __future__ import annotations

import shutil
from pathlib import Path

# INV-PAYLOAD-01: a payload is appended to a binary that gets distributed, and often
# signed. Anything credential-shaped that lands in it is published. Build directories
# routinely sit next to a working .env, so exclusion is the default, not the operator's job.
_SECRET_PATTERNS = ("*.env", ".env", ".env.*", ".envrc", ".direnv",
                    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
                    "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
                    ".ssh", ".aws", ".gnupg", ".netrc", "_netrc",
                    "credentials", "credentials.*", "secrets.*", "*.secret",
                    ".npmrc", ".pypirc", "service-account*.json")

_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".venv", "venv", "*.egg-info",
                                 "dist", "build", ".git", "haru_pack.toml", ".mypy_cache",
                                 ".pytest_cache", ".ruff_cache", "*.exe",
                                 *_SECRET_PATTERNS)


def copy_app_tree(source: Path, app: Path) -> None:
    """Copy the project (or the single script) into the payload's app directory."""
    if source.is_file():
        app.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, app / source.name)
    else:
        shutil.copytree(source, app, ignore=_IGNORE)


def target_is_host(tgt) -> bool:
    """Cache warming runs the TARGET's interpreter, so it only works building for this box.

    Cross-compiled thick builds use warm_cache_windows, which resolves wheels for the
    target platform without executing them.
    """
    return tgt.is_host


def _staged_tree_bytes(payload_dir: Path) -> int:
    """Size of the tree the launcher will STAGE, for the RAM-fit check (docs/adr/0007,
    INV-EPHEMERAL-01).

    Not `du` of the payload dir: `uv` ships XZ-compressed (`uv.xz`, ~14 MB) and the launcher
    EXPANDS it on stage (~56 MB) via `expandCompressedMembers`. Summing the compressed bytes
    would under-count by ~40 MB and could hand the RAM gate a "fits" verdict for a tree that
    then OOMs the small box the gate exists to protect (adversarial review C1). So for every
    `.xz` member the build wrote a `.xz.size` sidecar for (see `bundle.compress_uv`), count the
    EXPANDED size, and drop the `.xz` and its metadata sidecars from the count entirely — they
    are removed before the launcher records the tree. The result is the staged tree's real size;
    the launcher applies the ×1.2 headroom on top (INV-EPHEMERAL-01)."""
    total = 0
    for p in payload_dir.rglob("*"):
        if not p.is_file():
            continue
        name = p.name
        if name.endswith((".xz.size", ".xz.sha256")):
            continue                        # metadata sidecars, not part of the staged tree
        if name.endswith(".xz"):
            sidecar = p.with_name(name + ".size")
            if sidecar.exists():
                try:
                    total += int(sidecar.read_text().strip())   # EXPANDED size
                    continue
                except ValueError:
                    pass
            # Sidecar missing OR present-but-unparseable (the `except ValueError` above): either
            # way the launcher's own expandCompressedMembers refuses to stage this member at all
            # (StageError: "no .size sidecar" / "unreadable size sidecar"), so a build that ships
            # this tree unchanged would never actually reach the RAM-fit check with it. Count the
            # compressed size as the best available fallback for THIS estimate; it does not change
            # what the launcher will do at runtime.
            total += p.stat().st_size
            continue
        total += p.stat().st_size
    return total

"""Copying the project into the payload, and measuring what the launcher will stage.

The exclusion list is the interesting part of this module. A payload is appended to a
binary that gets distributed, and often signed — anything credential-shaped that lands in
it is published. Build directories routinely sit next to a working `.env`, so exclusion is
the DEFAULT, not the operator's job (INV-PAYLOAD-01).

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Behaviour unchanged.
"""
from __future__ import annotations

import shutil
import subprocess
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

# Excluded at ANY depth — never legitimate project source wherever it appears, and (for the
# credential patterns, INV-PAYLOAD-01) excluded even when git-TRACKED: a tracked `.env` must
# never ship regardless of where it sits in the tree.
_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".git", "*.exe", "haru_pack.toml",
                                 "*.egg-info", ".mypy_cache", ".pytest_cache", ".ruff_cache",
                                 *_SECRET_PATTERNS)

# Excluded ONLY at the project root: build/env artifact directories whose names also occur as
# legitimate source subpackages. `src/haru_pack/build/` is a package — a bare "build" pattern
# matched at ANY depth silently dropped it, shipping a binary that died with
# `ModuleNotFoundError: No module named 'haru_pack.build'`. Anchoring to the root keeps a
# project's top-level build output out while letting nested source through. (`.venv` is also
# .gitignored, but `build`/`dist` are not, so the denylist — not only the .gitignore layer —
# has to cover them.)
_ROOT_ONLY = {"dist", "build", ".venv", "venv"}


def _git_ignored(source: Path) -> set[Path]:
    """Absolute paths git considers ignored under `source` (whole ignored dirs collapsed to
    the dir). Empty when `source` is not a git work tree or git is unavailable — so a non-git
    project's behaviour is exactly the old denylist-only one.

    This is what stops a dev box's gitignored-but-present junk from being published: a 759 MB
    `.claude/` of agent worktrees, a `.busybody/` run dir, an `emit/` toolchain cache. None of
    it is project source; all of it is already in `.gitignore`; none of it belonged in a 15 MB
    payload that shipped at 438 MB because the exclusion list was a fixed denylist that never
    heard of those directories.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(source), "ls-files", "--others", "--ignored",
             "--exclude-standard", "--directory", "-z"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if out.returncode != 0:
        return set()
    ignored: set[Path] = set()
    for rel in out.stdout.split("\0"):
        rel = rel.rstrip("/")
        if rel:
            ignored.add(source / rel)
    return ignored


def copy_app_tree(source: Path, app: Path) -> None:
    """Copy the project (or the single script) into the payload's app directory.

    Three exclusion layers:
      * `_IGNORE` — the always-on any-depth denylist: credential patterns (INV-PAYLOAD-01),
        `__pycache__`, `.git`, caches. Applied even to git-TRACKED files, because a tracked
        `.env` must never ship regardless of what `.gitignore` says.
      * `_ROOT_ONLY` — `build`/`dist`/`.venv`/`venv`, excluded only at the project root, so a
        top-level build dir goes but the `src/haru_pack/build/` source package stays.
      * `.gitignore` — anything the project already ignores (a dev's `.venv`, `.claude/`
        agent worktrees, `.busybody/` run dirs, generated caches). Not project source, and
        the cause of a payload ballooning from ~15 MB to hundreds of MB. Honoured only when
        `source` is a git work tree; a non-git project falls back to the denylist alone.
    """
    if source.is_file():
        app.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, app / source.name)
        return
    ignored = _git_ignored(source)
    src_resolved = source.resolve()

    def _ignore(directory: str, names: list[str]) -> set[str]:
        skip = set(_IGNORE(directory, names))
        base = Path(directory)
        if base.resolve() == src_resolved:                  # root-only build/env artifacts
            skip.update(n for n in names if n in _ROOT_ONLY)
        if ignored:
            skip.update(n for n in names if base / n in ignored)
        return skip

    shutil.copytree(source, app, ignore=_ignore)


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

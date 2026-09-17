"""Single source of truth for the haru-pack version.

A git-commit-derived, PEP 440-valid build id: ``YYYYMMDDHHMMSS[+g<shorthash>]`` — the HEAD commit's
committer date (UTC) plus, in a checkout, its abbreviated hash. The 14-digit timestamp says *which*
build and its order ("the one from today, before or after lunch?"); the hash maps it to an exact
commit. Adopted from lotek's ``src/app/_version.py`` (kept close so the two can be diffed), with one
deliberate difference for haru-pack — see ``git_build_id``'s ``with_hash``.

Resolution order, so every runtime context gets a sensible value:
  1. a git checkout (dev) -> computed live from HEAD, WITH the ``+g<hash>`` (so a developer can see
     exactly which commit they are running);
  2. an installed wheel (no ``.git``) -> the version baked at build time by ``hatch_build.py``
     (importlib.metadata), which is the BARE 14-digit timestamp;
  3. neither -> ``0+unknown``.

Surfaced at runtime by ``haru-pack version`` (``cli/inspectcmd.py``). ``pyproject.toml`` computes the
version at build time via the hatchling metadata hook in ``hatch_build.py`` (so wheel metadata / ``uv``
agree) — but the wheel gets the BARE form, because **PyPI refuses PEP 440 local versions** (the
``+g<hash>`` segment) on upload. lotek can carry the hash in its published version because lotek is
deploy-only and never uploads to PyPI; haru-pack does, so its releases are the bare timestamp and the
tag (``scripts/cut-release.sh``) is ``vYYYYMMDDHHMMSS`` with no hash.
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path

# src/haru_pack/_version.py -> the repo root is two parents up; that's where the .git checkout lives.
_REPO_ROOT = Path(__file__).resolve().parents[2]


def format_build_id(epoch: int, short_hash: str | None = None) -> str:
    """**The** build-id formatter — every producer routes through this one function.

    ``epoch`` is the commit's committer date as UTC seconds; ``short_hash`` its abbreviated hash (omit
    it, or pass ``None``, for the bare form that goes to PyPI). Returns ``YYYYMMDDHHMMSS[+g<hash>]``.

    **One 14-digit segment, deliberately — not ``YYYY.M.D.HHMMSS`` and not ``YYYY.MM.DD.HHMMSS``.**
    A dotted form is not lexicographically sortable unless every component is fixed-width, and
    zero-padding does NOT fix it: PEP 440 normalisation *strips leading zeros*, so
    ``2026.09.16.083708`` parses back to ``2026.9.16.83708`` and the tag would stop matching the
    version the running tool reports. A single 14-digit segment sidesteps that entirely: the year's
    first digit is never ``0``, so there is no leading zero to strip, the width is constant, and
    lexicographic order == PEP 440 order == chronological order. (This is why the requested "leading
    zeros" survive: they are inside one integer segment, not dot-separated components.)
    """
    t = time.gmtime(epoch)
    stamp = (
        f"{t.tm_year:04d}{t.tm_mon:02d}{t.tm_mday:02d}"
        f"{t.tm_hour:02d}{t.tm_min:02d}{t.tm_sec:02d}"
    )
    return f"{stamp}+g{short_hash}" if short_hash else stamp


def git_build_id(root: Path, *, with_hash: bool = True) -> str | None:
    """PEP 440 build id from the HEAD commit at ``root``.

    With ``with_hash`` (the default) returns ``YYYYMMDDHHMMSS+g<shorthash>``; with ``with_hash=False``
    returns the bare ``YYYYMMDDHHMMSS`` — the form that goes into wheel metadata and the release tag,
    because PyPI rejects the local ``+g<hash>`` segment on upload. Returns ``None`` when ``root`` is
    not a git checkout or git is unavailable. ``%ct`` (epoch) avoids a datetime dependency;
    ``time.gmtime`` gives the UTC parts.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "show", "-s", "--format=%ct %h", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    parts = out.stdout.split()
    if len(parts) != 2 or not parts[0].isdigit():
        return None
    return format_build_id(int(parts[0]), parts[1] if with_hash else None)


def read_frozen(pkg_dir: Path | None = None) -> str | None:
    """A build-time-frozen version, for a source tree with no `.git`.

    A haru-pack binary's payload carries the project source but NOT `.git` (INV-PAYLOAD /
    tree.py excludes it), so `git_build_id` can't recompute the version on the target and the
    binary would otherwise report `0+unknown`. `scripts/self-build.sh` writes
    `_frozen_version.py` next to this file just before packing; it ships in the payload (and,
    kept as a `.py`, in the wheel's `**/*.py` include) and is absent in a normal checkout.
    """
    d = pkg_dir or Path(__file__).parent
    f = d / "_frozen_version.py"
    if not f.exists():
        return None
    for line in f.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith("VERSION"):
            _, _, val = s.partition("=")
            return val.strip().strip('"').strip("'") or None
    return None


def _resolve_version() -> str:
    from_git = git_build_id(_REPO_ROOT)
    if from_git:
        return from_git
    frozen = read_frozen()               # a packed binary's payload: no .git, but a frozen version
    if frozen:
        return frozen
    try:  # an installed wheel has no .git — read the version baked at build time (see hatch_build.py)
        from importlib.metadata import PackageNotFoundError, version
        try:
            return version("haru-pack")
        except PackageNotFoundError:
            pass
    except Exception:
        pass
    return "0+unknown"


__version__ = _resolve_version()

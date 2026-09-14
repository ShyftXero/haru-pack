"""Phase 2b — move what survived the rules out of the payload.

Files go to a QUARANTINE directory, never to `unlink`. The verify phase has to be able to
tell the difference between "this was pruned" and "this was never here", and an operator
debugging a field failure should be able to look at what was taken.

Split out of shake.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import fnmatch
import re
import shutil
from pathlib import Path

from .config import (_CACHE_DROP_PREFIXES, _CACHE_KEEP_PREFIXES, _PY_DROP_ALWAYS,
                     _PY_DROP_UNLESS_OBSERVED)
from .index import _always_keep


def _quarantine(src: Path, root: Path, qroot: Path) -> int:
    """Move one file out of the payload, preserving its path under the quarantine root."""
    rel = src.relative_to(root)
    dest = qroot / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    n = src.stat().st_size if not src.is_symlink() else 0
    shutil.move(str(src), str(dest))
    return n


def _prune_cache_buckets(cache_dir: Path, qroot: Path, log=None) -> tuple:
    say = log or (lambda _m: None)
    dropped, freed = [], 0
    for d in sorted(cache_dir.iterdir()) if cache_dir.is_dir() else []:
        if not d.is_dir():
            continue
        if d.name.startswith(_CACHE_KEEP_PREFIXES):
            continue
        if not d.name.startswith(_CACHE_DROP_PREFIXES):
            say(f"shake: keeping unrecognised uv cache bucket {d.name!r} "
                f"(no rule says it is safe to drop)")
            continue
        for f in sorted(p for p in d.rglob("*") if p.is_file()):
            freed += _quarantine(f, cache_dir.parent.parent, qroot)
            dropped.append(f)
        shutil.rmtree(d, ignore_errors=True)
    return dropped, freed


def _prune_interpreter(pydir: Path, payload: Path, qroot: Path, observed: set,
                       keep_globs, log=None) -> tuple:
    """Apply the static rulepack to the bundled standalone Python."""
    say = log or (lambda _m: None)
    obs_blob = "\n".join(sorted(observed))
    globs = list(_PY_DROP_ALWAYS)
    for feature, pats in _PY_DROP_UNLESS_OBSERVED.items():
        if not pats:
            continue
        if re.search(rf"/{re.escape(feature)}(/|\.py|\b)", obs_blob):
            say(f"shake: keeping {feature} — the observation run used it")
            continue
        globs += list(pats)
    dropped, freed = [], 0
    for f in sorted(p for p in pydir.rglob("*") if p.is_file()):
        rel = f.relative_to(pydir).as_posix()
        cands = _suffixes(rel)
        if any(fnmatch.fnmatch(c, g) for c in cands for g in keep_globs):
            continue
        if any(fnmatch.fnmatch(c, g) for c in cands for g in globs):
            freed += _quarantine(f, payload, qroot)
            dropped.append(f)
    return dropped, freed


def _suffixes(rel: str) -> list:
    """Every path-component suffix of `rel`, so a rule can be written prefix-free.

    python-build-standalone's archive extracts to a `python/` directory, and some layouts
    add an `install/` level under that, so the interpreter actually lands at
    `vendor/python/python/lib/python3.12/...`. The first version of the rulepack matched
    against the full relative path and therefore matched NOTHING — the interpreter came
    through a `--shake` untouched and the saving was silently zero. Rules are written
    against the prefix that is stable (`lib/python*/test/*`) and matched against every
    suffix, so a new upstream layout cannot quietly disable them.
    """
    parts = rel.split("/")
    return ["/".join(parts[i:]) for i in range(len(parts))]


def _prune_dependencies(archives: list, payload: Path, qroot: Path, keep: set,
                        runtime: set, keep_globs, own: str = "", log=None) -> tuple:
    say = log or (lambda _m: None)
    dropped, freed = [], 0
    per_dist = {}
    # Relpaths pruned from dists that ARE in the runtime resolution. Only these have to
    # stay missing from the verification env (INV-SHAKE-02): a dev-only tree is dropped
    # *because* it is the measuring device, and the verify step installs the test tooling
    # back on purpose, so including those paths made the absence check fire on every real
    # project. Found on the first end-to-end run, 2026-09-10 — 491 false positives, all of
    # them `_pytest/**`.
    runtime_dropped: set = set()
    for a in archives:
        whole = bool(a.dist) and a.dist not in runtime
        if whole:
            say(f"shake: {a.dist} {a.version} is not in the runtime resolution "
                f"(dev-only) — dropping the whole tree")
        if own and a.dist == own:
            # The project's OWN code is never file-pruned. It is small, it is the part the
            # operator wrote, and it is the part whose untested branches they are most
            # likely to know about and least likely to expect a packager to delete. The
            # size in a thick payload is in the dependencies and the interpreter, so
            # exempting it costs nothing worth having.
            say(f"shake: keeping all of {a.dist} — the project's own code is not pruned")
            per_dist[a.dist] = {"kept": len(a.files()), "dropped": 0, "dropped_bytes": 0}
            continue
        for f in a.files():
            rel = f.relative_to(a.root).as_posix()
            st = per_dist.setdefault(a.dist or a.root.name,
                                     {"kept": 0, "dropped": 0, "dropped_bytes": 0})
            if not whole and (rel in keep or _always_keep(rel, keep_globs)):
                st["kept"] += 1
                continue
            n = _quarantine(f, payload, qroot)
            freed += n
            st["dropped"] += 1
            st["dropped_bytes"] += n
            dropped.append(f)
            if not whole:
                runtime_dropped.add(rel)
    return dropped, freed, per_dist, runtime_dropped

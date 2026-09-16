"""`--shake` — drop payload files the project's own test suite proves it never touches.

The idea, and the reason it is not just "delete what looks unused": a `--thick` payload
carries an entire dependency closure because that is what the tier promises, but a closure
resolved by a *resolver* is much larger than the set of files a *program* opens. Torch is
the canonical case — the wheel is gigabytes of CUDA kernels and a CPU-only inference app
dlopens none of them. Docker's `slim` makes the same bet for container images, and makes it
the same way: **observe** a real execution, keep what was touched, verify the result still
works. It does not read the code and reason about it.

So this package is three phases, and the third is not optional. Each has a module:

    config    what --shake was told to do; ShakeError; ShakeConfig
    observe   1. run the suite under a file-access tracer and record every path opened
    index     2a. what is in the payload, and what must be kept whatever the tracer saw
    prune     2b. move the rest to a QUARANTINE directory — never to `unlink`
    verify    3. rebuild from the pruned cache, offline, and re-run the suite against it

`shake()` below is the only thing that runs all three, in that order. It stays here, in the
package root, because the ORDER is the invariant: a caller must not be able to observe and
prune without verifying (INV-SHAKE-01), and the way to make that impossible is to give them
one function rather than three.

What this deliberately does NOT claim: that a passing test suite proves runtime safety. A
suite that never exercises a code path is evidence about the suite, not about the program.
`--shake` is opt-in for that reason, it refuses to run without a declared test command
(INV-SHAKE-03), and it writes down every file it removed so an operator debugging a field
failure has something better than a bisect.

Split out of a single 536-statement shake.py 2026-09-13 (INV-MODULARITY-01). The names
below are the ones that module exported, so no caller and no test had to change.
"""
from __future__ import annotations

import json
from pathlib import Path

from .config import ShakeConfig, ShakeError, resolve_config
from .index import (Archive, _index_archives, _lazy_import_closure, _module_index,
                    _observed_relpaths, _project_name, _retain_package_inits,
                    _runtime_dists)
from .observe import _install_audit_hook, _observe, _parse_strace
from .prune import _prune_cache_buckets, _prune_dependencies, _prune_interpreter
from .verify import _resurrected, _verify

__all__ = [
    "Archive", "ShakeConfig", "ShakeError",
    "manifest_summary", "resolve_config", "shake", "write_report",
    # Underscored, but named directly by tests that exercise one phase in isolation or
    # neutralize it to walk a Red-path. Imported here (rather than reached through a
    # submodule) so `monkeypatch.setattr(shake, "_verify", ...)` still reaches the
    # reference `shake()` actually calls.
    "_index_archives", "_install_audit_hook", "_lazy_import_closure", "_module_index",
    "_observe", "_observed_relpaths", "_parse_strace", "_project_name",
    "_prune_dependencies", "_prune_interpreter", "_resurrected", "_retain_package_inits",
    "_runtime_dists", "_verify",
]


def shake(payload: Path, app_dir: Path, cache_dir: Path, py: Path, obs_env: Path,
          cfg: ShakeConfig, workdir: Path, sources=None, log=None) -> dict:
    """Observe, prune, verify. Returns the report; raises ShakeError rather than shipping."""
    say = log or (lambda _m: None)
    qroot = workdir / "shake-quarantine"
    qroot.mkdir(parents=True, exist_ok=True)
    before = _tree_bytes(payload)

    runtime = _runtime_dists(app_dir)
    archives = _index_archives(cache_dir)
    if not archives:
        raise ShakeError(
            f"--shake found no unpacked wheel trees in {cache_dir} to shake. A thick build "
            "warms `vendor/cache` from the project's lockfile; if that did not happen there "
            "is nothing to prune and the flag is a no-op, which haru-pack reports rather "
            "than passing off as a saving.")

    observed, runs, tracer = _observe(cfg, obs_env, app_dir, py, log=say)
    keep = _observed_relpaths(observed, obs_env)
    index = _module_index(archives)
    say(f"shake: {len(observed)} path(s) traced, {len(keep)} inside the dependency trees")
    if cfg.follow_lazy_imports:
        keep = _lazy_import_closure(keep, index, log=say)
    keep = _retain_package_inits(keep, index)

    dep_dropped, dep_freed, per_dist, dropped_rel = _prune_dependencies(
        archives, payload, qroot, keep, runtime, cfg.keep,
        own=_project_name(app_dir), log=say)
    bucket_dropped, bucket_freed = _prune_cache_buckets(cache_dir, qroot, log=say)
    py_dropped, py_freed = ([], 0)
    if cfg.shake_interpreter:
        pydir = payload / "vendor" / "python"
        if pydir.is_dir():
            py_dropped, py_freed = _prune_interpreter(pydir, payload, qroot, observed,
                                                      cfg.keep, log=say)

    freed = dep_freed + bucket_freed + py_freed
    say(f"shake: pruned {len(dep_dropped) + len(bucket_dropped) + len(py_dropped)} file(s), "
        f"{freed / 1e6:.1f} MB uncompressed — verifying")

    verify = _verify(app_dir, cache_dir, py, cfg, workdir, dropped_rel,
                     sources=sources, log=say)

    after = _tree_bytes(payload)
    return {
        "tracer": tracer,
        "observation": {"runs": runs, "paths_traced": len(observed)},
        "verification": verify,
        "payload_bytes_before": before,
        "payload_bytes_after": after,
        "freed_bytes": freed,
        "dropped_files": len(dep_dropped) + len(bucket_dropped) + len(py_dropped),
        "dropped": {
            "dependencies": {"files": len(dep_dropped), "bytes": dep_freed},
            "uv_cache_buckets": {"files": len(bucket_dropped), "bytes": bucket_freed},
            "interpreter": {"files": len(py_dropped), "bytes": py_freed},
        },
        "per_dist": per_dist,
        "kept_globs": list(cfg.keep),
        "quarantine": str(qroot),
        "dropped_paths": sorted(p.relative_to(payload).as_posix()
                                for p in [*dep_dropped, *bucket_dropped, *py_dropped]
                                if _is_within(p, payload)),
    }


def _is_within(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root); return True
    except ValueError:
        return False


def _tree_bytes(root: Path) -> int:
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file())


def write_report(report: dict, out: Path) -> Path:
    """Drop the receipt next to the binary.

    An operator debugging "it works here and ImportErrors on the customer's box" needs the
    list of files this build removed, and needs it without rebuilding. The summary also
    goes into the payload manifest, but the full path list would bloat every launcher, so
    it lives here.
    """
    dest = Path(str(out) + ".shake.json")
    dest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return dest


def manifest_summary(report: dict) -> dict:
    """The part of the report small enough to ship inside the payload."""
    return {
        "shaken": True,
        "tracer": report["tracer"],
        "dropped_files": report["dropped_files"],
        "freed_bytes": report["freed_bytes"],
        "verified": all(r["exit"] == 0 for r in report["verification"]["runs"]),
    }

"""Phase 3 — rebuild from the PRUNED cache, offline, and re-run the suite against it.

Not optional, and not something a caller can decline: it lives inside `shake()`. The
failure mode of guessing wrong is an `ImportError` on a customer machine at first run,
which is the worst possible place to find out (INV-SHAKE-01).

Split out of shake.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from .config import ShakeConfig, ShakeError
from .observe import _site_packages


def _verify(app_dir: Path, cache_dir: Path, py: Path, cfg: ShakeConfig, workdir: Path,
            dropped_rel: set, sources=None, log=None) -> dict:
    """Rebuild the runtime env from the PRUNED cache, offline, then re-run the suite.

    Two things are being proven, and the second is the one that is easy to get wrong:

    1. The pruned cache still installs offline — the same `uv sync` the launcher does on
       the target, with `UV_OFFLINE=1` and the bundled interpreter.
    2. The suite passes *against a tree that really is missing the pruned files*. The test
       tooling is installed from the BUILD HOST's cache afterwards (network allowed; it is
       build-time only, and it must not come from the payload since we just deleted it from
       there). A dev dependency that pins a different version of a runtime dist can make uv
       reinstall it — unpruned — and the suite would then pass against files the customer
       will not have. So the pruned paths are re-checked for absence before the suite runs
       (INV-SHAKE-02). A false green here is worse than no verification at all: it converts
       "we did not check" into "we checked and it was fine".
    """
    say = log or (lambda _m: None)
    venv = workdir / "shake-verify"
    shutil.rmtree(venv, ignore_errors=True)
    base = dict(os.environ, NO_COLOR="1", UV_PYTHON_DOWNLOADS="never")
    off = dict(base, UV_CACHE_DIR=str(cache_dir), UV_OFFLINE="1",
               UV_PROJECT_ENVIRONMENT=str(venv), UV_PYTHON=str(py))
    r = subprocess.run(["uv", "sync", "--project", str(app_dir), "--frozen", "--no-dev"],
                       env=off, capture_output=True, text=True)
    if r.returncode != 0:
        raise ShakeError(
            "the shaken payload no longer installs offline — `uv sync --frozen --no-dev` "
            "failed against the pruned cache, which is exactly what the target does on "
            f"first run:\n\n{(r.stderr or r.stdout)[-1500:]}\n\n"
            "Nothing was shipped. A uv cache bucket this build needs is being dropped; "
            "report it, and build without --shake meanwhile.")

    vpy = _env_python(venv)
    # Test tooling, from OUTSIDE the payload. `--inexact`-style: pip install leaves the
    # already-satisfied runtime dists alone, which is what the absence check below confirms.
    dev = subprocess.run(["uv", "export", "--project", str(app_dir), "--only-dev",
                          "--no-hashes", "--no-header", "--no-emit-project",
                          "--format", "requirements-txt"],
                         env=base, capture_output=True, text=True)
    reqs = [ln.strip() for ln in dev.stdout.splitlines()
            if ln.strip() and not ln.strip().startswith(("#", "-"))]
    if reqs:
        rf = workdir / "shake-dev-reqs.txt"
        rf.write_text("\n".join(reqs) + "\n")
        idx = list(sources.uv_index_args()) if sources is not None else []
        r = subprocess.run(["uv", "pip", "install", "--python", str(vpy), *idx,
                            "-r", str(rf)], env=base, capture_output=True, text=True)
        if r.returncode != 0:
            raise ShakeError("could not install the project's dev dependencies into the "
                             "shake verification env (build-time only, network allowed):\n"
                             + (r.stderr or r.stdout)[-1200:])

    resurrected = _resurrected(venv, dropped_rel)
    if resurrected:
        raise ShakeError(
            f"{len(resurrected)} pruned file(s) came back into the verification env, so "
            "verifying against it would prove nothing about the shipped payload "
            "(INV-SHAKE-02). This happens when a dev dependency pulls a different version "
            "of a runtime dist and uv reinstalls it whole.\n  "
            + "\n  ".join(sorted(resurrected)[:8])
            + "\n\nNothing was shipped. Pin the dev group to the runtime versions, or "
              "build without --shake.")

    bindir = venv / ("Scripts" if sys.platform == "win32" else "bin")
    results = []
    for cmd in [list(cfg.test), *[list(c) for c in cfg.also_run]]:
        env = dict(base, VIRTUAL_ENV=str(venv),
                   PATH=str(bindir) + os.pathsep + base.get("PATH", ""))
        env.pop("PYTHONHOME", None)
        say(f"shake: verifying with `{' '.join(cmd)}` against the pruned payload")
        r = subprocess.run(cmd, cwd=str(app_dir), env=env, capture_output=True, text=True)
        results.append({"command": cmd, "exit": r.returncode})
        if r.returncode != 0:
            raise ShakeError(
                f"the suite FAILED against the shaken payload (`{' '.join(cmd)}` exited "
                f"{r.returncode}). Nothing was shipped.\n\n"
                f"{(r.stdout or r.stderr or '')[-2000:]}\n\n"
                "Something the program needs was observed as unused. Keep it explicitly:\n"
                "    haru-pack build ... --shake --shake-keep 'pkg/thefile.so'\n"
                "or in haru_pack.toml:\n"
                "    [shake]\n    keep = [\"pkg/thefile.so\"]")
    return {"env": str(venv), "runs": results}


def _env_python(venv: Path) -> Path:
    for c in (venv / "bin" / "python", venv / "bin" / "python3",
              venv / "Scripts" / "python.exe"):
        if c.exists():
            return c
    raise ShakeError(f"no interpreter in the verification env {venv}")


def _resurrected(venv: Path, dropped_rel: set) -> set:
    sps = _site_packages(venv)
    return {rel for rel in dropped_rel for sp in sps if (sp / rel).exists()}

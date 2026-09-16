"""The `--thick` tier's staging: bundle an interpreter, warm the cache, run bundle steps.

thick's contract is "download NOTHING, fully offline" (docs/TIERS.md), and everything here
exists to make that literally true on a machine that has never seen the binary before —
including a PEP 723 script's inline dependencies, which were silently NOT staged until
2026-09-09 (INV-TIER-01).

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Behaviour unchanged.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from .. import shake as shake_mod
from ..bundle import (bundle_python, bundle_uv, install_dev_tools, run_bundle_step,
                      run_bundle_steps_wine, warm_cache_and_lock, warm_cache_for_script,
                      warm_cache_windows)
from ..entrypoints import verify_console_script
from . import slim as slim_mod
from .errors import BuildError
from .tree import target_is_host


def _warm_on_host(*, payload: Path, app_dir: Path, cache: Path, py, steps, manifest: dict,
                  sources, log, shake: bool, shake_keep, shake_report, workdir: Path, tgt) -> None:
    """Resolve and stage the project's dependencies using the BUNDLED interpreter.

    Everything happens against a throwaway env (`tmp_env`) rather than the project's own
    `.venv`, and that is load-bearing for `--shake`: the throwaway env was built by uv FROM
    THE BUNDLED CACHE with the BUNDLED interpreter, so every path the tracer sees maps onto
    a file that is actually in the payload. Observing a project's `.venv` would trace a
    different resolution against a different Python and produce a keep set for a payload
    that does not exist.
    """
    tmp_env = Path(tempfile.mkdtemp(prefix="haru-warm-"))
    uv_dir = Path(tempfile.mkdtemp(prefix="haru-warmuv-"))
    try:
        # Warm with the PINNED uv (the one the binary bundles and runs), not the build host's
        # `uv` on PATH. uv keys its cache buckets by its own schema version, so a cache warmed by
        # a different host uv is unreadable to the bundled uv at offline run time — the deps are
        # present but the run can't resolve them (#53). For a host target the pinned uv is this
        # arch, so it runs here. It goes in its OWN temp dir, never inside `tmp_env` — that is
        # `UV_PROJECT_ENVIRONMENT`, and a stray subdir there makes `uv sync` refuse it.
        uv_bin = str(bundle_uv(tgt, uv_dir, sources=sources))
        warm_cache_and_lock(app_dir, py, cache, tmp_env, sources=sources, uv_bin=uv_bin)
        # The bundled cache above is runtime-only (INV-PAYLOAD-03). Dev tools
        # go into the throwaway env only, so a [[bundle]] step or a --shake
        # observation can still run them without the payload carrying them.
        if steps or shake:
            install_dev_tools(app_dir, tmp_env, sources=sources, log=log)
        # At thick there IS an environment, so a console-script entrypoint can
        # be checked for certain instead of warned about (INV-BUILD-08). This
        # is the strongest form of the check and the only one that can see a
        # script provided by a dependency rather than by the project.
        ep_argv = manifest.get("entrypoint") or []
        if len(ep_argv) == 1 and not ep_argv[0].endswith(".py"):
            level, msg = verify_console_script(ep_argv[0], app_dir, env_dir=tmp_env)
            if level == "error":
                raise BuildError(msg)
        for step in steps:
            run_bundle_step(step, payload, tmp_env, app_dir)
        if shake:
            cfg = shake_mod.resolve_config(
                app_dir, {"shake": manifest.get("shake_declared") or {}},
                cli_keep=shake_keep)
            rep = shake_mod.shake(payload, app_dir, cache, py, tmp_env, cfg,
                                  workdir, sources=sources, log=log)
            if shake_report is not None:
                shake_report.update(rep)
            manifest.update(shake_mod.manifest_summary(rep))
    finally:
        shutil.rmtree(tmp_env, ignore_errors=True)
        shutil.rmtree(uv_dir, ignore_errors=True)


def _stage_script_dependencies(*, manifest: dict, vendor: Path, source: Path, py, tgt,
                               sources, log) -> None:
    """Stage a PEP 723 script's inline dependencies into the payload.

    A script's dependencies live in its inline metadata, and until 2026-09-09 nothing staged
    them: `kind == "project"` got its cache warmed and `kind == "script"` did not, so
    `--thick` produced a binary that still hit the network on first run. The tier's contract
    is "download NOTHING", so at thick this is not optional and not silent (INV-TIER-01).
    """
    if manifest.get("kind") != "script" or not target_is_host(tgt):
        return
    deps = manifest.get("script_dependencies") or []
    if not deps:
        return
    cache = vendor / "cache"; cache.mkdir(parents=True, exist_ok=True)
    say = log or (lambda _m: None)
    say(f"staging {len(deps)} script dependency/ies into the payload: "
        + ", ".join(deps[:6]) + (" …" if len(deps) > 6 else ""))
    # Warm with the PINNED uv, not the host's — same reason as the project path (#53).
    warm_uv = Path(tempfile.mkdtemp(prefix="haru-scriptuv-"))
    try:
        uv_bin = str(bundle_uv(tgt, warm_uv, sources=sources))
        warm_cache_for_script(Path(source), py, cache, sources=sources, uv_bin=uv_bin)
    finally:
        shutil.rmtree(warm_uv, ignore_errors=True)
    manifest["cache_dir"] = "vendor/cache"


def stage(*, payload: Path, vendor: Path, manifest: dict, source: Path, tgt, python: str,
          wine: bool, sources, log, shake: bool, shake_keep, shake_report,
          workdir: Path, slim: bool = False, slim_report: dict | None = None) -> None:
    """Everything `--thick` adds to a payload, in order."""
    steps = manifest.get("bundle") or []
    if steps and not tgt.is_host and not wine:
        raise BuildError(
            f"bundle steps run target-native code and can't be produced for --target "
            f"{tgt} from here. Re-run with --wine, build --thick on a {tgt} machine, or "
            f"fetch by URL.")
    py = bundle_python(tgt, vendor, version=python, sources=sources)
    # ORDER IS THE INVARIANT (INV-SHAKE-05): the interpreter is fetched and digest-verified
    # by `bundle_python` (INV-SUPPLY-01) BEFORE `--slim-python` removes a single file, so the
    # provenance chain is "verified PBS artifact, then these N files removed by us". Moving
    # this above `bundle_python` prunes an unverified tree — do not.
    slim_rep = slim_mod.maybe_slim(vendor / "python", payload, slim=slim, log=log)
    if slim_report is not None and slim_rep:
        slim_report.update(slim_rep)
    if manifest.get("kind") == "project" or steps:
        app_dir = payload / manifest["app_subdir"]
        cache = vendor / "cache"; cache.mkdir(parents=True, exist_ok=True)
        if tgt.is_host:
            _warm_on_host(payload=payload, app_dir=app_dir, cache=cache, py=py, steps=steps,
                          manifest=manifest, sources=sources, log=log, shake=shake,
                          shake_keep=shake_keep, shake_report=shake_report, workdir=workdir,
                          tgt=tgt)
        else:
            warm_cache_windows(app_dir, cache, python, sources=sources)
            if steps and wine:
                run_bundle_steps_wine(steps, payload, py, app_dir)
        manifest["cache_dir"] = "vendor/cache"
    _stage_script_dependencies(manifest=manifest, vendor=vendor, source=source, py=py,
                               tgt=tgt, sources=sources, log=log)

"""Building the binaries the cases attack, and measuring what one costs.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from busybody_config import ADDRESS_SPACE_MB  # noqa: E402

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "src") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "src"))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from haru_pack import overlay  # noqa: E402,F401

import busybody_config as cfg  # noqa: E402
from busybody_config import (FATAL, MARKER, case, fixture_source)  # noqa: E402,F401
from busybody_runner import (Ctx, InfraFailure, blame, classify, clean_env,  # noqa: E402,F401
                             dir_bytes, infra_failure_reason, run_exe, stage_root,
                             warm, work_root_report)

# ================================================================ fixture + driver

APP = '''# /// script
# requires-python = ">=3.12"
# ///
import sys
print("BUSYBODY_OK", sys.version_info[:2])
'''


@fixture_source("synthetic")
def _synthetic_source(tier: str, reaper, log=print) -> list:
    """`--fixtures synthetic`: one two-line script, packed. The default."""
    return [("synthetic", build_fixture(tier, log=log))]


@fixture_source("top25")
def _top25_source(tier: str, reaper, log=print) -> list:
    """`--fixtures top25`: one binary per top-25 PyPI package."""
    return build_top25_fixtures(tier, reaper, log=log)


def build_fixture(tier: str, log=print) -> Path:
    """One real binary, built once, copied per case."""
    cfg.OUT.mkdir(parents=True, exist_ok=True)
    exe = cfg.OUT / f"fixture-{tier}"
    if exe.exists():
        log(f"reusing {exe.name}")
        return exe
    src = cfg.OUT / "app.py"
    src.write_text(APP)
    haru = shutil.which("haru-pack") or str(cfg.REPO / ".venv" / "bin" / "haru-pack")
    log(f"building fixture ({tier}) — once, then every case gets a copy")
    r = subprocess.run([haru, "build", str(src), "-o", str(exe), "--tier", tier],
                       capture_output=True, text=True, timeout=1800)
    if r.returncode != 0 or not exe.exists():
        raise SystemExit("fixture build failed:\n" + (r.stderr or r.stdout)[-1500:])
    return exe



def _flexrun():
    """Reuse the flex harness's project builder rather than a second copy of it."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("flexrun", cfg.REPO / "tools" / "flex-run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_top25_fixtures(tier: str, reaper, log=print) -> list:
    """One binary per top-25 package, so the chaos cases run against real payloads.

    The synthetic fixture is a two-line script: its payload is a handful of files. A real
    package brings native libraries, deep trees, and thousands of staged files — which is
    what the staging, verification and truncation cases are actually about.

    THICK on purpose. Every case runs with a pristine cache directory (otherwise the
    tampering cases prove nothing, since a warm stage is reused). At the default tier that
    would mean each of several hundred case-runs re-downloading an interpreter and the
    package's dependencies; thick puts them in the payload, so the runs need no network at
    all and are the same speed for every case.
    """
    from haru_pack import tomlio
    manifest = cfg.REPO / "flex" / "packages.toml"
    if not manifest.exists():
        raise SystemExit("flex/packages.toml missing — run tools/gen-package-manifest.py")
    pkgs = [p for p in tomlio.load(manifest).get("package", []) if p.get("list") == "top25"]
    if not pkgs:
        raise SystemExit("no top25 packages in flex/packages.toml")

    flex = _flexrun()
    haru = shutil.which("haru-pack") or str(cfg.REPO / ".venv" / "bin" / "haru-pack")
    fixdir = cfg.OUT / "fixtures"
    fixdir.mkdir(parents=True, exist_ok=True)

    built, failed = [], []
    log(f"building {len(pkgs)} top-25 fixture(s) at tier={tier} — once, then reused")
    for i, pkg in enumerate(pkgs, 1):
        name = pkg["name"]
        exe = fixdir / f"fixture-{name}"
        if exe.exists():
            log(f"  [{i}/{len(pkgs)}] {name}: reusing")
            built.append((name, exe))
            continue
        work = reaper.track(Path(tempfile.mkdtemp(prefix="bb-fixture-", dir=cfg.WORK_ROOT)))
        proj = flex.make_project({**pkg, "smoke": (pkg.get("smoke") or "").replace(
            "FLEX_OK", MARKER) or f"print('{MARKER}')"}, work)
        r = subprocess.run([haru, "build", str(proj), "-o", str(exe), "--tier", tier],
                           capture_output=True, text=True, timeout=3600)
        if r.returncode != 0 or not exe.exists():
            failed.append((name, (r.stderr or r.stdout).strip()[-200:]))
            log(f"  [{i}/{len(pkgs)}] {name}: BUILD FAILED")
            continue
        log(f"  [{i}/{len(pkgs)}] {name}: {exe.stat().st_size / 1e6:.0f}MB")
        built.append((name, exe))

    if failed:
        log(f"{len(failed)} fixture(s) could not be built; those packages are skipped, "
            f"not silently passed:")
        for name, err in failed:
            log(f"  {name}: {err[:120]}")
    if not built:
        raise SystemExit("no fixtures built")
    return built



# ---------------------------------------------------------------- calibration

def calibrate(fixtures: list, log=print) -> int:
    """Find the resource band that separates a light package from a heavy one.

    A ceiling only discriminates between packages if it sits BETWEEN their requirements.
    The first `tight_address_space` guessed 256 MB, which is below what a bare interpreter
    needs — every package failed identically and the case discriminated nothing while
    looking thorough. This measures instead of guessing, and prints a number to paste.

    Staging is warmed at no limit first, so what gets measured is the APPLICATION's
    requirement rather than the staging step's — which is the same for every package and
    not the question.
    """
    import resource
    from busybody_analyze import RESOURCE_LADDER

    if len(fixtures) < 2:
        log("calibration needs at least two fixtures to find a band between them.")
        log("Try:  python tools/busybody.py --calibrate --fixtures top25")
        return 2

    log("=" * 78)
    log("busybody calibration — RLIMIT_AS")
    log("=" * 78)
    log("")
    log("Each fixture is staged once with no limit, then run at each ceiling. The lowest")
    log("ceiling at which it still works is its requirement. A threshold placed between")
    log("the smallest and largest requirement is one that tells packages apart.")
    log("")
    log(f"  {'fixture':24} {'requires':>10}   ladder")
    log(f"  {'-' * 24} {'-' * 10:>10}   {'-' * 30}")

    needs = {}
    for name, exe in fixtures:
        work = Path(tempfile.mkdtemp(prefix="bb-calibrate-", dir=cfg.WORK_ROOT))
        try:
            cache, first = warm(exe, work)
            if first["outcome"] != "RAN":
                log(f"  {name:24} {'?':>10}   SKIPPED: would not run unrestricted")
                continue
            marks, need = [], None
            for mb in RESOURCE_LADDER:
                r = run_exe(exe, work, env=clean_env(cache), timeout=180,
                            rlimits={resource.RLIMIT_AS: (mb * 1024 * 1024,) * 2})
                ok = r["outcome"] == "RAN"
                marks.append(f"{mb}={'ok' if ok else 'x'}")
                if ok:
                    need = mb
                    break
            needs[name] = need
            log(f"  {name:24} {(str(need) + 'MB') if need else '>ladder':>10}   "
                f"{' '.join(marks)}")
        finally:
            shutil.rmtree(work, ignore_errors=True)

    log("")
    measured = {k: v for k, v in needs.items() if v}
    if len(measured) < 2:
        log("Not enough measurements to name a band.")
        return 1
    lo, hi = min(measured.values()), max(measured.values())
    if lo == hi:
        log(f"Every fixture needs {lo}MB. No band exists at this granularity, so RLIMIT_AS")
        log("cannot separate these packages — pick fixtures with more contrast (a config")
        log("parser against a numeric stack), or discriminate on something else.")
        return 1
    candidates = [m for m in RESOURCE_LADDER if lo <= m < hi]
    pick = candidates[len(candidates) // 2] if candidates else (lo + hi) // 2
    log(f"Band: {lo}MB (lightest) .. {hi}MB (heaviest).")
    log(f"Recommended threshold: {pick}MB")
    log("")
    log("Paste into tools/busybody.py, WITH this measurement beside it:")
    log(f"    ADDRESS_SPACE_MB = {pick}")
    log("")
    for k, v in sorted(measured.items(), key=lambda kv: kv[1]):
        log(f"    #:   {k:22} ok at {v}MB")
    log("")
    log("This number is machine-specific. It is not a constant of nature — re-run")
    log("calibration on a different box rather than assuming it transfers.")
    if pick == ADDRESS_SPACE_MB:
        log("")
        log(f"(Current ADDRESS_SPACE_MB is already {ADDRESS_SPACE_MB} — no change needed.)")
    return 0





# The engine reads this rather than importing `calibrate` by name; see
# busybody_config.CALIBRATOR and INV-MODULARITY-04.
cfg.CALIBRATOR = calibrate

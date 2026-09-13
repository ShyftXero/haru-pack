"""examiner — a real package sits its OWN test suite inside the binary.

`import numpy` succeeds long before numpy WORKS. The package's own suite is the only
smoke test nobody can accidentally write too weakly.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "src") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "src"))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from haru_pack import overlay  # noqa: E402,F401

from busybody_config import (FATAL, MARKER, case)  # noqa: E402,F401
from busybody_runner import (Ctx, InfraFailure, blame, classify, clean_env,  # noqa: E402,F401
                             dir_bytes, infra_failure_reason, run_exe, stage_root,
                             warm, work_root_report)
from busybody_wedge import _build, _run_artifact  # noqa: E402,F401

# ---------------------------------------------------------------- examiner: sit the exam

# A hello-world fixture proves a module imported. That is a low bar: `import numpy` succeeds
# long before `numpy` is usable, because the failure modes of a bundled native package are in
# the parts an import does not touch — a missing .so a submodule loads lazily, a data file,
# an f2py-generated extension, a locale-dependent codec path.
#
# The examiner makes the payload sit the package's OWN test suite, inside the thick binary,
# with nothing to download. That is the strongest available statement that a thick artifact
# carried a working library rather than an importable one.
#
# Checked 2026-09-10, all 25 top-PyPI packages: only TWO ship a runnable test suite in the
# wheel — numpy (13 test packages) and certifi. The other 23 would need sdists, which is a
# second acquisition path for no extra assurance, so this persona covers the two that can.
# Both are declared as data below rather than hardcoded in logic.
EXAMS = {
    "numpy": {
        # Bounded on purpose: the full suite is ~40k tests. These two modules exercise the
        # native core and the f2py/linalg surfaces where a truncated payload actually shows
        # up, and they run in a bearable time.
        "deps": ["numpy", "pytest", "hypothesis"],
        "modules": ["_core/tests/test_numeric.py", "linalg/tests/test_linalg.py"],
        "why_this_package": ("native BLAS, lazily-imported submodules, compiled extensions "
                             "and packaged data files — everything a payload can truncate "
                             "without breaking `import numpy`"),
    },
    "certifi": {
        "deps": ["certifi", "pytest"],
        "modules": ["tests"],
        "why_this_package": ("tiny, but it ships a real suite and its whole job is a data "
                             "file, which is exactly the kind of thing a payload drops"),
    },
}


def _exam_script(pkg: str, spec: dict) -> str:
    """A PEP 723 script that runs the installed package's own tests from inside the binary."""
    deps = ", ".join(f'"{d}"' for d in spec["deps"])
    mods = ", ".join(f'"{m}"' for m in spec["modules"])
    # Pinned to 3.12 deliberately. `>=3.11` resolves to whatever python-build-standalone
    # published most recently for that series, and the supply-chain guard refuses an
    # interpreter with no publisher digest in pins.toml — correctly. A test fixture is not a
    # reason to widen the pin set, so it asks for a version that is already pinned.
    return f"""# /// script
# requires-python = "==3.12.*"
# dependencies = [{deps}]
# ///
# Run the packaged library's own test suite from inside the packed binary. The package
# under test is located through its __file__ rather than by guessing a path, so this works
# wherever the launcher staged the payload.
import pathlib
import sys

import pytest

import {pkg}

root = pathlib.Path({pkg}.__file__).parent
targets = [str(root / m) for m in [{mods}]]
missing = [t for t in targets if not pathlib.Path(t).exists()]
if missing:
    print("PAYLOAD INCOMPLETE: test files absent from the staged package:", missing)
    sys.exit(2)

rc = pytest.main(["-q", "--no-header", "-x", "-p", "no:cacheprovider", *targets])
if rc == 0:
    print("{MARKER}", "{pkg} passed its own tests inside the binary")
sys.exit(rc)
"""


def _sit_exam(pkg: str, work: Path) -> dict:
    spec = EXAMS[pkg]
    proj = work / "exam"
    proj.mkdir(parents=True, exist_ok=True)
    src = proj / f"exam_{pkg}.py"
    src.write_text(_exam_script(pkg, spec))

    out = work / f"exam-{pkg}"
    rc, so, se = _build(proj / f"exam_{pkg}.py", out, "--tier", "thick", timeout=2400)
    if rc != 0 or not out.exists():
        return {"outcome": "REFUSED", "rc": rc, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"thick build failed: {(so + se).strip()[-400:]}"}

    # Nothing to download: thick sets UV_OFFLINE=1 inside the launcher, and the proxy vars
    # are pointed at a closed port so any library-level HTTP attempt fails loudly rather
    # than quietly succeeding and hiding a payload gap.
    env = clean_env(work / "ec", http_proxy="http://127.0.0.1:1",
                    https_proxy="http://127.0.0.1:1", no_proxy="")
    r = run_exe(out, work, env=env, timeout=2400)
    r["exam_mb"] = round(out.stat().st_size / 1e6, 1)
    return r


@case("examiner", "RAN",
      "numpy runs its own test suite from inside a thick binary, offline. `import numpy` "
      "succeeds long before numpy is usable: the failure modes of a bundled native package "
      "live in the parts an import never touches — a lazily-loaded .so, an f2py extension, "
      "a packaged data file. This is the strongest available statement that a thick payload "
      "carried a working library and not merely an importable one.",
      inv="INV-TIER-01",
      remedy="A failure here is a payload completeness bug, not a numpy bug. Compare the "
             "staged tree against the wheel: something the suite reaches was not packed. "
             "`PAYLOAD INCOMPLETE` in the output means the test files themselves are absent.",
      per_fixture=False, serial=True)
def numpy_passes_its_own_tests_inside_the_binary(exe: Path, work: Path) -> dict:
    return _sit_exam("numpy", work)


@case("examiner", "RAN",
      "certifi runs its own test suite from inside a thick binary, offline. Tiny, but its "
      "entire job is to ship a data file — exactly the kind of thing a payload builder "
      "drops while leaving the module importable.",
      inv="INV-TIER-01",
      remedy="A failure here means the CA bundle or the test data did not make it into the "
             "payload. Check the payload's ignore patterns against what the wheel ships.",
      per_fixture=False, serial=True)
def certifi_passes_its_own_tests_inside_the_binary(exe: Path, work: Path) -> dict:
    return _sit_exam("certifi", work)




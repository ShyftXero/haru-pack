"""examiner — a real package sits its OWN test suite, sourced from its SDIST, inside the binary.

`import numpy` succeeds long before numpy WORKS. The package's own suite is the only smoke
test nobody can accidentally write too weakly.

WHERE THE SUITE COMES FROM. Tests almost never ship in the wheel — checked across the top-25,
only numpy and certifi do, and only under the installed package. Every OTHER package's tests
ride in the SDIST. A wheel-only examiner therefore covers 2 of N. The sdist is the one
acquisition path that reaches any package's real suite, so this persona reuses the flex exam's
machinery — `tools/exam_fetch` — to do exactly what `tools/exam.py` does: fetch the sdist,
locate the test tree, extract the package's own declared test-deps, ship the whole tree into a
thick project whose entrypoint runs pytest over it, and run that binary offline. It does NOT
fork that machinery; duplicating fetch/locate/test_deps is what INV-CHAOS-15 forbids.

HONEST ABOUT COVERAGE. A package whose sdist carries no test tree has no suite to sit. That is
recorded as "no test suite in sdist" — `exam_fetch.locate_suite` is what decides it — and is
NEVER faked as a pass. A suite that errors is a real result, not a skip. numpy and certifi
themselves land on the no-suite branch under the sdist mechanism, because their suites ship
only in the wheel; that is the honest face of the coverage the old wheel path hid.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Generalized from a hardcoded
numpy/certifi pair to any top-N package, sourced from the sdist, 2026-09-16 (INV-CHAOS-15).
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "src") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "src"))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from haru_pack import overlay  # noqa: E402,F401

from busybody_config import case  # noqa: E402
from busybody_runner import clean_env, run_exe  # noqa: E402
from busybody_wedge import _build  # noqa: E402  (one build path, shared with the wedge persona)

# The sdist -> thick-project -> offline-pytest machinery, IMPORTED (never forked) from the flex
# exam. `MARKER` is the exam entrypoint's own success token — the generated `python -m exam`
# prints it, not busybody's BUSYBODY_OK, so the outcome is re-graded on it below.
from exam_fetch import (MARKER as EXAM_MARKER,  # noqa: E402
                        fetch_sdist, locate_suite, make_project, pypi_meta, test_deps, top_n)

# ---------------------------------------------------------------- examiner: sit the exam

NO_SUITE = "no test suite in sdist"

# The examiner is no longer a frozen pair. These are DEFAULTS — packages whose sdist ships a
# small, fast, pure-python suite — chosen so the persona proves the mechanism on real suites
# without dragging a 40k-test build into every sweep. Any top-N package can be sat instead
# (`sit_exam(pkg, work)`, or iterate `top_n_packages()`). numpy and certifi are deliberately
# NOT here: their suites ride only in the wheel, so the sdist mechanism records them as
# NO_SUITE, honestly, rather than the old hardcoded pass.
EXAM_PACKAGES = ("iniconfig", "six")


def top_n_packages() -> list[str]:
    """The ranked top-N package names, from the same matrix the flex exam reads. The examiner
    can sit any of these — `sit_exam(name, work)` — not just the EXAM_PACKAGES defaults."""
    return [p["name"] for p in top_n()]


def exam_project_from_root(pkg: str, imp: str, ver: str, root: Path, proj: Path):
    """Turn an already-unpacked sdist ROOT into a thick-exam project, or decline honestly.

    Reuses `exam_fetch.locate_suite` / `test_deps` / `make_project` verbatim. Returns
    `(proj, layout)` when the sdist carries a suite, or `(None, NO_SUITE)` when it does not —
    never a faked project. Split from the network fetch below so the honest no-suite branch is
    testable on a local sdist tree, with no PyPI round-trip and no thick build.
    """
    kind, suite = locate_suite(root)
    if kind == "none":
        return None, NO_SUITE
    make_project(pkg, imp, ver, kind, suite, test_deps(root), proj, sdist_root=root)
    return proj, kind + ":" + ",".join(p.name for p in suite)


def sit_exam(pkg: str, work: Path, imp: str | None = None) -> dict:
    """Sit ONE package's own test suite, sourced from its sdist, inside a thick binary, offline.

    Generalized over any top-N package, not the old hardcoded numpy/certifi pair: the suite is
    fetched from the sdist with `exam_fetch`, the same mechanism `tools/exam.py` proves the
    flex top-N with. HONEST — a package whose sdist has no test tree yields a NO-SUITE result
    carrying "no test suite in sdist", never a faked pass. (Network: PyPI, at build time only.)
    """
    imp = imp or pkg.replace("-", "_")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    meta = pypi_meta(pkg)
    if not meta["sdist_url"]:
        return {"outcome": "NO-SUITE", "rc": None, "seconds": 0, "blame": "none",
                "note": "no sdist on PyPI", "stdout": "", "stderr": "no sdist on PyPI"}
    root = fetch_sdist(meta["sdist_url"], work / "sd")
    proj, layout = exam_project_from_root(pkg, imp, meta["version"], root, work / "proj")
    if proj is None:
        # No test tree in the sdist. Recorded, never faked: a pass here would be a lie about
        # what the examiner actually covered.
        return {"outcome": "NO-SUITE", "rc": None, "seconds": 0, "blame": "none",
                "note": NO_SUITE, "stdout": "", "stderr": NO_SUITE}

    out = work / f"exam-{pkg}"
    rc, so, se = _build(proj, out, "--tier", "thick", timeout=2400)
    if rc != 0 or not out.exists():
        return {"outcome": "REFUSED", "rc": rc, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"thick build failed: {(so + se).strip()[-400:]}"}

    # Nothing to download: thick sets UV_OFFLINE=1 inside the launcher, and the proxy vars are
    # pointed at a closed port so any library-level HTTP attempt fails loudly rather than
    # quietly succeeding and hiding a payload gap.
    env = clean_env(work / "ec", http_proxy="http://127.0.0.1:1",
                    https_proxy="http://127.0.0.1:1", no_proxy="")
    r = run_exe(out, work, env=env, timeout=2400)
    # The exam entrypoint prints EXAM_OK, not busybody's BUSYBODY_OK, so run_exe.classify reads a
    # clean pass as SILENT. Re-grade on the exam's own marker: rc 0 with EXAM_OK is a genuine RAN.
    # Everything else classify decided stands — a traceback is still CRASHED/APP-CRASHED, a
    # timeout still HUNG, a non-zero exit still REFUSED.
    if r["outcome"] == "SILENT" and EXAM_MARKER in (r.get("stdout") or ""):
        r["outcome"], r["blame"] = "RAN", "none"
    r["exam_mb"] = round(out.stat().st_size / 1e6, 1)
    r["layout"] = layout
    return r


def _register_exam_case(pkg: str):
    """Register one examiner case for `pkg`. A factory, not two hand-copied functions, so the
    default set is one edit and the persona cannot silently drift to a hardcoded pair again."""
    def fn(exe: Path, work: Path) -> dict:
        return sit_exam(pkg, work)

    fn.__name__ = f"{pkg.replace('-', '_')}_passes_its_own_tests_inside_the_binary"
    return case(
        "examiner", "RAN",
        f"{pkg} runs its OWN test suite — sourced from its sdist, the same way the flex exam "
        f"does — from inside a thick binary with the network denied. `import {pkg}` succeeds "
        f"long before {pkg} is usable; the package's own suite is the strongest available "
        f"statement that a thick payload carried a WORKING library and not merely an "
        f"importable one.",
        inv="INV-TIER-01",
        remedy=f"A failure here is a payload-completeness bug, not a bug in {pkg}: compare the "
               f"staged tree against the sdist, something the suite reaches was not packed. A "
               f"NO-SUITE result means {pkg}'s sdist ships no test tree to sit — honest "
               f"coverage, not a defect.",
        per_fixture=False, serial=True)(fn)


for _pkg in EXAM_PACKAGES:
    _register_exam_case(_pkg)

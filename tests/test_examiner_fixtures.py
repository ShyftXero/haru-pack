"""INV-TIER-01 — a thick payload carries a WORKING library, not merely an importable one.

`import numpy` succeeds long before numpy is usable. The failure modes of a bundled native
package live in the parts an import never touches: a lazily-loaded `.so`, an f2py-generated
extension, a packaged data file. A hello-world fixture cannot see any of them.

busybody's `examiner` persona makes the payload sit the package's own test suite, inside the
thick binary, with nothing to download. Measured 2026-09-10 on this box:

    numpy     2175 passed, 3 skipped, 2 xfailed in 26.33s   (100.8 MB binary)
    certifi      3 passed in 0.03s                          ( 63.7 MB binary)

These tests guard the harness that produces those numbers — that the generated scripts are
valid, that a vacuous pass is impossible, and that the interpreter they ask for is one the
supply chain has a publisher digest for.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _busybody():
    sys.path.insert(0, str(REPO / "tools"))
    spec = importlib.util.spec_from_file_location("bb_exam", REPO / "tools" / "busybody.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def bb():
    return _busybody()


@pytest.mark.invariant("INV-TIER-01")
def test_only_packages_that_actually_ship_tests_are_examined(bb):
    """Checked against all 25 top-PyPI packages on 2026-09-10: exactly two ship a runnable
    suite in the wheel. The other 23 would need sdists — a second acquisition path for no
    extra assurance, which is the opposite of the one-code-path rule this project follows."""
    assert set(bb.EXAMS) == {"numpy", "certifi"}
    for pkg, spec in bb.EXAMS.items():
        assert spec["modules"], f"{pkg} has no test targets"
        assert spec["deps"][0] == pkg, f"{pkg} must be its own first dependency"
        assert "pytest" in spec["deps"], f"{pkg}'s suite needs a runner in the payload"
        assert spec["why_this_package"], (
            f"{pkg} must record what it is here to catch, or the next person cannot judge "
            f"whether it is still worth its runtime"
        )


@pytest.mark.invariant("INV-TIER-01")
@pytest.mark.parametrize("pkg", ["numpy", "certifi"])
def test_the_generated_exam_script_is_valid_python(bb, pkg):
    src = bb._exam_script(pkg, bb.EXAMS[pkg])
    compile(src, f"exam_{pkg}", "exec")
    assert "# /// script" in src, "the payload's dependencies come from PEP 723 metadata"
    assert f"import {pkg}" in src


@pytest.mark.invariant("INV-TIER-01")
@pytest.mark.parametrize("pkg", ["numpy", "certifi"])
def test_an_exam_that_collected_nothing_cannot_pass(bb, pkg):
    """The way this test would lie.

    If the suite were absent from the payload, a naive script would run pytest against
    nothing and exit 0 — reporting a pass for a payload that shipped no tests at all. Two
    things prevent it: the script checks the paths exist first and exits 2 with
    `PAYLOAD INCOMPLETE`, and pytest itself returns 5 (not 0) when it collects nothing. The
    success marker is printed only on rc == 0.
    """
    src = bb._exam_script(pkg, bb.EXAMS[pkg])
    assert "PAYLOAD INCOMPLETE" in src, (
        "a missing suite must be reported as a payload gap, not as a pass"
    )
    assert "sys.exit(2)" in src
    assert re.search(r"if rc == 0:\s*\n\s*print\(\"BUSYBODY_OK\"", src), (
        "the marker must be printed only when pytest actually returned success"
    )
    assert "sys.exit(rc)" in src, "the harness classifies on the exit code"


@pytest.mark.invariant("INV-SUPPLY-01")
@pytest.mark.parametrize("pkg", ["numpy", "certifi"])
def test_the_exam_asks_for_an_interpreter_the_supply_chain_has_pinned(bb, pkg):
    """The examiner's first run was refused by the pin guard, correctly.

    `requires-python = ">=3.11"` resolved to CPython 3.11.9, which has no publisher digest
    in pins.toml — and the guard says in as many words not to invent one. A test fixture is
    not a reason to widen the pin set, so the script asks for a version already pinned.

    Red-path: change the exam script back to a series with no pin and this fails here,
    at test time, instead of after a two-minute thick build.
    """
    src = bb._exam_script(pkg, bb.EXAMS[pkg])
    m = re.search(r'#\s*requires-python\s*=\s*"([^"]+)"', src)
    assert m, "the exam script must declare an interpreter"
    series = re.search(r"(\d+\.\d+)", m.group(1))
    assert series, f"cannot read a version series from {m.group(1)!r}"

    pins = (REPO / "src" / "haru_pack" / "pins.toml").read_text()
    pinned = set(re.findall(r"cpython-(\d+\.\d+)\.\d+", pins))
    assert series.group(1) in pinned, (
        f"the exam asks for Python {series.group(1)}, which has no pinned build "
        f"({sorted(pinned)}). The build would be refused by the supply-chain guard."
    )


@pytest.mark.invariant("INV-TIER-01")
def test_the_exam_runs_offline_and_thick(bb):
    """Thick is the whole point: the payload must need nothing. The proxy variables are
    pointed at a closed port so a library-level HTTP attempt fails loudly rather than
    quietly succeeding and hiding a payload gap."""
    import ast
    import inspect
    body = ast.unparse(ast.parse(inspect.getsource(bb._sit_exam).lstrip()))
    assert "'--tier', 'thick'" in body, "an exam on a non-thick binary proves nothing"
    assert "http_proxy" in body and "127.0.0.1:1" in body, (
        "network must be denied at the process level, not assumed absent"
    )


@pytest.mark.invariant("INV-TIER-01")
def test_exam_cases_build_their_own_artifact_and_run_once(bb):
    """They say nothing about the packed fixture, so running them per fixture would repeat
    one answer 25 times — the census inflation INV-CHAOS-04 exists to prevent. They are also
    serial: a thick numpy build plus 2175 tests is not something to run eight of at once."""
    exam_cases = [c for c in bb.CASES if c["persona"] == "examiner"]
    assert len(exam_cases) == 2
    for c in exam_cases:
        assert c["per_fixture"] is False, f"{c['name']} would run once per fixture"
        assert c["serial"] is True, f"{c['name']} should not share the machine"
        assert c["expect"] == ("RAN",), (
            f"{c['name']} must require a real pass; anything else is a payload gap"
        )

"""INV-CHAOS-15 / INV-TIER-01 — the examiner sits ANY top-N package's OWN suite, from its sdist.

The examiner makes a thick payload sit the packaged library's own test suite, offline. `import
numpy` succeeds long before numpy WORKS, so the suite is the only smoke test nobody can write
too weakly. It sources that suite from the SDIST via `tools/exam_fetch` — the very machinery the
flex exam (`tools/exam.py`) uses — so it covers any top-N package, not just the two (numpy,
certifi) that happen to ship a runnable suite in the WHEEL. And it is honest: a package whose
sdist carries no test tree is recorded as "no test suite in sdist", never a faked pass.

These run offline and build NOTHING. They drive the sdist -> thick-project decision on a LOCAL
sdist tree, so there is no PyPI fetch and no minutes-long thick build; the network-bound
`sit_exam` wrapper is exercised in a real sweep, not here.
"""
from __future__ import annotations

import ast
import inspect
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
if str(REPO / "tools") not in sys.path:
    sys.path.insert(0, str(REPO / "tools"))


@pytest.fixture(scope="module")
def bb():
    """busybody, loaded the way the harness loads it, so `bb.CASES` is the real registry."""
    import busybody
    return busybody


@pytest.fixture(scope="module")
def bbx():
    import busybody_cases_exam
    return busybody_cases_exam


@pytest.fixture(scope="module")
def ef():
    import exam_fetch
    return exam_fetch


def _sdist_root(base: Path, *, with_suite: bool) -> Path:
    """A minimal unpacked sdist tree: a package dir, a pyproject, and — optionally — a real
    test tree. Stands in for what `fetch_sdist` would extract, so the branch under test needs
    no network."""
    root = base / "widget-1.2.3"
    (root / "widget").mkdir(parents=True)
    (root / "widget" / "__init__.py").write_text("__version__ = '1.2.3'\n")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "widget"\nversion = "1.2.3"\n'
        '[project.optional-dependencies]\ntest = ["pytest"]\n')
    if with_suite:
        (root / "tests").mkdir()
        (root / "tests" / "test_widget.py").write_text("def test_ok():\n    assert True\n")
    return root


# ---------------------------------------------------------------- (c) it REUSES exam_fetch

@pytest.mark.invariant("INV-CHAOS-15")
def test_the_examiner_reuses_exam_fetch_and_does_not_fork_it(bbx, ef):
    """The sdist/locate/test_deps logic must be the flex exam's, imported — not a second copy.

    Two copies of "find the test tree in an sdist" is exactly how the examiner and the flex
    exam would drift into disagreeing about what a package's suite is. So the examiner binds
    the same function objects, and defines none of its own.

    Red-path: paste `locate_suite`'s body into busybody_cases_exam as a local def (fork it).
    The identity check below goes red, and the source scan names the forked function.
    """
    for name in ("fetch_sdist", "locate_suite", "make_project", "pypi_meta", "test_deps"):
        assert getattr(bbx, name) is getattr(ef, name), (
            f"busybody_cases_exam.{name} is not exam_fetch.{name} — the examiner has forked "
            f"the sdist machinery instead of reusing it"
        )

    tree = ast.parse(Path(bbx.__file__).read_text(encoding="utf-8"))
    local_defs = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    forked = local_defs & {"fetch_sdist", "locate_suite", "test_deps", "make_project", "pypi_meta"}
    assert not forked, (
        f"busybody_cases_exam re-defines exam_fetch machinery instead of importing it: {forked}"
    )


# ---------------------------------------------------------------- (a) ANY package, from the sdist

@pytest.mark.invariant("INV-CHAOS-15")
def test_the_examiner_is_not_frozen_to_numpy_and_certifi(bbx):
    """The old examiner could sit exactly numpy and certifi. The generalized one covers any
    top-N package, and its defaults are packages whose suite actually ships in the sdist —
    numpy and certifi are NOT among them, because their suites ride only in the wheel.

    Red-path: set `EXAM_PACKAGES = ("numpy", "certifi")` (re-freeze the pair). This goes red.
    """
    assert set(bbx.EXAM_PACKAGES) != {"numpy", "certifi"}, (
        "the examiner is still frozen to the numpy/certifi pair"
    )
    assert "numpy" not in bbx.EXAM_PACKAGES and "certifi" not in bbx.EXAM_PACKAGES, (
        "numpy/certifi ship a suite only in the wheel; the sdist examiner records them as "
        "NO-SUITE, so they must not be examiner DEFAULTS that expect a pass"
    )
    # The capability is a plain function of a package NAME, so any caller-supplied package —
    # or any of top_n_packages() — can be sat, not a hardcoded set.
    assert "pkg" in inspect.signature(bbx.sit_exam).parameters


@pytest.mark.invariant("INV-CHAOS-15")
def test_the_examiner_sits_a_package_other_than_numpy_certifi_from_a_local_sdist(bbx, tmp_path):
    """Feed a NON-numpy/certifi sdist tree through the examiner's project builder and confirm it
    produces a thick-exam project via `exam_fetch.make_project`: a project that depends on the
    package under test and whose entrypoint runs the package's own suite."""
    root = _sdist_root(tmp_path / "sd", with_suite=True)
    proj, layout = bbx.exam_project_from_root("widget", "widget", "1.2.3", root, tmp_path / "proj")

    assert proj is not None, "a sdist that ships a test tree must yield a project to sit"
    assert layout.startswith("dir:tests"), f"the located suite was not the tests/ tree: {layout}"

    pyproject = (proj / "pyproject.toml").read_text()
    assert '"widget==1.2.3"' in pyproject, "the exam project does not depend on the package"
    hp = (proj / "haru_pack.toml").read_text()
    assert 'entrypoint = ["python", "-m", "exam"]' in hp
    main = (proj / "exam" / "__main__.py").read_text()
    assert "import widget" in main and "pytest.main" in main
    assert (proj / "exam" / "_src" / "tests" / "test_widget.py").exists(), (
        "the whole sdist tree — the suite and the in-tree helpers beside it — must be shipped"
    )


# ---------------------------------------------------------------- (b) honest about NO suite

@pytest.mark.invariant("INV-CHAOS-15")
def test_a_sdist_with_no_test_tree_is_no_suite_not_a_pass(bbx, tmp_path):
    """The core correctness point: a package with no suite in its sdist has no suite to sit.

    It must be recorded as "no test suite in sdist" and NO project built — never a faked pass.

    Red-path: make the no-suite branch return a project anyway (`return proj, "faked"`), so a
    suiteless package looks examinable and would report a pass it never ran. This goes red.
    """
    root = _sdist_root(tmp_path / "sd", with_suite=False)
    proj, reason = bbx.exam_project_from_root("widget", "widget", "1.2.3", root, tmp_path / "proj")

    assert proj is None, "a sdist with no test tree must NOT yield a project — that would fake a pass"
    assert reason == bbx.NO_SUITE == "no test suite in sdist"
    assert not (tmp_path / "proj").exists(), "no exam project may be written for a suiteless sdist"


@pytest.mark.invariant("INV-CHAOS-15")
def test_sit_exam_records_no_suite_and_never_grades_it_a_pass(bbx):
    """`sit_exam`'s honesty, read from its source: the no-suite branches return the NO-SUITE
    outcome carrying "no test suite in sdist" / "no sdist on PyPI", and the only way a run is
    re-graded RAN is a rc-0 exit that ALSO printed the exam marker."""
    src = inspect.getsource(bbx.sit_exam)
    assert '"outcome": "NO-SUITE"' in src, "a package with no suite must not fall through to a pass"
    assert "no test suite in sdist" in src and "no sdist on PyPI" in src
    # The SILENT->RAN re-grade must be gated on the real success marker, or a binary that exited
    # 0 having run nothing would be credited a pass.
    assert 'r["outcome"] == "SILENT" and EXAM_MARKER in' in src, (
        "the pass re-grade is not gated on the exam's success marker — a vacuous 0-exit could "
        "be counted as RAN"
    )


# ---------------------------------------------------------------- INV-TIER-01: thick + offline

@pytest.mark.invariant("INV-TIER-01")
def test_the_exam_builds_thick_and_denies_the_network(bbx):
    """Thick is the whole point: the payload must need nothing. The proxy variables are pointed
    at a closed port so a library-level HTTP attempt fails loudly rather than quietly
    succeeding and hiding a payload gap.

    Red-path: drop `--tier thick` (build the default tier) or the proxy denial from `sit_exam`.
    """
    body = ast.unparse(ast.parse(inspect.getsource(bbx.sit_exam).lstrip()))
    assert "'--tier', 'thick'" in body, "an exam on a non-thick binary proves nothing"
    assert "http_proxy" in body and "127.0.0.1:1" in body, (
        "network must be denied at the process level, not assumed absent"
    )


@pytest.mark.invariant("INV-TIER-01")
def test_exam_cases_build_their_own_artifact_and_run_once(bb):
    """The examiner cases say nothing about the packed fixture — they build their own thick
    binary — so running them per fixture would repeat one answer 25 times, the census inflation
    INV-CHAOS-04 exists to prevent. They are serial: a thick build plus a real suite is not
    something to run eight of at once. And each must require a real pass; NO-SUITE for a package
    whose suite was expected is a coverage regression, not an acceptable outcome."""
    import busybody_cases_exam as bbx
    exam_cases = [c for c in bb.CASES if c["persona"] == "examiner"]
    assert len(exam_cases) == len(bbx.EXAM_PACKAGES), (
        "one examiner case per default package, generated from EXAM_PACKAGES"
    )
    for c in exam_cases:
        assert c["per_fixture"] is False, f"{c['name']} would run once per fixture"
        assert c["serial"] is True, f"{c['name']} should not share the machine"
        assert c["expect"] == ("RAN",), (
            f"{c['name']} must require a real pass; anything else is a payload/coverage gap"
        )
        assert c["inv"] == "INV-TIER-01"

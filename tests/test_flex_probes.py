"""INV-FLEX-03 — the import name flex exercises is one the distribution actually provides.

`flex/curation.toml` used to carry eight hand-curated `import_name` entries. Every one was a
guess, and `pillow` -> `PIL` is the case that makes guessing wrong. The probe now asks the
installed distribution, and the curated values are checked against the answer rather than
believed.

These run offline and build nothing. The generated body IS executed, though — a test that
only asserts a generated string "looks right" passes just as happily when the string is
syntactically broken.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

import flex_probes as fp  # noqa: E402


# ──────────────────────────────────────────── INV-FLEX-03: resolution, including pillow

@pytest.mark.invariant("INV-FLEX-03")
def test_a_distribution_that_imports_under_another_name_resolves_correctly():
    """The whole reason this exists. `pip install pillow` gives you `import PIL`."""
    mods, how = fp._provided_modules("pillow", mapping={"PIL": ["pillow"]})
    assert mods == ["PIL"]
    assert how == "packages_distributions"


@pytest.mark.invariant("INV-FLEX-03")
def test_resolution_normalises_the_distribution_name():
    """PEP 503: `typing-extensions`, `typing_extensions` and `Typing.Extensions` are one dist.

    Red-path: compare the names raw. Every dist whose name carries a `-` or `.` then resolves
    to nothing and silently falls through to the guess.
    """
    mapping = {"typing_extensions": ["typing-extensions"]}
    for spelling in ("typing-extensions", "typing_extensions", "Typing.Extensions"):
        mods, how = fp._provided_modules(spelling, mapping=mapping)
        assert mods == ["typing_extensions"], f"{spelling} did not resolve"
        assert how == "packages_distributions"


def test_a_distribution_providing_several_modules_reports_all_of_them():
    mods, _ = fp._provided_modules("attrs", mapping={"attr": ["attrs"], "attrs": ["attrs"],
                                                     "other": ["something-else"]})
    assert mods == ["attr", "attrs"]


def test_a_module_shared_by_several_distributions_still_resolves():
    """Namespace packages map one module to several dists; ours just has to be among them."""
    mods, _ = fp._provided_modules("zope-interface",
                                   mapping={"zope": ["zope.interface", "zope-event"]})
    assert mods == ["zope"]


@pytest.mark.invariant("INV-FLEX-03")
def test_it_falls_back_to_top_level_txt_when_the_mapping_is_unavailable():
    """`packages_distributions` is 3.10+, and some wheels are not mapped by it."""
    mods, how = fp._provided_modules("pillow", mapping={}, top_level="PIL\n\n")
    assert (mods, how) == (["PIL"], "top_level.txt")


@pytest.mark.invariant("INV-FLEX-03")
def test_the_last_resort_guess_is_labelled_as_a_guess():
    """Red-path: return the guess without saying so.

    The guess is wrong for exactly the packages this was written for, so a result that cannot
    be distinguished from an exact answer is worse than no result.
    """
    mods, how = fp._provided_modules("some-unknown-dist", mapping={}, top_level="")
    assert mods == ["some_unknown_dist"]
    assert how == "guess", "a guess must be reported as a guess, never as a resolution"


def test_an_exact_answer_is_preferred_over_a_guess():
    mods, how = fp._provided_modules("pillow", mapping={"PIL": ["pillow"]}, top_level="pillow")
    assert (mods, how) == (["PIL"], "packages_distributions")


# ──────────────────────────────────────────── the generated body is real code that runs

def run_body(body: str, tmp_path: Path) -> subprocess.CompletedProcess:
    app = tmp_path / "probe.py"
    app.write_text(body, encoding="utf-8")
    return subprocess.run([sys.executable, str(app)], capture_output=True, text=True,
                          timeout=120)


def test_the_generated_importable_body_executes_and_reports_success(tmp_path):
    """`json` is in the stdlib, so this resolves and imports for real, here, with no build.

    Red-path: break the generated source (a stray brace from the `.format`, a missing import
    in the prelude). A test that only grepped the string would not notice.
    """
    r = run_body(fp.importable_body({"name": "json"}), tmp_path)
    assert r.returncode == 0, f"probe failed:\n{r.stdout}\n{r.stderr}"
    assert "successfully imported json" in r.stdout
    assert fp.MARKER in r.stdout


def test_the_generated_body_reports_the_full_traceback_and_fails(tmp_path):
    """A dist that does not exist resolves to a guess, and importing the guess raises.

    Both halves matter: a non-zero exit so the harness records a failure, and the FULL
    traceback so there is something to dig into after the container is gone.
    """
    r = run_body(fp.importable_body({"name": "definitely-not-installed-xyz"}), tmp_path)
    assert r.returncode != 0
    assert fp.MARKER not in r.stdout
    assert "Traceback (most recent call last)" in r.stderr
    assert "ModuleNotFoundError" in r.stderr


def test_the_generated_body_emits_a_machine_readable_report(tmp_path):
    r = run_body(fp.importable_body({"name": "json"}), tmp_path)
    report = fp.parse_report(r.stdout)
    assert report is not None, "the probe must emit a FLEX_JSON line"
    assert report["dist"] == "json"
    assert report["failed"] == []
    assert "json" in report["modules"]
    assert report["how"] in ("packages_distributions", "top_level.txt", "guess")


def test_one_broken_module_does_not_hide_the_others(tmp_path):
    """Per-module try/except, not one try around the lot.

    A package with several top-level modules must say WHICH one broke. Red-path: wrap the
    loop in a single try — the report then names the package and nothing more useful.
    """
    body = fp.importable_body({"name": "x"}).replace(
        "mods, how = _provided_modules(DIST)",
        "mods, how = ['json', 'nonexistent_aaa', 'sys'], 'test'")
    r = run_body(body, tmp_path)
    report = fp.parse_report(r.stdout)
    assert report["failed"] == ["nonexistent_aaa"]
    assert "successfully imported json" in r.stdout
    assert "successfully imported sys" in r.stdout, (
        "a failure partway through must not stop the remaining modules being tried"
    )


def test_the_probe_does_not_consult_the_curated_import_name(tmp_path):
    """Red-path: generate the body from `pkg["import_name"]`.

    If a curated value can steer the probe, then checking the probe's answer against that
    same value proves nothing — the assertion becomes a tautology.
    """
    body = fp.importable_body({"name": "json", "import_name": "totally_wrong_name"})
    assert "totally_wrong_name" not in body
    r = run_body(body, tmp_path)
    assert r.returncode == 0 and fp.MARKER in r.stdout


# ──────────────────────────────────────────── INV-FLEX-03: curation is checked, not trusted

@pytest.mark.invariant("INV-FLEX-03")
def test_a_stale_curated_import_name_is_a_failure_that_blames_the_manifest():
    """Red-path: point a curated `import_name` at a module the dist does not ship.

    The message has to say the MANIFEST is stale. Reporting it as a package failure sends
    someone to debug a package that is fine.
    """
    conflict = fp.curation_conflict(
        {"name": "pyyaml", "import_name": "pyyaml"},
        {"dist": "pyyaml", "modules": ["yaml", "_yaml"], "how": "packages_distributions"})
    assert conflict
    assert "stale" in conflict
    assert "pyyaml" in conflict and "yaml" in conflict
    assert "not necessarily at fault" in conflict


@pytest.mark.invariant("INV-FLEX-03")
def test_a_correct_curated_import_name_passes():
    assert not fp.curation_conflict(
        {"name": "pyyaml", "import_name": "yaml"},
        {"dist": "pyyaml", "modules": ["yaml", "_yaml"], "how": "packages_distributions"})


def test_no_curated_name_and_no_report_are_both_silent():
    report = {"dist": "x", "modules": ["x"], "how": "guess"}
    assert not fp.curation_conflict({"name": "x"}, report)
    assert not fp.curation_conflict({"name": "x", "import_name": "x"}, None)


# ──────────────────────────────────────────────────────────────────────── style dispatch

def test_every_declared_style_produces_a_body():
    for style in fp.STYLES:
        assert fp.body_for({"name": "certifi"}, style).strip()


def test_an_unknown_style_is_refused_rather_than_guessed():
    with pytest.raises(ValueError):
        fp.body_for({"name": "certifi"}, "importible")


def test_the_smoke_style_still_honours_a_curated_import_name():
    """The smoke body is hand-written throughout, so the curated name is part of it.

    Only `importable` must ignore curation — conflating the two would either break the
    existing smoke bodies or make the INV-FLEX-03 check vacuous.
    """
    body = fp.body_for({"name": "pyyaml", "import_name": "yaml"}, "smoke")
    assert "import yaml as _m" in body


def test_the_smoke_style_uses_a_custom_body_when_the_manifest_gives_one():
    body = fp.body_for({"name": "numpy", "smoke": "import numpy\nprint('FLEX_OK')"}, "smoke")
    assert "import numpy" in body and fp.MARKER in body


def test_parse_report_ignores_noise_and_takes_the_last_report():
    stdout = (f"{fp.JSON_MARKER} not json at all\n"
              "some package printed this\n"
              f'{fp.JSON_MARKER} {json.dumps({"dist": "b", "modules": ["b"]})}\n')
    assert fp.parse_report(stdout)["dist"] == "b"


def test_parse_report_survives_a_package_printing_the_marker_itself():
    """Packages print all sorts of things. A malformed line must not raise."""
    assert fp.parse_report(f"{fp.JSON_MARKER} {{not valid json\n") is None
    assert fp.parse_report("nothing here\n") is None


@pytest.mark.invariant("INV-FLEX-03")
def test_the_default_style_is_importable():
    """Red-path: change the `--style` default back to `smoke`.

    Pinned because it is the decision in this change most likely to be quietly reverted —
    it is a one-word edit, it makes no test fail on its own, and it silently changes what a
    green run means.
    """
    import argparse
    src = (REPO / "tools" / "flex-run.py").read_text(encoding="utf-8")
    assert 'default="importable"' in src, "the --style default must be importable"

    # And prove argparse really produces it, not just that the string is in the file.
    ap = argparse.ArgumentParser()
    ap.add_argument("--style", choices=fp.STYLES, default="importable")
    assert ap.parse_args([]).style == "importable"


def test_the_style_is_recorded_in_the_result_not_just_used():
    """An `importable` pass and a `smoke` pass are different claims.

    Red-path: drop `style` from the result dict. Two runs asking different questions then
    produce results that look directly comparable, which is how a narrowing gets forgotten.
    """
    src = (REPO / "tools" / "flex-run.py").read_text(encoding="utf-8")
    assert '"style": style' in src, "run_one must record which style produced the result"

"""INV-PKG-01 — `haru` and `haru-pack` are the same tool, and the tool says which you used.

Asserted against `pyproject.toml` rather than against an installed environment, because the
thing that can regress is the declaration: delete one line from `[project.scripts]` and
every user with the other name in their muscle memory gets "command not found", with no
test to catch it. The end-to-end check (build a wheel, install it into a clean venv, run
both) was walked by hand on 2026-09-10 and is recorded in the commit rather than run here —
it needs a network and a build, which the suite deliberately does not.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from haru_pack import cli, tomlio

REPO = Path(__file__).resolve().parent.parent
PYPROJECT = tomlio.load(REPO / "pyproject.toml")
SCRIPTS = (PYPROJECT.get("project") or {}).get("scripts") or {}


@pytest.mark.invariant("INV-PKG-01")
def test_both_commands_are_declared():
    """Red-path: remove either entry from `[project.scripts]`."""
    assert "haru-pack" in SCRIPTS, "the long name is the documented one; it cannot go away"
    assert "haru" in SCRIPTS, "the short name was asked for as an equivalent, not a synonym"


@pytest.mark.invariant("INV-PKG-01")
def test_both_commands_are_the_same_program():
    """Equivalent, not merely similar: one callable, so they cannot drift apart."""
    assert SCRIPTS["haru"] == SCRIPTS["haru-pack"] == "haru_pack.cli:main"


@pytest.mark.invariant("INV-PKG-01")
@pytest.mark.parametrize("argv0,expected", [
    ("/usr/local/bin/haru", "haru"),
    ("/usr/local/bin/haru-pack", "haru-pack"),
    (r"C:\Python\Scripts\haru.exe", "haru"),
    (r"C:\Python\Scripts\haru-pack.exe", "haru-pack"),
    ("/usr/bin/python", "haru-pack"),            # python -m haru_pack
    ("/usr/bin/pytest", "haru-pack"),            # under the test runner
    ("", "haru-pack"),                            # embedded / frozen
    ("haru-pack-2.0", "haru-pack"),              # not one of ours: fall back
])
def test_prog_reports_the_invoked_name(monkeypatch, argv0, expected):
    """A refusal that prints a command the operator did not type is one more thing for them
    to translate (docs/PRINCIPLES.md). Red-path: hardcode `"haru-pack"` in `cli.prog`."""
    monkeypatch.setattr(sys, "argv", [argv0])
    assert cli.prog() == expected


@pytest.mark.invariant("INV-PKG-01")
def test_the_copy_pasteable_command_uses_the_invoked_name(monkeypatch, tmp_path, capsys):
    from haru_pack.discovery import AmbiguousProject, discover

    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\nversion = '0'\n")
    (tmp_path / "demo").mkdir()
    (tmp_path / "demo" / "__init__.py").write_text("def main():\n    pass\n")

    monkeypatch.setattr(sys, "argv", ["/usr/local/bin/haru"])
    try:
        discover(tmp_path)
    except AmbiguousProject as e:
        cli._report_ambiguity(tmp_path, e)
    out = capsys.readouterr().out
    assert "  haru build " in out
    assert "haru-pack build" not in out, (
        "invoked as `haru`, the tool told the operator to run `haru-pack`"
    )


@pytest.mark.invariant("INV-PKG-01")
def test_version_names_the_project_not_the_alias(monkeypatch, capsys):
    """`version` is the one place the long name is correct however you invoked it: it
    reports what is installed, and the distribution is `haru-pack`."""
    monkeypatch.setattr(sys, "argv", ["/usr/local/bin/haru"])
    cli.version()
    assert "haru-pack" in capsys.readouterr().out


# ------------------------------------------------------------------ shipping the sources

@pytest.mark.invariant("INV-PKG-02")
def test_the_launcher_sources_are_declared_for_the_wheel():
    """The launcher is compiled from source at build time, so a wheel missing `.nim` or the
    vendored `.c` produces a haru-pack that cannot build anything — and the failure is on
    the *user's* machine, at their first build.

    Red-path: drop the `src/haru_pack/launcher/xz/*.c` line from `[tool.hatch.build]`
    include. This goes red; without it the break only shows up for someone who installed
    from PyPI, which is nobody on the dev machine.
    """
    include = (((PYPROJECT.get("tool") or {}).get("hatch") or {})
               .get("build") or {}).get("include") or []
    need = ["src/haru_pack/launcher/*.nim",
            "src/haru_pack/launcher/xz/*.c",
            "src/haru_pack/launcher/xz/*.h",
            "src/haru_pack/pins.toml"]
    for pat in need:
        assert pat in include, f"{pat} is not shipped in the wheel"


@pytest.mark.invariant("INV-PKG-02")
def test_every_launcher_source_on_disk_is_covered_by_an_include_pattern():
    """The include list is a hand-written allowlist, so a new launcher file silently falls
    out of the wheel. This catches the next one."""
    import fnmatch

    include = (((PYPROJECT.get("tool") or {}).get("hatch") or {})
               .get("build") or {}).get("include") or []
    launcher = REPO / "src" / "haru_pack" / "launcher"
    missed = []
    for p in sorted(launcher.rglob("*")):
        if not p.is_file() or p.suffix in (".pyc",):
            continue
        rel = p.relative_to(REPO).as_posix()
        if not any(fnmatch.fnmatch(rel, pat) for pat in include):
            missed.append(rel)
    assert not missed, f"launcher files not covered by [tool.hatch.build] include: {missed}"


@pytest.mark.invariant("INV-PKG-02")
def test_the_license_file_exists():
    """`license = "MIT"` in pyproject is a claim; the file is the thing. Hatchling ships it
    to `dist-info/licenses/` automatically, so its absence is silent."""
    assert (REPO / "LICENSE").is_file()
    text = (REPO / "LICENSE").read_text(encoding="utf-8")
    assert "MIT License" in text
    assert "xz-embedded" in text, (
        "the vendored third-party source should be acknowledged where someone auditing the "
        "distribution will look"
    )


# ------------------------------------------------- the checks that gate a release, checked

CI_YML = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
CUT_RELEASE = (REPO / "scripts" / "cut-release.sh").read_text(encoding="utf-8")
SELF_BUILD = REPO / "scripts" / "self-build.sh"


def uncommented(text: str) -> str:
    """Lines with `#` comments stripped.

    These assertions forbid specific strings, and the comment *explaining* why a string is
    forbidden contains it — so grepping the raw file fails on the explanation. That has now
    bitten four tests in this repo; strip the comments and check the code.
    """
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.append(line.split("#", 1)[0] if "#" in line else line)
    return "\n".join(out)


CI_RUN = uncommented(CI_YML)
CUT_RUN = uncommented(CUT_RELEASE)


@pytest.mark.invariant("INV-CI-01")
def test_the_linter_is_pinned_to_one_version():
    """An unpinned linter fails on code it passed yesterday. Because `lint` runs before the
    invariant contract in ci.yml, that meant the contract did not run in CI for days.

    Red-path: put `uvx ruff check .` back in ci.yml, or loosen the dev-group pin.
    """
    dev = (PYPROJECT.get("dependency-groups") or {}).get("dev") or []
    pins = [d for d in dev if isinstance(d, str) and d.replace(" ", "").startswith("ruff==")]
    assert pins, f"ruff is not pinned exactly in [dependency-groups] dev: {dev}"

    assert "uvx ruff" not in CI_RUN, (
        "ci.yml lints with an unpinned `uvx ruff`; ruff's default rule set grows between "
        "releases, so this fails on unchanged code"
    )
    assert 'ruff==' in CI_RUN.replace("'", '"') or "ruff@$pin" in CI_RUN, (
        "ci.yml no longer derives the linter version from the pyproject pin"
    )
    assert "uvx" in CI_RUN and "ruff@" in CI_RUN, (
        "ci.yml should run the pinned ruff via uvx, in its own environment — "
        "`uv run --group dev` installs into the project env and would mutate the env the "
        "tests run in"
    )
    assert "uv run --group dev ruff" not in CI_RUN, (
        "linting through the project environment mutates it; the test job then runs against "
        "a different set of packages than it installed"
    )


@pytest.mark.invariant("INV-CI-01")
def test_the_release_gate_uses_the_same_pinned_linter():
    """The gate reported success on the exact commit CI rejected, because it used whatever
    `ruff` was on PATH. Three different ruffs were installed on the machine at the time."""
    assert 'ruff@$RUFF_PIN' in CUT_RUN, (
        "cut-release.sh does not lint through the pinned ruff"
    )
    assert 'ruff==' in CUT_RUN, (
        "cut-release.sh does not read the pin from pyproject, so it can drift from CI"
    )
    assert "skipping lint" not in CUT_RUN, (
        "the gate still has a path where it skips the linter and prints a note; a skipped "
        "check that looks like a passed one is what let CI stay red for a week"
    )


@pytest.mark.invariant("INV-CI-02")
def test_the_release_gate_self_builds():
    """Red-path: remove the self-build call from the gate, or make its failure non-fatal."""
    assert "./scripts/self-build.sh" in CUT_RUN, (
        "the release gate no longer packs haru-pack with haru-pack"
    )
    gate = CUT_RUN.split("gate passed at")[0]
    assert "self-build.sh" in gate, (
        "the self-build runs after the gate; it must run BEFORE tagging, or a failure "
        "leaves a pushed tag with no artifacts"
    )
    assert "--no-self-build" in CUT_RUN, "there is no explicit way to skip it"


@pytest.mark.invariant("INV-CI-02")
def test_the_self_build_covers_both_release_targets():
    src = uncommented(SELF_BUILD.read_text(encoding="utf-8"))
    assert "linux-x86_64 windows-x86_64" in src, "both release targets must be built"
    assert "-e haru-pack" in src, (
        "this project declares two console scripts, so the self-build must name one or "
        "discovery correctly refuses (INV-PKG-01)"
    )
    assert "verify" in src, "every artifact's payload must be verified before publishing"


@pytest.mark.invariant("INV-CI-02")
def test_the_self_build_script_is_executable():
    import os
    assert SELF_BUILD.is_file()
    assert os.access(SELF_BUILD, os.X_OK), "scripts/self-build.sh is not executable"

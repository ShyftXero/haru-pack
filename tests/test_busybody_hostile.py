"""The trojan persona's detectors, fed synthetic evidence.

This is the same discipline as `TestGuardCanFail` in `test_invariants_enforced.py`: a
detector that cannot be made to fire is a detector that reports `CONTAINED` forever, and a
persona whose cases all pass because they are broken is worse than no persona — it is a
green light nobody earned.

Two of these tests are the record of real regressions. `test_leaked_tokens_needs_the_payload`
is the DEFLATE blind spot, which reported `CONTAINED` for a key that was provably in the
payload. `test_a_project_tree_is_what_reaches_copytree` is the single-script branch, which
made six attacks invisible by never copying the tree at all.

None of this builds anything. The cases themselves are the integration test, and they cost
minutes each; these cost milliseconds and answer a different question — *would the detector
say so?*
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import busybody_hostile as H  # noqa: E402


def _evidence(tmp_path: Path, name: str, **kw) -> H.Evidence:
    """An Evidence that says 'the build succeeded and nothing happened', overridable."""
    base = dict(name=name, proj=tmp_path / "gift", home=tmp_path / "elsewhere",
                drop=tmp_path / "drop", exe=tmp_path / "out", rc=0, log="",
                members=[], blob=b"MZ", scan=lambda needles: {n: [] for n in needles})
    base.update(kw)
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "drop").mkdir(exist_ok=True)
    base["exe"].write_bytes(base["blob"])
    return H.Evidence(**base)


def test_every_attack_is_completely_declared():
    """A half-declared attack runs and then cannot be classified."""
    for name, spec in H.ATTACKS.items():
        for field in ("plant", "verdict", "tier", "timeout", "names"):
            assert field in spec, f"{name} declares no {field}"
        assert spec["tier"] in ("thin", "default", "thick"), name
        assert spec["names"], f"{name} declares no substrings a refusal must name"


def test_every_attack_plants_something_a_build_would_see(tmp_path):
    for name, spec in H.ATTACKS.items():
        proj = tmp_path / name
        home = H.planted_home(tmp_path / f"home-{name}")
        spec["plant"](proj, home)
        assert (proj / "pyproject.toml").exists(), (
            f"{name} plants no pyproject.toml, so `discover()` treats the directory as a "
            f"single script and `build.py` copies only that file — the attack is never "
            f"reached. See test_a_project_tree_is_what_reaches_copytree.")


def test_a_project_tree_is_what_reaches_copytree(tmp_path):
    """The regression that made six attacks invisible, stated as a property.

    `discovery.discover()` returns the .py FILE as `source` for a directory holding one
    script, and `build.py` then copies that file alone. Only a project — pyproject plus an
    executable package — makes `source` the directory, which is what puts `copytree` on the
    path. Asserted against the real discoverer, not against a belief about it.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from haru_pack.discovery import discover

    proj = tmp_path / "gift"
    H.ATTACKS["a_symlink_walks_a_private_key_into_the_payload"]["plant"](
        proj, H.planted_home(tmp_path / "home"))
    d = discover(proj)
    assert Path(d["source"]).is_dir(), (
        f"discover() resolved {d['source']} — a file, so the payload copy is a copy2 of one "
        f"script and the planted symlinks are never looked at")


def test_planted_credentials_are_outside_the_project(tmp_path):
    """The whole mechanism: the secrets are somewhere `_IGNORE` is never consulted for."""
    home = H.planted_home(tmp_path / "home")
    proj = tmp_path / "gift"
    H.ATTACKS["a_symlink_walks_a_private_key_into_the_payload"]["plant"](proj, home)
    assert home.exists() and not str(home).startswith(str(proj))
    links = [p for p in proj.rglob("*") if p.is_symlink()]
    assert links, "the symlink case planted no symlinks"
    for link in links:
        target = Path(link).resolve()
        assert str(target).startswith(str(home.resolve())), (
            f"{link.name} points at {target}, which is not the planted credential tree")


def test_leaked_tokens_needs_the_payload_not_just_the_binary(tmp_path):
    """The DEFLATE blind spot, as a test rather than as a comment.

    A scanner that only greps the exe's bytes returns nothing for a secret that is inside a
    compressed payload member. `Evidence.scan` is injected precisely so the detector cannot
    quietly regress to the weaker check.
    """
    def payload_only(needles):
        return {n: (["app/assets/logo.png"] if n == H.KEY_TOKEN else []) for n in needles}

    e = _evidence(tmp_path, "a_symlink_walks_a_private_key_into_the_payload",
                  scan=payload_only)
    outcome, msg = H.verdict_symlinked_key(e)
    assert outcome == "SMUGGLED", (outcome, msg)
    assert H.KEY_TOKEN in msg and "logo.png" in msg


def test_a_clean_artifact_is_contained(tmp_path):
    e = _evidence(tmp_path, "a_symlink_walks_a_private_key_into_the_payload")
    assert H.verdict_symlinked_key(e)[0] == "CONTAINED"


def test_a_marker_in_the_drop_is_an_escape(tmp_path):
    """Execution on the build host, unannounced, is ESCAPED; announced, it is SANCTIONED."""
    name = "a_build_backend_owns_the_build_host"
    e = _evidence(tmp_path, name)
    assert H.verdict_build_backend(e)[0] == "CONTAINED"

    H.marker(e.drop, name).write_text("")
    assert H.verdict_build_backend(e)[0] == "ESCAPED"


def test_a_named_bundle_step_is_sanctioned_and_a_silent_one_is_not(tmp_path):
    name = "a_bundle_step_runs_unannounced_on_the_build_host"
    silent = _evidence(tmp_path, name, log="build complete")
    H.marker(silent.drop, name).write_text("")
    assert H.verdict_bundle_step(silent)[0] == "ESCAPED"

    named = _evidence(tmp_path, name, log="bundle step: python -c ...\nbuild complete")
    H.marker(named.drop, name).write_text("")
    assert H.verdict_bundle_step(named)[0] == "SANCTIONED"


def test_post_install_is_smuggled_only_when_the_log_is_silent(tmp_path):
    name = "a_post_install_step_ships_code_to_the_customer"
    shipped = {H.SHIPPED_TOKEN: ["manifest.toml"]}

    silent = _evidence(tmp_path, name, log="build complete",
                       scan=lambda ns: {n: shipped.get(n, []) for n in ns})
    assert H.verdict_post_install(silent)[0] == "SMUGGLED"

    warned = _evidence(tmp_path, name, log="WARNING: 1 post_install step(s) will run",
                       scan=lambda ns: {n: shipped.get(n, []) for n in ns})
    assert H.verdict_post_install(warned)[0] == "SANCTIONED"


@pytest.mark.parametrize("member,expected", [
    ("app/..\\..\\Startup\\evil.bat", "SMUGGLED"),
    ("app/data/../../escape.txt", "SMUGGLED"),
    ("app/assets/logo.png", "CONTAINED"),
])
def test_separator_ambiguous_member_names_are_caught(tmp_path, member, expected):
    e = _evidence(tmp_path, "a_filename_escapes_the_payload_on_windows",
                  members=[(member, b"x")])
    assert H.verdict_windows_escape(e)[0] == expected


def test_marker_names_match_their_attack_keys(tmp_path):
    """The bug that hid a build-host escape: two halves of one string, spelled separately.

    `Evidence.escaped()` looks for `escaped-<case name>`. A hostile program that writes
    `escaped-build_backend` while the case is called
    `a_build_backend_owns_the_build_host` executes on the build host and is scored
    CONTAINED, because nothing looks for the file it wrote.
    """
    import re

    for name, spec in H.ATTACKS.items():
        proj = tmp_path / f"k-{name}"
        spec["plant"](proj, H.planted_home(tmp_path / f"h-{name}"))
        for f in proj.rglob("*"):
            if f.is_symlink() or not f.is_file():
                continue
            try:
                body = f.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            for written in re.findall(r"escaped-([A-Za-z0-9_]+)", body):
                assert written == name, (
                    f"{name} plants a marker called escaped-{written}, which "
                    f"Evidence.escaped() will never look for")


def test_a_refused_build_is_not_a_pass(tmp_path):
    """Every detector must distinguish 'the attack did not land' from 'nothing was built'."""
    for name, spec in H.ATTACKS.items():
        e = _evidence(tmp_path / name.replace("/", "_"), name, rc=1, blob=b"",
                      log="haru-pack: refused")
        e.exe.unlink(missing_ok=True)
        outcome, _ = spec["verdict"](e)
        assert outcome in ("REFUSED", "CONTAINED", "ESCAPED"), (name, outcome)


def test_the_hostile_snippet_writes_only_into_the_drop(tmp_path):
    """The safety rule, enforced rather than asserted in a docstring.

    The marker snippet is the ONLY code these programs run. Executing it with TMPDIR
    redirected must produce exactly one file, inside the redirect.
    """
    import subprocess

    drop = tmp_path / "drop"
    drop.mkdir()
    snippet = H.MARKER_SNIPPET.format(name="unit_test")
    subprocess.run([sys.executable, "-c", snippet], check=True,
                   env={"PATH": "/usr/bin:/bin", "TMPDIR": str(drop)})
    assert [p.name for p in drop.iterdir()] == ["escaped-unit_test"]

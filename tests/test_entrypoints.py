"""INV-BUILD-03 — haru-pack refuses to guess which program to build.

The bug this replaces: `discovery.discover` did

    entrypoint = [next(iter(scripts))] if scripts else [...]

which silently picked an arbitrary dict key when a project declared more than one console
script. A project with `serve` and `migrate` got a coin flip, no warning, and a binary that
builds cleanly and runs the wrong program. That failure surfaces at the customer, not at
the build — which is what makes guessing worse than refusing.
"""
from __future__ import annotations

import pytest

from haru_pack.discovery import AmbiguousProject, discover
from haru_pack.entrypoints import EntryPointError, argv_for_object_ref, resolve_entrypoint


def _pyproject(d, body: str):
    (d / "pyproject.toml").write_text(body)
    return d


# ---------------------------------------------------------------- unambiguous cases

@pytest.mark.invariant("INV-BUILD-03")
def test_a_single_console_script_is_the_answer(tmp_path):
    """The lotek shape: a noisy root, one declared script. That script is the artifact."""
    _pyproject(tmp_path, '[project]\nname = "lotek"\nrequires-python = ">=3.14"\n'
                         '[project.scripts]\nlotek = "app.cli:main"\n')
    for noise in ("lotek_runner.py", "call_graph.py", "swap_xsl.py", "conftest.py"):
        (tmp_path / noise).write_text("# a helper, not the program\n")

    d = discover(tmp_path)
    assert d["entrypoint"] == ["lotek"], (
        "root .py files must not be entrypoint candidates once [project.scripts] exists — "
        "in a real tree they are helpers the console script invokes"
    )
    assert d["kind"] == "project"
    assert d["python"] == "3.14"


@pytest.mark.invariant("INV-BUILD-03")
def test_a_lone_script_still_just_works(tmp_path):
    (tmp_path / "hello.py").write_text("print('hi')\n")
    assert discover(tmp_path)["entrypoint"] == ["hello.py"]
    assert discover(tmp_path / "hello.py")["entrypoint"] == ["hello.py"]


@pytest.mark.invariant("INV-BUILD-03")
def test_no_scripts_table_falls_back_to_dash_m_only_if_the_package_exists(tmp_path):
    _pyproject(tmp_path, '[project]\nname = "my-app"\n')
    (tmp_path / "my_app").mkdir()
    (tmp_path / "my_app" / "__init__.py").write_text("")
    assert discover(tmp_path)["entrypoint"] == ["python", "-m", "my_app"]


# ---------------------------------------------------------------- refusals

@pytest.mark.invariant("INV-BUILD-03")
def test_multiple_console_scripts_refuse_and_list_candidates(tmp_path):
    """Red-path: restore `entrypoint = [next(iter(scripts))]`. This goes green on a guess."""
    _pyproject(tmp_path, '[project]\nname = "multi"\n[project.scripts]\n'
                         'serve = "m.a:main"\nmigrate = "m.b:main"\n')
    with pytest.raises(AmbiguousProject) as ei:
        discover(tmp_path)
    assert sorted(ei.value.candidates) == ["migrate", "serve"], (
        "the operator has to be told what the options were, or the refusal is just a wall"
    )


@pytest.mark.invariant("INV-BUILD-03")
def test_several_loose_scripts_refuse(tmp_path):
    for n in ("a.py", "b.py", "c.py"):
        (tmp_path / n).write_text("")
    with pytest.raises(AmbiguousProject) as ei:
        discover(tmp_path)
    assert set(ei.value.candidates) == {"a.py", "b.py", "c.py"}


@pytest.mark.invariant("INV-BUILD-03")
def test_no_scripts_and_no_importable_package_refuses(tmp_path):
    """`python -m my_app` is only a defensible guess if `my_app` actually exists."""
    _pyproject(tmp_path, '[project]\nname = "my-app"\n')
    with pytest.raises(AmbiguousProject):
        discover(tmp_path)


# ---------------------------------------------------------------- entry-point spellings

@pytest.mark.invariant("INV-BUILD-04")
def test_object_reference_becomes_runnable_argv():
    argv = argv_for_object_ref("app.cli:main", prog="lotek")
    assert argv[:2] == ["python", "-c"]
    code = argv[2]
    assert "from app.cli import main as _o" in code
    assert "raise SystemExit(_o())" in code, (
        "a console script exits with its callable's return value; dropping SystemExit "
        "would turn a non-zero exit code into success"
    )
    assert "sys.argv[0]='lotek'" in code, (
        "python -c leaves argv[0] as '-c', which argparse and click print as the program name"
    )


@pytest.mark.invariant("INV-BUILD-04")
def test_object_reference_runs_for_real(tmp_path):
    """Efficacy: execute the generated argv and check the exit code and argv handling."""
    import subprocess
    import sys

    (tmp_path / "demo.py").write_text(
        "import sys\n"
        "def main():\n"
        "    print('argv0=' + sys.argv[0])\n"
        "    print('args=' + ','.join(sys.argv[1:]))\n"
        "    return 7\n"
    )
    argv = argv_for_object_ref("demo:main", prog="demo-prog")
    r = subprocess.run([sys.executable, argv[1], argv[2], "x", "y"],
                       cwd=tmp_path, capture_output=True, text=True)
    assert r.returncode == 7, f"return value not propagated as exit code: {r.returncode}"
    assert "argv0=demo-prog" in r.stdout
    assert "args=x,y" in r.stdout, f"user args did not reach the callable: {r.stdout!r}"


@pytest.mark.invariant("INV-BUILD-04")
def test_dotted_attribute_is_supported():
    code = argv_for_object_ref("pkg.mod:Cls.run", prog="x")[2]
    assert "from pkg.mod import Cls as _o" in code
    assert "raise SystemExit(_o.run())" in code


@pytest.mark.invariant("INV-BUILD-04")
@pytest.mark.parametrize("bad", ["not a ref!", "mod:", ":func", "mod::func", "", "  "])
def test_malformed_entry_points_are_rejected(bad):
    with pytest.raises(EntryPointError):
        resolve_entrypoint(bad, name="x", kind="project")


@pytest.mark.invariant("INV-BUILD-04")
def test_plain_names_pass_through_untouched():
    assert resolve_entrypoint("hello.py", name="h", kind="script") == ["hello.py"]
    assert resolve_entrypoint("lotek", name="lotek", kind="project") == ["lotek"]
    assert resolve_entrypoint(["python", "-m", "pkg"], name="p", kind="project") == [
        "python", "-m", "pkg"]

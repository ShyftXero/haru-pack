"""INV-BUILD-03 — haru-pack refuses to guess which program to build.

The bug this replaces: `discovery.discover` did

    entrypoint = [next(iter(scripts))] if scripts else [...]

which silently picked an arbitrary dict key when a project declared more than one console
script. A project with `serve` and `migrate` got a coin flip, no warning, and a binary that
builds cleanly and runs the wrong program. That failure surfaces at the customer, not at
the build — which is what makes guessing worse than refusing.
"""
from __future__ import annotations

import textwrap

import pytest

from haru_pack.build import BuildError, _resolve
from haru_pack.discovery import AmbiguousProject, discover
from haru_pack.entrypoints import (EntryPointError, argv_for_object_ref, resolve_entrypoint,
                                   suggest_object_refs, verify_console_script,
                                   verify_object_ref, verify_script_file)


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
def test_no_scripts_table_falls_back_to_dash_m_only_if_the_package_is_executable(tmp_path):
    """Was `..._only_if_the_package_exists`, and asserted the bug.

    It created `my_app/__init__.py` alone and expected `python -m my_app`, which is an argv
    CPython refuses: "'my_app' is a package and cannot be directly executed". Existing is
    not the same as executable — `__main__.py` is what makes `-m` work. Corrected
    2026-09-10 along with `discovery`; the refusal is covered by
    `test_an_importable_but_unexecutable_package_is_refused` below.
    """
    _pyproject(tmp_path, '[project]\nname = "my-app"\n')
    (tmp_path / "my_app").mkdir()
    (tmp_path / "my_app" / "__init__.py").write_text("")
    (tmp_path / "my_app" / "__main__.py").write_text("print('hi')\n")
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


# ------------------------------------------- a well-formed reference that names nothing

def _proj(tmp_path, files: dict, name="demo"):
    """A project tree with a pyproject and whatever modules the test needs."""
    d = tmp_path / "proj"
    d.mkdir(exist_ok=True)
    (d / "pyproject.toml").write_text(
        f"[project]\nname = '{name}'\nversion = '0'\n", encoding="utf-8")
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body), encoding="utf-8")
    return d


@pytest.mark.invariant("INV-BUILD-04")
def test_a_reference_to_a_missing_callable_is_refused(tmp_path):
    """`-e app:mian` used to build cleanly and die on the customer's machine, because the
    generated `python -c "from app import mian"` was never checked against anything."""
    d = _proj(tmp_path, {"app.py": "def serve():\n    pass\n"})
    problem = verify_object_ref("app:mian", d)
    assert problem, "a typo'd callable was accepted"
    assert "defines no `mian`" in problem
    assert "serve" in problem, "the message should name what the module does define"
    with pytest.raises(EntryPointError):
        _resolve(d, "default", "", "", [], "", "", False, False, "app:mian")


@pytest.mark.invariant("INV-BUILD-04")
def test_a_main_guard_is_diagnosed_as_not_being_a_callable(tmp_path):
    """The specific misconception that produces this mistake: `if __name__ == "__main__":`
    is not addressable as `module:callable`. Saying "defines no main" alone would leave the
    operator staring at a file that visibly runs when executed."""
    d = _proj(tmp_path, {"app.py": """
        def helper():
            pass
        if __name__ == "__main__":
            helper()
    """})
    problem = verify_object_ref("app:main", d)
    assert "__main__" in problem and "cannot be imported and called" in problem


@pytest.mark.invariant("INV-BUILD-04")
@pytest.mark.parametrize("spec,body", [
    ("app:main", "def main():\n    pass\n"),
    ("app:main", "async def main():\n    pass\n"),
    ("app:main", "class main:\n    pass\n"),
    ("app:main", "from .impl import main\n"),
    ("app:main", "main = lambda: None\n"),
    ("app:main", "from os import *\n"),
    ("app:Cls.run", "class Cls:\n    def run(self): pass\n"),
])
def test_references_that_do_resolve_are_left_alone(tmp_path, spec, body):
    d = _proj(tmp_path, {"app.py": body})
    assert verify_object_ref(spec, d) == "", f"{spec} with body {body!r} was wrongly refused"


@pytest.mark.invariant("INV-BUILD-04")
def test_a_module_outside_the_project_tree_is_not_second_guessed(tmp_path):
    """The module may come from a dependency. Refusing what we cannot see would make the
    check worse than useless — it would block correct builds."""
    d = _proj(tmp_path, {"app.py": "x = 1\n"})
    assert verify_object_ref("gunicorn.app.wsgiapp:run", d) == ""
    assert verify_object_ref("nope.not_here:main", d) == ""


@pytest.mark.invariant("INV-BUILD-04")
def test_a_src_layout_module_is_found(tmp_path):
    d = _proj(tmp_path, {"src/app/__init__.py": "def go():\n    pass\n"})
    assert verify_object_ref("app:go", d) == ""
    assert "defines no `nope`" in verify_object_ref("app:nope", d)


# ------------------------------------------------ importable is not the same as executable

@pytest.mark.invariant("INV-BUILD-03")
def test_an_importable_but_unexecutable_package_is_refused(tmp_path):
    """`python -m pkg` needs `pkg/__main__.py`. Discovery checked `__init__.py`, so a
    library-shaped package produced an entrypoint that cannot run: "'pkg' is a package and
    cannot be directly executed" — on the target, after a clean build."""
    d = _proj(tmp_path, {"demo/__init__.py": "VALUE = 1\n"})
    with pytest.raises(AmbiguousProject) as e:
        discover(d)
    assert "__main__.py" in str(e.value)
    assert "would fail on the target" in str(e.value)


@pytest.mark.invariant("INV-BUILD-03")
@pytest.mark.parametrize("layout", ["demo", "src/demo"])
def test_a_package_with_a_main_module_is_discovered(tmp_path, layout):
    d = _proj(tmp_path, {f"{layout}/__init__.py": "", f"{layout}/__main__.py": "print(1)\n"})
    assert discover(d)["entrypoint"] == ["python", "-m", "demo"]


# ------------------------------------------------------------- where directives may live

@pytest.mark.invariant("INV-BUILD-07")
def test_directives_can_live_in_pyproject(tmp_path):
    """A project that already has a pyproject.toml should not need a second file to say how
    it is bundled."""
    d = _proj(tmp_path, {"demo/__init__.py": "", "demo/__main__.py": ""})
    (d / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\nversion = '0'\n\n"
        "[tool.haru-pack]\ncwd_policy = 'exe'\nentrypoint = 'demo'\n", encoding="utf-8")
    manifest, _, _, _, _ = _resolve(d, "default", "", "", [], "", "", False, False)
    assert manifest["cwd_policy"] == "exe"
    assert manifest["entrypoint"] == ["demo"]


@pytest.mark.invariant("INV-BUILD-07")
def test_haru_pack_toml_wins_over_pyproject(tmp_path):
    """The sidecar is the local override; the pyproject table is the project's own default."""
    d = _proj(tmp_path, {"demo/__init__.py": "", "demo/__main__.py": ""})
    (d / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\nversion = '0'\n\n"
        "[tool.haru-pack]\ncwd_policy = 'exe'\npython = '3.11'\n", encoding="utf-8")
    (d / "haru_pack.toml").write_text("cwd_policy = 'launch'\n", encoding="utf-8")
    manifest, _, pyver, _, _ = _resolve(d, "default", "", "", [], "", "", False, False)
    assert manifest["cwd_policy"] == "launch", "haru_pack.toml did not win"
    assert pyver == "3.11", "keys only pyproject set must still apply"


@pytest.mark.invariant("INV-BUILD-07")
def test_an_underscored_tool_table_is_refused_not_ignored(tmp_path):
    """A config table nobody reads is worse than a missing one: the operator believes it
    took effect. Red-path: drop the refusal and this build succeeds while ignoring the
    table."""
    d = _proj(tmp_path, {"demo/__init__.py": "", "demo/__main__.py": ""})
    (d / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\nversion = '0'\n\n"
        "[tool.haru_pack]\ncwd_policy = 'exe'\n", encoding="utf-8")
    with pytest.raises(BuildError) as e:
        _resolve(d, "default", "", "", [], "", "", False, False)
    assert "[tool.haru-pack]" in str(e.value)


@pytest.mark.invariant("INV-BUILD-07")
def test_a_cli_flag_still_beats_both(tmp_path):
    d = _proj(tmp_path, {"demo/__init__.py": "", "demo/__main__.py": "",
                         "other.py": "def go():\n    pass\n"})
    (d / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\nversion = '0'\n\n"
        "[tool.haru-pack]\nentrypoint = 'demo'\n", encoding="utf-8")
    (d / "haru_pack.toml").write_text("entrypoint = 'demo'\n", encoding="utf-8")
    manifest, _, _, _, _ = _resolve(d, "default", "", "", [], "", "", False, False,
                                    "other:go")
    assert manifest["entrypoint"][:2] == ["python", "-c"]
    assert "from other import go" in manifest["entrypoint"][2]


# ------------------------------------------------------ console scripts and script files

@pytest.mark.invariant("INV-BUILD-08")
def test_a_missing_script_file_is_refused(tmp_path):
    """The launcher resolves a `.py` token inside the payload, so a filename that is not in
    the tree is a guaranteed runtime failure — and one we can be certain of at build time."""
    d = _proj(tmp_path, {"real.py": "print(1)\n"})
    problem = verify_script_file("nosuch.py", d)
    assert "does not exist" in problem
    assert "real.py" in problem, "the message should name the files that DO exist"
    assert verify_script_file("real.py", d) == ""
    with pytest.raises(EntryPointError):
        _resolve(d, "default", "", "", [], "", "", False, False, "nosuch.py")


@pytest.mark.invariant("INV-BUILD-08")
def test_a_declared_console_script_is_trusted(tmp_path):
    """Trusted without looking in an environment: a `[tool.uv] package = false` project does
    not install its own scripts, and refusing it would be wrong."""
    d = _proj(tmp_path, {})
    (d / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\nversion = '0'\n\n"
        "[project.scripts]\nserve = 'demo:main'\n", encoding="utf-8")
    assert verify_console_script("serve", d) == ("", "")


@pytest.mark.invariant("INV-BUILD-08")
def test_an_unverifiable_console_script_warns_rather_than_refusing(tmp_path):
    """`uv run <name>` resolves scripts from DEPENDENCIES too — gunicorn, flask, celery are
    correct answers absent from [project.scripts]. Refusing them would reject working
    builds, which docs/PRINCIPLES.md counts as an ergonomic failure of its own."""
    d = _proj(tmp_path, {})
    level, msg = verify_console_script("gunicorn", d)
    assert level == "warn", "an unverifiable name must not be a hard refusal"
    assert "--thick" in msg, "the warning should say how to get it checked properly"


@pytest.mark.invariant("INV-BUILD-08")
def test_a_console_script_nothing_provides_is_refused_at_thick(tmp_path):
    """With a real environment the answer is certain, so the warning becomes a refusal."""
    d = _proj(tmp_path, {})
    env = tmp_path / "env"
    (env / "bin").mkdir(parents=True)
    level, msg = verify_console_script("serve", d, env_dir=env)
    assert level == "error"
    assert "command not found" in msg
    # ...and it is silent once the environment actually has it
    (env / "bin" / "serve").write_text("#!/bin/sh\n")
    assert verify_console_script("serve", d, env_dir=env) == ("", "")


@pytest.mark.invariant("INV-BUILD-08")
def test_the_thick_check_is_wired_into_the_build():
    """Red-path: delete the verify_console_script call from `build.thick._warm_on_host`."""
    import inspect
    from haru_pack.build import thick as thick_mod
    src = inspect.getsource(thick_mod._warm_on_host)
    assert "verify_console_script(" in src
    assert "env_dir=tmp_env" in src, (
        "the thick check must look in the env uv just built, or it cannot be certain"
    )


# ------------------------------------------------- a refusal has to say what to type next

@pytest.mark.invariant("INV-BUILD-09")
def test_a_non_executable_package_suggests_its_own_callables(tmp_path):
    """Refusing is correct; refusing with no next step is a wall. The candidates become the
    `--entry-point` line the CLI prints."""
    d = _proj(tmp_path, {"demo/__init__.py": """
        def helper():
            pass
        def main():
            pass
    """})
    with pytest.raises(AmbiguousProject) as e:
        discover(d)
    assert e.value.candidates == ["demo:main", "demo:helper"], (
        "candidates must be real callables, preferred names first, so candidates[0] is a "
        "sensible thing for the CLI to print"
    )


@pytest.mark.invariant("INV-BUILD-09")
def test_private_and_dunder_names_are_not_suggested(tmp_path):
    d = _proj(tmp_path, {"demo/__init__.py": """
        def _internal():
            pass
        def run():
            pass
    """})
    with pytest.raises(AmbiguousProject) as e:
        discover(d)
    assert e.value.candidates == ["demo:run"]


@pytest.mark.invariant("INV-BUILD-09")
def test_preferred_names_are_ordered_first(tmp_path):
    d = _proj(tmp_path, {"app.py": """
        def zzz():
            pass
        def cli():
            pass
        def main():
            pass
    """})
    assert suggest_object_refs("app", d)[:2] == ["app:main", "app:cli"]


@pytest.mark.invariant("INV-BUILD-09")
def test_a_typod_reference_offers_the_real_ones(tmp_path):
    """The other half of the same courtesy: a wrong `module:callable` gets a copy-pasteable
    list rather than only being told it is wrong."""
    d = _proj(tmp_path, {"app.py": "def serve():\n    pass\n"})
    problem = verify_object_ref("app:mian", d)
    assert "--entry-point app:serve" in problem


@pytest.mark.invariant("INV-BUILD-09")
def test_the_cli_prints_a_copy_pasteable_command(tmp_path, capsys):
    from haru_pack.cli import _report_ambiguity
    d = _proj(tmp_path, {"demo/__init__.py": "def main():\n    pass\n"})
    try:
        discover(d)
    except AmbiguousProject as e:
        _report_ambiguity(d, e)
    out = capsys.readouterr().out
    assert "--entry-point demo:main" in out
    assert str(d) in out, "the printed command must be runnable as-is"

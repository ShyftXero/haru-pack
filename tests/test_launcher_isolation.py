"""INV-LAUNCH-07 — a packed binary does not touch the environment of the directory it runs in.

haru-pack's selling point is that a binary behaves "like a compiled program in the folder it
was launched from". The cwd is therefore the user's directory, and `uv` walks UP from its
working directory looking for a project. Put those together and a packed script binary run
inside any Python project adopts that project — and rebuilds its `.venv` against the staged
interpreter.

That is not a corner case. Running a tool inside your own repository is the normal way people
use tools.

Found by busybody on 2026-09-09, destructively: a chaos case whose work directory happened to
sit inside this checkout left `.venv/bin/python` a dangling symlink into a staged tree that
was then deleted. The harness broke the repo it was testing, which is how the bug in the
launcher got noticed at all.

Fix: `uv run --no-project` on the script path. The project path already passes `--project`
explicitly, which pins it.
"""
from __future__ import annotations

from pathlib import Path

import pytest

LAUNCHER = Path(__file__).resolve().parent.parent / "src/haru_pack/launcher/main.nim"


def _run_argv_section() -> str:
    """The part of main.nim that assembles the `uv run` argv."""
    src = LAUNCHER.read_text()
    start = src.index("case m.kind")
    return src[start:start + 2000]


@pytest.mark.invariant("INV-LAUNCH-07")
def test_script_runs_are_isolated_from_an_enclosing_project():
    """Red-path: delete `a.add "--no-project"` from the akScript branch of main.nim.

    Then build any script binary, run it from inside a directory containing a
    pyproject.toml, and watch uv adopt that project's virtualenv. Verified by hand on
    2026-09-09 both ways: without the flag the victim project's .venv/bin/python was
    repointed at the staged interpreter; with it, byte-identical before and after.
    """
    section = _run_argv_section()
    assert '"--no-project"' in section, (
        "the script path no longer passes --no-project to `uv run`. cwd is the user's "
        "launch directory, so uv will discover and modify an enclosing project's venv."
    )
    idx_np = section.index('"--no-project"')
    idx_script = section.index('"--script"')
    assert idx_np < idx_script, "--no-project must precede --script in the argv"


@pytest.mark.invariant("INV-LAUNCH-07")
def test_project_runs_pin_their_project_explicitly():
    """The project path is isolated a different way: it names the project it means.

    Red-path: drop `--project appDir`, and uv falls back to discovery from cwd — the same
    bug by a different route.
    """
    section = _run_argv_section()
    assert '"--project"' in section, (
        "the project path no longer pins --project, so uv discovers one from the cwd"
    )


@pytest.mark.invariant("INV-LAUNCH-07")
def test_busybody_cannot_contaminate_the_tree_it_tests():
    """The harness half of the same lesson.

    busybody runs real binaries, which run uv. Its per-case work directories therefore live
    OUTSIDE the repository, and it strips the variables that make a child adopt the caller's
    Python environment. Red-path: put the work dirs back under busybody/out/ and uv finds
    haru-pack's own pyproject.toml again.
    """
    src = (Path(__file__).resolve().parent.parent / "tools" / "busybody.py").read_text()
    assert "_CONTAMINATING" in src and "VIRTUAL_ENV" in src, (
        "busybody no longer scrubs environment-adopting variables"
    )
    # The single mkdtemp lives in run_one(), which both the parallel and serial passes use.
    # dir=None means $TMPDIR, which is outside the checkout.
    assert 'mkdtemp(prefix=f"bb-{case_name}-",' in src and "dir=work_root_str or None" in src, (
        "busybody's work directories are back inside the repository; uv will discover "
        "haru-pack's own project from them"
    )
    # --work-root was added so a long sweep can escape a quota'd /tmp (INV-CHAOS-05). It is
    # also a new way to point scratch straight back into the repository, so it is refused.
    assert "REPO in WORK_ROOT.parents" in src, (
        "--work-root can aim scratch inside the repo, reinstating the contamination bug"
    )

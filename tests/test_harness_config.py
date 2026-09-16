"""Nothing takes a private copy of a busybody setting that something else rewrites.

Written 2026-09-13 after this exact bug cost an afternoon, and it is worth stating plainly
because the failure is silent and expensive:

`busybody_config` holds a registry (`CASES`) that the `@case` decorators append to and a
test may swap wholesale, four knobs `main()` rewrites from the command line, and three path
roots the tests redirect. Every one of them is REBOUND after import. A module that wrote
`from busybody_config import CASES` froze whichever list existed when it was imported, and
then disagreed with the rest of the harness forever after.

What that looked like in practice: `tests/test_busybody_faults.py` swaps in an empty
catalogue so it can register ONE synthetic case and drive `main()` over it. `busybody_cli`
had imported `CASES` by value, so selection still saw all 80 — and the test quietly started
a real thick sweep, building real binaries, for twenty minutes, while looking like a hang.
Nothing failed. It just did the wrong thing slowly.

The rule is one line: **read a rebindable name as `cfg.NAME`, never import it by value.**
This file is what makes that a rule rather than a comment.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"

# Everything in busybody_config that is assigned to after import — by `main()`, by the
# `@case` decorator, or by a test. Deliberately NOT derived from the module: a name that
# starts being rewritten must be added here by whoever made it mutable, which is the moment
# to notice they have created this hazard.
REBINDABLE = {
    "CASES",              # appended to by @case; swapped wholesale by tests
    "FIXTURE_SOURCES",    # filled by @fixture_source at import
    "CALIBRATOR",         # set by busybody_fixtures at import
    "WORK_ROOT",          # --work-root
    "SCRATCH_CAP_GB",     # --scratch-cap-gb
    "DEFAULT_TIMEOUT_S",  # --timeout
    "HERD_N",             # --herd-n
    "REPO", "OUT", "RUNS",  # redirected by tests
    "BB_REGISTRY",        # the single-instance registry; redirected by tests
}

# The facade is allowed to name them, because it FORWARDS them via module __getattr__
# rather than binding them — see the note at the bottom of tools/busybody.py.
ALLOWED = {"busybody.py", "busybody_config.py"}

MODULES = sorted(p for p in TOOLS.glob("busybody*.py") if p.name not in ALLOWED)


def test_there_are_modules_to_check():
    """A scanner that finds nothing passes every other test in this file."""
    assert len(MODULES) > 10, (
        f"only {len(MODULES)} busybody modules found under {TOOLS}; the glob is wrong"
    )


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_no_module_imports_a_rebindable_setting_by_value(path: Path):
    """Red-path: put `from busybody_config import CASES` back in busybody_cli.py."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.module != "busybody_config":
            continue
        for alias in node.names:
            if alias.name in REBINDABLE:
                bad.append((node.lineno, alias.name))
    assert not bad, (
        f"{path.name} imports rebindable setting(s) by value:\n"
        + "\n".join(f"  line {ln}: {name}" for ln, name in bad)
        + f"\nThese are reassigned after import — by main(), by @case, or by a test — so a "
          f"by-value import freezes the wrong object and the module silently disagrees with "
          f"the rest of the harness. Use `import busybody_config as cfg` and read "
          f"`cfg.{bad[0][1]}`."
    )


def test_the_facade_forwards_rather_than_copies():
    """`bb.CASES` must follow `cfg.CASES`, or a test that swaps the catalogue gets a
    facade that still reports the old one.

    Red-path: re-add `CASES` to busybody.py's `from busybody_config import (...)` line.
    """
    import sys
    if str(TOOLS) not in sys.path:
        sys.path.insert(0, str(TOOLS))
    import busybody as bb
    import busybody_config as cfg

    before = cfg.CASES
    sentinel = [{"name": "_sentinel", "persona": "_none"}]
    try:
        cfg.CASES = sentinel
        assert bb.CASES is sentinel, (
            "busybody.CASES did not follow busybody_config.CASES; the facade is holding a "
            "stale copy and `bb.CASES` lies about what the harness will run"
        )
    finally:
        cfg.CASES = before
    assert bb.CASES is before, "the facade did not follow the restore either"


def test_an_unknown_attribute_still_raises():
    """The forwarding __getattr__ must not turn every typo into a silent None."""
    import sys
    if str(TOOLS) not in sys.path:
        sys.path.insert(0, str(TOOLS))
    import busybody as bb

    with pytest.raises(AttributeError):
        bb.definitely_not_a_real_attribute


# ---------------------------------------------------------------- the frozen layout


def test_paths_is_frozen_and_derived_from_one_place():
    """A run's layout does not change while the run is going, so it is a value.

    `rooted_at` is the only place the conventional `busybody/out/runs` shape is written
    down. Two copies of that arithmetic is how `OUT` and `RUNS` drift into disagreeing
    about where a report went.
    """
    import busybody_config as cfg

    p = cfg.Paths.rooted_at(Path("/somewhere"))
    assert p.out == Path("/somewhere/busybody/out")
    assert p.runs == p.out / "runs"
    with pytest.raises(Exception):
        p.repo = Path("/elsewhere")          # frozen dataclass: FrozenInstanceError


def test_paths_reads_through_the_deprecated_shim(monkeypatch):
    """`monkeypatch.setattr(cfg, "RUNS", tmp)` must still reach converted code.

    This is the whole reason `paths()` builds from the module-level names rather than from
    a cached instance. The shim is deprecated, not dead: it is how every existing test and
    every unconverted reader redirects the harness, and a frozen object that ignored it
    would silently run a test's sweep against the real `busybody/out/runs`.
    """
    import busybody_config as cfg

    monkeypatch.setattr(cfg, "RUNS", Path("/tmp/somewhere-else"))
    assert cfg.paths().runs == Path("/tmp/somewhere-else")


def test_relative_does_not_raise_on_a_path_outside_the_repo():
    """The closing summary prints paths, and `--work-root` is documented as moving them out.

    `Path.relative_to` raises on a path outside the tree, so the naive version turns the
    last line of a SUCCESSFUL run into a traceback the moment someone follows the advice in
    `work_root_report()` and moves scratch off a quota'd filesystem.
    """
    import busybody_config as cfg

    p = cfg.Paths.rooted_at(Path("/repo"))
    assert p.relative(Path("/repo/busybody/out")) == "busybody/out"
    assert p.relative(Path("/mnt/scratch/bb-x")) == "/mnt/scratch/bb-x"


def test_the_sweep_lifecycle_takes_paths_rather_than_reading_the_module():
    """The engine's run path must not ask the module where the repo is.

    Not a style rule. This is the single thing that decides whether the engine can be run
    against a tree that is not haru-pack's own checkout without editing it: a global is a
    fact about THIS repo, an argument is a parameter. The functions listed here are the
    whole lifecycle of a run, and each one already takes the value.
    """
    import inspect

    import busybody_run
    import busybody_sweep

    lifecycle = [busybody_run._sweep, busybody_run._make_fixtures, busybody_run._finalize,
                 busybody_run._summarize, busybody_sweep.compose_sweep,
                 busybody_sweep._finish_compose]
    missing = [f.__name__ for f in lifecycle
               if "paths" not in inspect.signature(f).parameters]
    assert not missing, (
        f"these sweep-lifecycle functions no longer take `paths`: {missing}. They will be "
        f"reading busybody_config's module-level REPO/OUT/RUNS instead, which is the "
        f"deprecated shim — see busybody_config.Paths."
    )
    src = "".join(inspect.getsource(f) for f in lifecycle)
    for name in ("cfg.REPO", "cfg.OUT", "cfg.RUNS"):
        assert name not in src, (
            f"{name} is read inside the sweep lifecycle. Take it from the `paths` argument: "
            f"the layout is fixed for the duration of a run and passing it is what makes the "
            f"engine usable against a tree that is not this checkout."
        )

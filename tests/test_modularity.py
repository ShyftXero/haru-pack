"""INV-MODULARITY-01/02/03 — no module is allowed to become the place everything goes.

There is no allowlist in this file, and adding one would defeat it. An allowlist is how a
size budget becomes a formality: the first exception is always justified, the tenth is
never questioned, and the module it excuses is the one that got too big precisely because
nobody was counting. If a module here is over budget, split it.

The failure messages name the offender, the number, and the shape of the fix, because a
refusal that does not say what to type next is just a wall (docs/PRINCIPLES.md).
"""
from __future__ import annotations

import pytest

from _modularity import (
    CENTRAL_FANOUT,
    CENTRAL_MAX_CODE,
    FUNCTION_MAX_CODE,
    MODULE_MAX_CODE,
    collect_modules,
)

MODULES = collect_modules()


def test_there_are_modules_to_check():
    """A scanner that silently finds nothing passes every other test in this file."""
    assert len(MODULES) > 15, (
        f"_modularity.collect_modules() found only {len(MODULES)} modules. The roots it "
        f"scans have moved; fix ROOTS in tests/_modularity.py or this whole file is vacuous."
    )


@pytest.mark.invariant("INV-MODULARITY-01")
@pytest.mark.parametrize("mod", MODULES, ids=lambda m: m.rel)
def test_module_is_within_its_code_budget(mod):
    """No first-party module carries more than MODULE_MAX_CODE statements."""
    assert mod.code <= MODULE_MAX_CODE, (
        f"{mod.rel} holds {mod.code} statement lines ({mod.physical} physical); the budget "
        f"is {MODULE_MAX_CODE}.\n"
        f"Blank lines, comments and docstrings are already free, so this is {mod.code} lines "
        f"of actual logic in one file. Split it: name the second responsibility it grew and "
        f"move that out. If it is a package-sized subsystem, make it a package — "
        f"`{mod.rel[:-3]}/` with the entry points re-exported from its __init__.py — so "
        f"callers do not have to change."
    )


@pytest.mark.invariant("INV-MODULARITY-02")
@pytest.mark.parametrize("mod", MODULES, ids=lambda m: m.rel)
def test_no_function_is_longer_than_two_screens(mod):
    """A function nobody can see the whole of hides its own control flow."""
    over = [(name, n, line) for name, n, line in mod.functions if n > FUNCTION_MAX_CODE]
    assert not over, (
        f"{mod.rel}: "
        + "; ".join(f"{name}() at line {line} is {n} statements" for name, n, line in over)
        + f" (budget {FUNCTION_MAX_CODE}).\n"
        f"Extract the phases. A long build/dispatch function is usually a sequence of named "
        f"steps that were never given names — pull each into its own function and the caller "
        f"becomes the readable summary of what happens."
    )


@pytest.mark.invariant("INV-MODULARITY-03")
@pytest.mark.parametrize("mod", MODULES, ids=lambda m: m.rel)
def test_no_module_is_both_large_and_central(mod):
    """The actual definition of a god module: a big file that reaches into everything.

    Either half alone is fine and normal. `cli` has to import most of the package to
    dispatch to it; `shake` is 500 lines that import almost nothing. What must not exist is
    the module that is both — the one every change has to be routed through, because it is
    simultaneously the widest and the heaviest thing in the tree.
    """
    if not mod.is_central:
        return
    assert mod.code <= CENTRAL_MAX_CODE, (
        f"{mod.rel} imports {mod.fanout} first-party modules ({', '.join(mod.imports)}) AND "
        f"holds {mod.code} statement lines. Over {CENTRAL_FANOUT} imports it counts as "
        f"central, and a central module's budget is {CENTRAL_MAX_CODE}.\n"
        f"This is the god-module shape. A module is allowed to be the hub OR to hold the "
        f"work, not both: keep the wiring here and push the work down into the modules it "
        f"already imports."
    )

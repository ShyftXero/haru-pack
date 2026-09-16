"""INV-MODULARITY-01/02/03/04 — no module becomes the place everything goes, and
busybody's engine does not depend on busybody's catalogue.

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
    busybody_layer_violations,
    busybody_unclassified,
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


@pytest.mark.invariant("INV-MODULARITY-04")
def test_the_engine_does_not_import_the_catalogue():
    """busybody's engine may not depend on busybody's catalogue of faults.

    The size budgets above cannot express this one. `busybody_run` importing
    `busybody_fixtures` broke no budget — both files were small and neither was central —
    and it still meant the module that drives a sweep held a hard reference into the list
    of ways to break haru-pack. A budget measures how much a module holds; this measures
    which way it points, and only the second says anything about whether the engine could
    ever be lifted out.

    The dependency in the other direction is fine and expected: a case calls `run_exe`, a
    trait registers through `@trait`, and a catalogue that could not reach the engine would
    have nothing to run on.

    The fix is never "move the import inside a function" — that hides the edge from this
    scan without removing it. It is to invert the dependency: let the catalogue REGISTER
    what it offers and have the engine look it up, exactly as `CASES` has always worked and
    as `FIXTURE_SOURCES` now does.
    """
    violations = busybody_layer_violations()
    assert not violations, (
        "busybody's engine imports its catalogue:\n  "
        + "\n  ".join(f"{engine} -> {catalogue}" for engine, catalogue in violations)
        + "\nInvert it. Add a registry to busybody_config that the catalogue writes at "
        "import time and the engine reads by name — `CASES` and `FIXTURE_SOURCES` are both "
        "that shape. Moving the import into a function body would hide this edge from the "
        "scan without removing it, and the engine would still be unextractable."
    )


def test_every_busybody_module_is_on_one_side_or_the_other():
    """A module in neither set is governed by nothing, and the check above would not see it.

    This is the guard-of-guards for the partition: the layering rule is only as complete as
    the classification, and a new `busybody_*.py` that nobody placed would silently sit
    outside the rule while the suite stayed green.
    """
    stray = busybody_unclassified()
    assert not stray, (
        f"these busybody modules are in neither BUSYBODY_ENGINE nor BUSYBODY_CATALOGUE: "
        f"{stray}. Place each one deliberately in tests/_modularity.py — engine if a sweep "
        f"needs it to run at all, catalogue if it declares or builds something specific to "
        f"breaking haru-pack. Leaving it out exempts it from INV-MODULARITY-04."
    )

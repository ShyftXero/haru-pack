"""Every subcommand is still registered, and still reachable.

This file exists because of a failure mode the 2026-09-13 package split introduced
(INV-MODULARITY-01). `cli` used to be one module, so a command could not go missing without
deleting it. It is now a package whose `__init__.py` imports each command module purely so
that the `@app.command()` decorators run — which means a tidy-looking "unused import"
cleanup silently removes a subcommand from `--help`, with no error anywhere, and the first
person to notice is an operator whose script stopped working.

Nothing here tests what the commands DO; the rest of the suite does that. It tests that
they are wired in at all.
"""
from __future__ import annotations

import pytest
from typer.testing import CliRunner

from haru_pack import cli

# The complete surface. Spelled out rather than derived, so that ADDING a command is a
# deliberate edit to this list and REMOVING one cannot happen by accident.
EXPECTED = {"bootstrap", "build", "doctor", "init", "hostname", "verify", "version"}


def _registered() -> set[str]:
    return {c.name or c.callback.__name__.replace("_", "-")
            for c in cli.app.registered_commands}


def test_every_command_is_registered():
    """Red-path: delete `from .doctorcmd import doctor` from cli/__init__.py."""
    missing = EXPECTED - _registered()
    assert not missing, (
        f"these subcommands are no longer registered: {sorted(missing)}.\n"
        f"A command module has to be IMPORTED by haru_pack/cli/__init__.py for its "
        f"@app.command() decorator to run. An import there that looks unused is not."
    )


def test_no_command_appeared_unannounced():
    """The other direction: a new command should be a deliberate line in EXPECTED, so that
    the CLI's surface is reviewed rather than grown."""
    extra = _registered() - EXPECTED
    assert not extra, (
        f"new subcommand(s) {sorted(extra)} are registered but not listed in this test. "
        f"Add them to EXPECTED once they are documented in the README."
    )


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_each_command_has_help(name):
    """`--help` renders for each one. Catches a command whose module imported but whose
    option declarations reference something that is no longer there — the shape of the two
    NameErrors the split actually hit (`KNOWN_TARGETS`)."""
    result = CliRunner().invoke(cli.app, [name, "--help"])
    assert result.exit_code == 0, f"`{name} --help` exited {result.exit_code}:\n{result.output}"
    assert result.output.strip(), f"`{name} --help` printed nothing"


def test_the_bare_form_still_means_build():
    """`haru-pack somescript.py` is the documented simple case, and it is implemented by
    rewriting argv in a TyperGroup subclass rather than by a callback argument. That class
    moved modules in the split; this is the check that it still takes effect."""
    result = CliRunner().invoke(cli.app, ["definitely-not-a-command.py", "--help"])
    # It is dispatched to `build`, so build's help (not a "no such command" error) comes back.
    assert result.exit_code == 0, result.output
    assert "--thick" in result.output or "tier" in result.output.lower(), (
        "the bare `haru-pack <path>` form no longer dispatches to build"
    )

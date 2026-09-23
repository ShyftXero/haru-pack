"""The command-line surface, one module per command.

    root           the Typer app object every command registers itself on
    naming         which of the two console-script names the user typed
    report         the two long explanations (ambiguous project, capabilities)
    buildcmd       `build`'s option surface
    builddriver    the build itself; the bare `haru-pack <path>` form calls it too
    doctorcmd      `doctor`
    bootstrapcmd   `bootstrap`
    inspectcmd     `version`, `verify`, `init`, `hostname`

Importing a command module is what REGISTERS it: the `@app.command()` decorators run at
import time. So the imports below are not tidiness — drop one and its subcommand silently
disappears from `--help`. `test_cli_surface.py` guards that.

This file is a FACADE and must stay one. It re-exports the names `cli.py` exposed before it
became a package, and holds no logic of its own.
"""
from __future__ import annotations

from .buildcmd import build
from .builddriver import _run_build
from .doctorcmd import doctor
from .bootstrapcmd import bootstrap
from .inspectcmd import hostname_cmd, init, keygen, verify, version
from .naming import prog
from .report import _report_ambiguity, _report_capabilities
from .root import app


def main():
    app()


__all__ = [
    "app", "main", "prog",
    "bootstrap", "build", "doctor", "init", "hostname_cmd", "keygen", "verify", "version",
    "_report_ambiguity", "_report_capabilities", "_run_build",
]


if __name__ == "__main__":
    main()

"""The Typer application object, and the one piece of dispatch trickery it needs.

Every command module imports `app` from here and registers itself on it with
`@app.command()`. Keeping the object in a leaf module is what lets the command modules stay
independent of each other: none of them has to import a sibling to be registered, and
`cli/__init__.py` just imports them all so the decorators run.

Split out of cli.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import typer
from typer.core import TyperGroup


class _DefaultToBuild(TyperGroup):
    """Make `haru-pack somescript.py` mean `haru-pack build somescript.py`.

    Implemented at the group level rather than as a callback with a positional argument.
    A positional on the callback competes with subcommand dispatch: click binds the first
    token to it, so `haru-pack version` was parsed as "build the project named 'version'".
    Here the token is only rewritten when it is NOT a registered command and does not look
    like a flag, so every subcommand keeps working untouched.
    """

    def parse_args(self, ctx, args):
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args = ["build"] + args
        return super().parse_args(ctx, args)


app = typer.Typer(add_completion=False, cls=_DefaultToBuild,
                  help="haru-pack — pack a Python project into a single, signable native "
                       "launcher.\n\nThe simple case needs no subcommand: "
                       "`haru-pack somescript.py`.")



"""Terminal output for the CLI — `from .ui import print` and carry on.

The point is `rich`: colour, consistent styling, and sane handling of wide output. The
point of the wrapper, rather than `from rich import print` directly, is one measured fact:

    >>> from rich import print
    >>> print("[project.scripts]")      # prints NOTHING
    >>> print("[[bundle]]")             # prints "[]"

Rich reads `[...]` as style markup, and an unrecognised tag is dropped silently rather than
raising. haru-pack's most important strings are exactly that shape — `[project.scripts]`,
`[tool.haru-pack]`, `[shake]`, `[[bundle]]`, `[sources]` — and they appear in the refusals
whose whole job is telling an operator what to type. Losing them makes the tool look broken
in the one moment the operator most needs it to be clear (`docs/PRINCIPLES.md`, user 2).

So markup is **off by default** and opted into per call:

    print("done", style="ok")                       # styled, literal text
    print("[bold]careful[/bold]", markup=True)       # markup when you mean it

`highlight=False` for the same reason: rich's automatic highlighting recolours anything that
looks like a number, path or URL, which is pretty on a status line and actively confusing
inside a quoted error message. `soft_wrap=True` because these messages are already
hand-wrapped — letting rich re-flow them mangles indented example commands.

Styles are named rather than spelled as colours so "what does a warning look like" is one
edit, not forty.
"""
from __future__ import annotations

from rich.console import Console
from rich.text import Text
from rich.theme import Theme

__all__ = ["print", "console", "STYLES", "fields"]

STYLES = Theme({
    "info": "cyan",          # progress: what the build is doing
    "warn": "yellow",        # it built, but you should know something
    "error": "bold red",     # it did not build
    "ok": "green",           # it worked
    "detail": "dim",         # secondary text nobody needs to read first
    "key": "bold cyan",      # field names in receipts
})

console = Console(theme=STYLES, soft_wrap=True, highlight=False)


def print(*objects, style: str | None = None, markup: bool = False, **kwargs) -> None:
    """`rich`'s print, with markup off unless asked for. Drop-in for `builtins.print`."""
    console.print(*objects, style=style, markup=markup, **kwargs)


def fields(rows, *, title: str = "", keystyle: str = "key") -> None:
    """Print `(name, value)` pairs as coloured `name: value` lines.

    Deliberately NOT a `rich.Table`. `haru-pack verify` is what a CI job runs, and its
    `name: value` shape is an interface — the first version of this rendered a borderless
    table, which dropped the `:` and silently broke anything doing
    `haru-pack verify app | grep 'sha_ok: True'`. Prettier output is not worth changing a
    machine-readable format, so this keeps the exact text and only adds colour.
    """
    rows = [(str(k), "" if v is None else str(v)) for k, v in rows]
    if title:
        console.print(title, style="bold")
    width = max((len(k) for k, _ in rows), default=0)
    for k, v in rows:
        # `Text.append` never parses markup, so a value containing brackets — a Windows
        # path, a version specifier like `[extra]` — survives. Building the line with an
        # f-string and `markup=True` would re-introduce the whole bug this module exists
        # to avoid, one layer down.
        line = Text()
        line.append(f"{k:<{width}}", style=keystyle)
        line.append(f": {v}")
        console.print(line)

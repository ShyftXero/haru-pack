"""INV-UI-01 — nothing haru-pack prints is silently eaten by terminal markup.

The measured hazard, which is why `haru_pack.ui` exists rather than `from rich import
print`:

    >>> from rich import print
    >>> print("[project.scripts]")      # prints NOTHING
    >>> print("[[bundle]]")             # prints "[]"

Rich treats `[...]` as a style tag and drops an unrecognised one without raising. Every
string haru-pack most needs an operator to read is that shape — `[project.scripts]`,
`[tool.haru-pack]`, `[shake]`, `[[bundle]]`, `[sources]` — and they live in the refusals
whose entire job is saying what to type next. Losing them makes the tool look broken at the
exact moment it is trying to be helpful (`docs/PRINCIPLES.md`, user 2).
"""
from __future__ import annotations

import inspect

import pytest

from haru_pack import cli, ui

# Every bracketed literal that appears in a real haru-pack message.
BRACKETED = [
    "[project.scripts]",
    "[tool.haru-pack]",
    "[tool.haru_pack]",
    "[shake]",
    "[sources]",
    "[[bundle]]",
    "[[post_install]]",
    "[encryption]",
    "[dependency-groups]",
    "a path with [brackets] in it",
]


@pytest.mark.invariant("INV-UI-01")
@pytest.mark.parametrize("text", BRACKETED)
def test_bracketed_text_survives_printing(text, capsys):
    """Red-path: change `ui.print`'s default to `markup=True`, or import rich's `print`
    directly in cli.py. Every parametrization here goes red — silently, in production."""
    ui.print(text)
    out = capsys.readouterr().out
    assert text in out, (
        f"{text!r} did not survive printing; rich ate it as markup, which is how an "
        f"operator ends up reading a refusal with the actionable part missing"
    )


@pytest.mark.invariant("INV-UI-01")
def test_rich_would_in_fact_eat_them():
    """The hazard is real, not folklore. If a future rich stops swallowing unknown tags this
    test tells us the wrapper's default could be revisited — it does not license doing so."""
    from io import StringIO

    from rich.console import Console
    c = Console(file=StringIO(), markup=True, highlight=False, soft_wrap=True)
    c.print("[project.scripts]")
    assert "project.scripts" not in c.file.getvalue(), (
        "rich no longer drops unknown markup tags; ui.py's rationale should be re-checked"
    )


@pytest.mark.invariant("INV-UI-01")
def test_markup_is_opt_in_not_opt_out():
    sig = inspect.signature(ui.print)
    assert sig.parameters["markup"].default is False, (
        "ui.print defaults to markup=True; every bracketed literal in the codebase is now "
        "a silent data-loss bug"
    )


@pytest.mark.invariant("INV-UI-01")
def test_the_cli_does_not_import_richs_print_directly():
    """The wrapper is worthless if a call site bypasses it."""
    src = inspect.getsource(cli)
    assert "from rich import print" not in src
    assert "from .ui import print" in src, "cli.py no longer routes output through ui.py"


@pytest.mark.invariant("INV-UI-01")
def test_field_values_containing_brackets_survive(capsys):
    """`fields` builds lines with `rich.Text.append`, which never parses markup. Building
    them with an f-string and `markup=True` would reintroduce the bug one layer down."""
    ui.fields([("path", r"C:\Users\x\[build]\app.exe"), ("ok", True)])
    out = capsys.readouterr().out
    assert "[build]" in out
    assert "ok" in out and "True" in out


@pytest.mark.invariant("INV-UI-01")
def test_fields_keeps_the_colon_separator(capsys):
    """`haru-pack verify`'s `name: value` shape is an interface — a CI job greps it. The
    first version of this rendered a borderless rich table, which dropped the `:` and would
    have broken `haru-pack verify app | grep 'sha_ok: True'`.

    Red-path: render `fields` as a `rich.Table` again.
    """
    ui.fields([("sha_ok", True), ("payload_len", 123)])
    out = capsys.readouterr().out
    assert "sha_ok" in out
    assert ": True" in out, "the key/value separator is gone; verify output is not greppable"
    assert ": 123" in out


@pytest.mark.invariant("INV-UI-01")
def test_styles_are_named_not_spelled(capsys):
    """Semantic names mean "what does a warning look like" is one edit, not forty."""
    for name in ("info", "warn", "error", "ok", "detail", "key"):
        assert name in ui.STYLES.styles, f"style {name!r} is missing from the theme"
    ui.print("hello", style="warn")
    assert "hello" in capsys.readouterr().out

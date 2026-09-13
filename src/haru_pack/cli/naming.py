"""The command name the user actually typed.

Split out of cli.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import re
import sys


def prog() -> str:
    """The command name the user actually typed — `haru-pack` or `haru`.

    Both are real console scripts (see `[project.scripts]`), so a message that hardcodes
    one of them tells half the users to type something other than what they just used.
    Copy-pasteable output is the whole point of those messages (docs/PRINCIPLES.md), and a
    command they did not invoke is one more thing to translate in their head.

    Falls back to `haru-pack` when argv[0] is something unhelpful — `python -m haru_pack`,
    a pytest runner, a frozen launcher.

    Split on BOTH separators rather than with `Path`: `Path(r"C:\\...\\haru.exe").name`
    returns the whole string on POSIX, because a backslash is an ordinary character there.
    That matters because this is a Windows-first tool whose argv[0] is routinely a Windows
    path, and it is the same mistake the vendored decoder's include path made under mingw.
    """
    raw = sys.argv[0] if sys.argv else ""
    name = re.split(r"[\\/]", raw)[-1] if raw else ""
    if name.lower().endswith(".exe"):
        name = name[:-4]
    return name if name in ("haru", "haru-pack") else "haru-pack"

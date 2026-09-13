"""Read first-party source as text, for the handful of tests that assert on WIRING.

A few invariants are about how two things are connected rather than what either one
computes — "the validators are actually called", "obfuscation does not imply encryption".
The cheapest honest check for those is to look at the code, and that is what these helpers
are for.

`build_source()` exists because `haru_pack.build` became a package (2026-09-13,
INV-MODULARITY-01) and those tests previously read one file. Concatenating the package
keeps them asking the question they were written to ask — *is this wired up anywhere in the
build?* — instead of being re-pointed at a new path every time a module is split again.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BUILD_PKG = REPO / "src" / "haru_pack" / "build"


def build_source() -> str:
    """Every module of the `haru_pack.build` package, concatenated, sorted by filename.

    Each file is preceded by a `# ── <name> ──` banner so a failing assertion's context is
    still legible when it is printed.
    """
    parts = []
    for path in sorted(BUILD_PKG.glob("*.py")):
        parts.append(f"\n# ── {path.name} ──\n")
        parts.append(path.read_text(encoding="utf-8"))
    return "".join(parts)


def module_source(dotted: str) -> str:
    """Source of one first-party module, e.g. `haru_pack.build.declare`."""
    path = REPO / "src" / Path(*dotted.split("."))
    return path.with_suffix(".py").read_text(encoding="utf-8")

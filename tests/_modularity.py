"""Measure the shape of every first-party module: how much code it holds, how much of
the package it reaches into, and how long its longest function is.

This is the machinery behind INV-MODULARITY-01/02/03. It is deliberately stdlib-only
(`ast`), because a check that needs a dependency to run is a check CI will one day skip.

Why *code* lines rather than physical lines
------------------------------------------
haru-pack's house style is comment-dense on purpose — the comments are the audit trail
for why a refusal exists, and several of them are cited from INVARIANTS.md. A physical
line cap would tax exactly the thing the repo wants more of, and the cheapest way to pass
it would be to DELETE an explanation. So the budget counts statements: blank lines,
comment lines, and docstrings are free. Write as much prose as the decision deserves.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The trees this invariant governs: the shipped package, and the dev harness that has to
# stay legible for anyone debugging a chaos finding.
#
# `tests/` is deliberately NOT here, and the reason is not squeamishness. A god module is a
# module other code must go THROUGH — the pathology is centrality, and a test module is a
# leaf that nothing imports. Splitting `test_supply_chain.py` in half would move lines
# between files and improve nothing. If a test file ever gets imported by another, it stops
# being a leaf and belongs under this cap.
ROOTS = ("src/haru_pack", "tools")

# ── the budgets ───────────────────────────────────────────────────────────────────────
# Calibrated against this tree on 2026-09-13 rather than picked from the air. At the time
# it was set, MODULE_MAX_CODE=300 named exactly the eight modules a reader would point at
# if asked which files are too big, and cleared everything else — including `toolchain.py`
# (256) and `bundle.py` (251), which are dense but each do one job.
MODULE_MAX_CODE = 300

# A function you cannot see the whole of. 80 statements is roughly 120 physical lines in
# this repo's comment style — about two screens.
FUNCTION_MAX_CODE = 80

# A "god module" is not merely a big file: it is a big file that knows about everything.
# These two numbers together are the actual definition. A module may be central (`cli`
# must import most of the package to dispatch to it) or it may be large (`shake` is a
# self-contained subsystem), but not both — a large central module is the thing no change
# can route around.
CENTRAL_FANOUT = 8
CENTRAL_MAX_CODE = 150


@dataclass
class Module:
    rel: str                 # repo-relative path
    code: int                # statement lines (see module docstring)
    physical: int
    fanout: int              # distinct FIRST-PARTY modules imported
    imports: tuple[str, ...]
    functions: tuple[tuple[str, int, int], ...]   # (name, code_lines, lineno)

    @property
    def is_central(self) -> bool:
        return self.fanout > CENTRAL_FANOUT


def _docstring_lines(tree: ast.AST) -> set[int]:
    """Line numbers occupied by bare string statements, i.e. docstrings."""
    out: set[int] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            out.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return out


def _count_code(lines: list[str], start: int, end: int, docs: set[int]) -> int:
    """Statement lines in the inclusive 1-indexed span [start, end]."""
    n = 0
    for i in range(start, end + 1):
        if i in docs:
            continue
        stripped = lines[i - 1].strip()
        if not stripped or stripped.startswith("#"):
            continue
        n += 1
    return n


def _first_party(node: ast.AST, package_peers: set[str]) -> set[str]:
    """Names this import statement pulls in from THIS project, if any.

    Three shapes count: a relative import (`from . import x`, `from .x import y`), an
    absolute `haru_pack.x`, and — for `tools/`, which is a flat directory of scripts run
    as `__main__` — a plain `import busybody_ledger` that resolves to a sibling file.
    """
    found: set[str] = set()
    if isinstance(node, ast.ImportFrom):
        if node.level:                                  # from . / from .mod
            if node.module:
                found.add(node.module.split(".")[0])
            else:
                found.update(a.name for a in node.names)
        elif node.module and node.module.split(".")[0] == "haru_pack":
            parts = node.module.split(".")
            found.add(parts[1] if len(parts) > 1 else "haru_pack")
        elif node.module and node.module.split(".")[0] in package_peers:
            found.add(node.module.split(".")[0])
    elif isinstance(node, ast.Import):
        for alias in node.names:
            head = alias.name.split(".")[0]
            if head == "haru_pack":
                parts = alias.name.split(".")
                found.add(parts[1] if len(parts) > 1 else "haru_pack")
            elif head in package_peers:
                found.add(head)
    return found


def _scan_file(path: Path, package_peers: set[str]) -> Module | None:
    src = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(src)
    except SyntaxError:                                  # not ours to police
        return None
    lines = src.splitlines()
    docs = _docstring_lines(tree)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imports |= _first_party(node, package_peers)
    imports.discard(path.stem)                           # a module importing itself is not fan-out
    functions = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body_start = node.body[0].lineno
            end = node.end_lineno or body_start
            functions.append((node.name, _count_code(lines, body_start, end, docs), node.lineno))
    return Module(
        rel=path.relative_to(REPO).as_posix(),
        code=_count_code(lines, 1, len(lines), docs),
        physical=len(lines),
        fanout=len(imports),
        imports=tuple(sorted(imports)),
        functions=tuple(functions),
    )


def collect_modules() -> list[Module]:
    """Every first-party module under ROOTS, largest first."""
    out: list[Module] = []
    for root in ROOTS:
        base = REPO / root
        if not base.is_dir():
            continue
        peers = {p.stem for p in base.rglob("*.py")}
        for path in sorted(base.rglob("*.py")):
            mod = _scan_file(path, peers)
            if mod is not None:
                out.append(mod)
    return sorted(out, key=lambda m: -m.code)

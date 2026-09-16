"""Parse INVARIANTS.md and collect the `invariant` markers that claim its entries.

Adopted from lotek's tests/_invariants.py. Kept dependency-free and deliberately
simple: this module is itself the thing that decides whether the invariant scheme is
being honoured, so it must be readable in one sitting.

It answers linkage questions only — which entries exist, and which tests claim them.
Whether a claiming test actually RAN is a different question, asked by the pytest hooks
in `_invariant_execution.py`.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INVARIANTS_MD = REPO / "INVARIANTS.md"

ID_RE = re.compile(r"\bINV-[A-Z]+-\d{2}\b")
HEADING_RE = re.compile(r"^### (INV-[A-Z]+-\d{2})\s*$", re.M)

REQUIRED_FIELDS = ("Statement", "Actors", "Assets", "Red-path", "Source")

# Trees scanned for prose citations of an INV- id (INV-DOC-01).
#
# `tools/` is here because leaving it out was a real hole, not a theoretical one. busybody's
# cases carry `inv=` strings naming the invariant each one governs, and those strings are
# citations in every sense that matters — they are printed in the report, rolled up in the
# ledger, and read by whoever triages a finding. While `tools/` went unscanned they resolved
# to nothing and were checked by nothing. The 2026-09-13 modularity split multiplied the
# files carrying them from one to twelve, which is when it became worth saying out loud.
CITATION_ROOTS = ("src", "docs", "tests", "tools")


class DuplicateInvariantError(ValueError):
    """INVARIANTS.md declares one id under two `### INV-...` headings."""


@dataclass
class Invariant:
    id: str
    status: str
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        return self.status == "active"


def _split_entries(text: str) -> list[tuple[str, str, int]]:
    """Return [(id, body, heading line number)] for every `### INV-...` heading."""
    matches = list(HEADING_RE.finditer(text))
    out = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        out.append((m.group(1), text[m.end():end], text.count("\n", 0, m.start()) + 1))
    return out


def load_invariants(path: Path = INVARIANTS_MD, *,
                    allow_duplicates: bool = False) -> dict[str, Invariant]:
    """Parse INVARIANTS.md into id -> Invariant, refusing a twice-declared id.

    The refusal exists because the silent version of this happened: INVARIANTS.md carried
    two unrelated `### INV-SECRET-02` entries (one about secrets at rest in a shipped
    binary, one about secrets in build artifacts). The return value is a dict keyed by id,
    so the second heading overwrote the first — 113 headings parsed to 112 entries, the
    first Statement was discarded unread, and every check in this suite passed against
    whichever one happened to be last in the file.

    `allow_duplicates=True` parses anyway, last heading winning. It has exactly one caller:
    the contract test, which wants a single named failure pointing at both line numbers
    rather than an import-time exception that takes the other hundred-odd checks with it.
    """
    text = path.read_text(encoding="utf-8")
    out: dict[str, Invariant] = {}
    first_seen: dict[str, int] = {}
    dupes: list[str] = []
    for inv_id, body, lineno in _split_entries(text):
        if inv_id in first_seen:
            dupes.append(f"{inv_id}: declared at line {first_seen[inv_id]}, "
                         f"declared again at line {lineno}")
        else:
            first_seen[inv_id] = lineno
        fields: dict[str, str] = {}
        for line in body.splitlines():
            m = re.match(r"^(Status|Statement|Actors|Assets|Red-path|Source|Note|Territory):\s*(.*)$", line)
            if m:
                fields[m.group(1)] = m.group(2).strip()
        out[inv_id] = Invariant(id=inv_id, status=fields.get("Status", ""), fields=fields)
    if dupes and not allow_duplicates:
        raise DuplicateInvariantError(
            f"{path} declares the same invariant id more than once. Entries are keyed by id, "
            f"so only the last heading survives and the earlier Statement is discarded "
            f"unread — give one of them a new id:\n  " + "\n  ".join(dupes))
    return out


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO))
    except ValueError:            # tmp_path fixtures in the guard-of-guards tests
        return str(p)


def _invariant_ids_in(expr: ast.expr) -> list[str]:
    """The ids named by one `pytest.mark.invariant(...)` expression, or [].

    Matched on the `.mark.invariant` attribute chain, so `from pytest import mark` and an
    aliased import both still resolve. Only literal string arguments count: an id assembled
    at runtime is invisible here, which shows up as the invariant reporting itself
    unclaimed rather than as a claim nobody can trace.
    """
    if not isinstance(expr, ast.Call):
        return []
    fn = expr.func
    if not (isinstance(fn, ast.Attribute) and fn.attr == "invariant"):
        return []
    owner = fn.value
    is_mark = ((isinstance(owner, ast.Attribute) and owner.attr == "mark")
               or (isinstance(owner, ast.Name) and owner.id == "mark"))
    if not is_mark:
        return []
    return [a.value for a in expr.args
            if isinstance(a, ast.Constant) and isinstance(a.value, str) and ID_RE.fullmatch(a.value)]


def collect_markers(tests_dir: Path | None = None) -> dict[str, list[str]]:
    """Map invariant id -> [test file paths that claim it], one entry per claiming def.

    Parsed, not grepped. The regex this replaced matched the marker's TEXT anywhere in a
    test file, so a commented-out marker, one quoted inside a docstring and one in an f-string
    all satisfied the linkage contract identically — `test_invariants_enforced.py` quotes the
    marker syntax twice in its own prose, and would have credited itself for whatever id those
    quotes named. `ast.parse` sees decorators on real defs and module/class `pytestmark`
    assignments, and nothing else.

    A test file that does not parse now raises SyntaxError out of here instead of quietly
    contributing no claims, which is the inverse of what the regex did with it.

    What this still does not prove is that a claiming test RUNS. That is the job of
    `_invariant_execution.py`; linkage alone was satisfied by five invariants whose every
    claimant skipped.
    """
    tests_dir = tests_dir or (REPO / "tests")
    out: dict[str, list[str]] = {}
    for p in sorted(tests_dir.rglob("test_*.py")):
        found: list[tuple[int, str]] = []
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"), filename=str(p))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for dec in node.decorator_list:
                    found += [(node.lineno, i) for i in _invariant_ids_in(dec)]
            elif isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets):
                marks = (node.value.elts if isinstance(node.value, (ast.List, ast.Tuple))
                         else [node.value])
                for mark in marks:
                    found += [(node.lineno, i) for i in _invariant_ids_in(mark)]
        for _lineno, inv_id in sorted(found):
            out.setdefault(inv_id, []).append(_rel(p))
    return out


def collect_citations() -> dict[str, list[str]]:
    """Map every INV- id mentioned in tracked prose/source -> [file paths].

    INVARIANTS.md itself is excluded; it is the definition, not a citation.
    """
    out: dict[str, list[str]] = {}
    paths: list[Path] = [p for p in REPO.glob("*.md") if p.name != "INVARIANTS.md"]
    for root in CITATION_ROOTS:
        d = REPO / root
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*")):
            if p.is_file() and p.suffix in {".py", ".md", ".nim", ".toml", ".yml", ".yaml"}:
                paths.append(p)
    for p in paths:
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for m in ID_RE.finditer(text):
            out.setdefault(m.group(0), []).append(_rel(p))
    return out

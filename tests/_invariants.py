"""Parse INVARIANTS.md and collect the `invariant` markers that claim its entries.

Adopted from lotek's tests/_invariants.py. Kept dependency-free and deliberately
simple: this module is itself the thing that decides whether the invariant scheme is
being honoured, so it must be readable in one sitting.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INVARIANTS_MD = REPO / "INVARIANTS.md"

ID_RE = re.compile(r"\bINV-[A-Z]+-\d{2}\b")
HEADING_RE = re.compile(r"^### (INV-[A-Z]+-\d{2})\s*$", re.M)
MARKER_RE = re.compile(r"""@pytest\.mark\.invariant\(\s*["'](INV-[A-Z]+-\d{2})["']""")

REQUIRED_FIELDS = ("Statement", "Actors", "Assets", "Red-path", "Source")

# Trees scanned for prose citations of an INV- id (INV-DOC-01).
CITATION_ROOTS = ("src", "docs", "tests")


@dataclass
class Invariant:
    id: str
    status: str
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        return self.status == "active"


def _split_entries(text: str) -> list[tuple[str, str]]:
    """Return [(id, body)] for every `### INV-...` heading in the document."""
    matches = list(HEADING_RE.finditer(text))
    out = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        out.append((m.group(1), text[m.end():end]))
    return out


def load_invariants(path: Path = INVARIANTS_MD) -> dict[str, Invariant]:
    text = path.read_text(encoding="utf-8")
    out: dict[str, Invariant] = {}
    for inv_id, body in _split_entries(text):
        fields: dict[str, str] = {}
        for line in body.splitlines():
            m = re.match(r"^(Status|Statement|Actors|Assets|Red-path|Source|Note|Territory):\s*(.*)$", line)
            if m:
                fields[m.group(1)] = m.group(2).strip()
        out[inv_id] = Invariant(id=inv_id, status=fields.get("Status", ""), fields=fields)
    return out


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO))
    except ValueError:            # tmp_path fixtures in the guard-of-guards tests
        return str(p)


def collect_markers(tests_dir: Path | None = None) -> dict[str, list[str]]:
    """Map invariant id -> [test file paths that claim it]."""
    tests_dir = tests_dir or (REPO / "tests")
    out: dict[str, list[str]] = {}
    for p in sorted(tests_dir.rglob("test_*.py")):
        for m in MARKER_RE.finditer(p.read_text(encoding="utf-8")):
            out.setdefault(m.group(1), []).append(_rel(p))
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

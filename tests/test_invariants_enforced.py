"""The linkage contract: INVARIANTS.md and the test suite must agree.

This does NOT prove any invariant holds. It proves that every `active` invariant is
*claimed* by a test, that every `proposed` one is honestly unclaimed, and that no file
in the repo cites an invariant id that was never declared. Efficacy is the Red-path's
job, and the Red-path is checked by a human neutralizing the guard and watching it go red.

Adopted from lotek's tests/test_invariants_enforced.py.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from _invariants import (
    INVARIANTS_MD,
    REPO,
    REQUIRED_FIELDS,
    Invariant,
    collect_citations,
    collect_markers,
    load_invariants,
)

INVARIANTS = load_invariants()
MARKERS = collect_markers()


def test_invariants_file_parses():
    assert INVARIANTS, f"no invariant entries parsed out of {INVARIANTS_MD}"


@pytest.mark.parametrize("inv_id", sorted(INVARIANTS))
def test_entry_is_well_formed(inv_id: str):
    inv = INVARIANTS[inv_id]
    assert inv.status in {"active", "proposed"}, (
        f"{inv_id}: Status must be 'active' or 'proposed', got {inv.status!r}"
    )
    missing = [f for f in REQUIRED_FIELDS if not inv.fields.get(f)]
    assert not missing, f"{inv_id}: missing required field(s): {', '.join(missing)}"
    if inv.is_active:
        assert inv.fields.get("Territory"), (
            f"{inv_id} is active but declares no Territory. An active invariant must say "
            f"where its behavior lives, or a reviewer cannot tell which diffs touch it."
        )


@pytest.mark.parametrize("inv_id", sorted(i for i, v in INVARIANTS.items() if v.is_active))
def test_active_invariant_is_claimed_by_a_test(inv_id: str):
    """An `active` invariant with no claiming test is a prose promise. That is the
    exact failure this whole scheme exists to prevent."""
    assert MARKERS.get(inv_id), (
        f"{inv_id} is marked active but no test carries "
        f'@pytest.mark.invariant("{inv_id}"). Either write the test, or change the '
        f"Status to 'proposed' and be honest that the behavior is not defended."
    )


@pytest.mark.parametrize("inv_id", sorted(i for i, v in INVARIANTS.items() if not v.is_active))
def test_proposed_invariant_is_not_claimed(inv_id: str):
    """A `proposed` invariant that has a claiming test is worse than an unclaimed one:
    it reads as covered while the entry says it is not. Resolve the contradiction."""
    claimants = MARKERS.get(inv_id, [])
    assert not claimants, (
        f"{inv_id} is 'proposed' but claimed by {claimants}. If the behavior is now "
        f"implemented and tested, promote the entry to 'active'."
    )


def test_every_marker_names_a_real_invariant():
    unknown = {k: v for k, v in MARKERS.items() if k not in INVARIANTS}
    assert not unknown, f"tests claim invariants that do not exist in INVARIANTS.md: {unknown}"


@pytest.mark.invariant("INV-DOC-01")
def test_every_cited_invariant_id_resolves():
    """lotek added this scanner after finding a modularity invariant cited across seven
    source files and five plans docs without ever having been declared.

    (Deliberately no literal id in this docstring — the scanner would flag it. It flagged
    the first draft of this very docstring, which is the cheapest possible demonstration
    that it works.)
    """
    citations = collect_citations()
    dangling = {k: v for k, v in citations.items() if k not in INVARIANTS}
    assert not dangling, (
        "these INV- ids are cited in the repo but declared nowhere in INVARIANTS.md: "
        f"{dangling}"
    )


VERIFIED_HEADING = re.compile(r"^#+\s*(?:Verified|Validated)\b.*$", re.M | re.I)


@pytest.mark.invariant("INV-DOC-02")
def test_verification_claims_name_their_evidence():
    """A dated 'Verified'/'Validated' section must cite an invariant id.

    This is the anti-hallucination control. Writing "Validated: the launcher verifies its
    payload sha256" costs nothing and was, in this repo, false at the moment it was
    written. Requiring an INV- reference forces the claim to point at something a reader
    can execute.
    """
    offenders = []
    docs = [p for p in (REPO / "docs").rglob("*.md")] + list(REPO.glob("*.md"))
    for p in docs:
        if p.name == "INVARIANTS.md":
            continue
        text = p.read_text(encoding="utf-8")
        for m in VERIFIED_HEADING.finditer(text):
            # look at the section body: heading -> next heading or EOF
            start = m.end()
            nxt = re.search(r"^#+\s", text[start:], re.M)
            body = text[start:start + nxt.start()] if nxt else text[start:]
            if not re.search(r"\bINV-[A-Z]+-\d{2}\b", body):
                offenders.append(f"{p.relative_to(REPO)}: {m.group(0).strip()!r}")
    assert not offenders, (
        "verification claims with no invariant reference (prose evidence is satisfiable "
        f"by a claim — name the test): {offenders}"
    )


# Synthetic ids are assembled at runtime so the literal never appears in this file —
# otherwise the citation scanner above would flag this module's own fixtures as dangling
# references. (It did, on the first run. The scanner works.)
def _fake(n: int) -> str:
    return "INV-" + "FAKE-" + f"{n:02d}"


class TestGuardCanFail:
    """Guard-of-guards: feed the linkage checker synthetic violating input and confirm
    it actually rejects it. Without this, a parser bug that silently returns {} would
    make every check above pass vacuously."""

    def test_missing_claim_is_detected(self, tmp_path: Path):
        fid = _fake(1)
        md = tmp_path / "INVARIANTS.md"
        md.write_text(
            f"### {fid}\nStatus: active\nStatement: x\nActors: x\nAssets: x\n"
            "Red-path: x\nSource: x\nTerritory: x\n",
            encoding="utf-8",
        )
        parsed = load_invariants(md)
        assert parsed[fid].is_active
        assert not collect_markers(tmp_path).get(fid), (
            "collect_markers found a claim in a directory containing no tests"
        )

    def test_malformed_entry_is_detected(self, tmp_path: Path):
        fid = _fake(2)
        md = tmp_path / "INVARIANTS.md"
        md.write_text(f"### {fid}\nStatus: active\nStatement: x\n", encoding="utf-8")
        inv = load_invariants(md)[fid]
        missing = [f for f in REQUIRED_FIELDS if not inv.fields.get(f)]
        assert missing == ["Actors", "Assets", "Red-path", "Source"], (
            f"the well-formedness check would not have caught this entry: {missing}"
        )

    def test_marker_regex_actually_matches(self, tmp_path: Path):
        fid = _fake(3)
        t = tmp_path / "test_synthetic.py"
        t.write_text(f'@pytest.mark.invariant("{fid}")\ndef test_x(): pass\n', encoding="utf-8")
        assert fid in collect_markers(tmp_path), (
            "the marker regex no longer matches the marker syntax the suite uses — every "
            "linkage check above would pass vacuously"
        )

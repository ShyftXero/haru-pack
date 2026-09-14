"""The linkage contract: INVARIANTS.md and the test suite must agree.

This does NOT prove any invariant holds. It proves that every `active` invariant is
*claimed* by a test, that every `proposed` one is honestly unclaimed, and that no file
in the repo cites an invariant id that was never declared. Efficacy is the Red-path's
job, and the Red-path is checked by a human neutralizing the guard and watching it go red.

Adopted from lotek's tests/test_invariants_enforced.py.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from _invariants import (
    ID_RE,
    INVARIANTS_MD,
    REPO,
    REQUIRED_FIELDS,
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


def _catalogue() -> tuple[list, dict]:
    """busybody's registered cases and traits, loaded the way the harness loads them.

    The registry, not a text scan: `@case(...)` and `@trait(...)` run at import and append to
    `busybody_config.CASES` / `busybody_compose.TRAITS`, so this is the citation set the
    report, the ledger and `--triage` will actually print. A regex over the source would also
    match a commented-out case or miss one built by a loop.
    """
    import importlib.util

    tools = REPO / "tools"
    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))
    spec = importlib.util.spec_from_file_location("busybody", tools / "busybody.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    import busybody_compose
    import busybody_config
    return list(busybody_config.CASES), dict(busybody_compose.TRAITS)


@pytest.mark.invariant("INV-DOC-01")
def test_every_case_inv_citation_resolves():
    """A case's `inv=` must name declared invariants, or name nothing at all.

    This is the half of the linkage contract that neither repo had. `collect_citations`
    proves that an id APPEARING in a file is real; it cannot prove that the specific field
    busybody prints under "INVARIANT" in every report is a citation rather than prose. Two
    distinct failures are caught here:

      * an `inv=` naming an id that was never declared — a report sends its reader to an
        entry that does not exist;
      * an `inv=` that is non-empty but contains no id at all (`inv="see THREAT_MODEL.md"`
        was real, and shipped) — a case that looks governed and is not. Cite an id, or leave
        the field empty and put the pointer in `why`/`remedy` where prose belongs.

    Traits are held to the same rule: `_stack_record` folds their `inv` values into the same
    ledger field, so a composed finding cites them identically.

    The reverse check — every declared invariant has a covering case — is deliberately NOT
    here. It would fail loudly today and it is a scoping conversation, not a fix.
    """
    cases, traits = _catalogue()
    entries = ([(f"case {c['name']}", c.get("inv", "")) for c in cases]
               + [(f"trait {n}", t.get("inv", "")) for n, t in traits.items()])
    offenders = []
    for label, value in entries:
        value = (value or "").strip()
        if not value:
            continue
        ids = ID_RE.findall(value)
        if not ids:
            offenders.append(f"{label}: inv={value!r} cites no INV- id at all")
            continue
        for inv_id in ids:
            if inv_id not in INVARIANTS:
                offenders.append(f"{label}: inv={value!r} names undeclared {inv_id}")
    assert not offenders, (
        "busybody catalogue entries carry `inv=` citations that resolve to nothing. Every "
        "one of these is printed under INVARIANT in a report and rolled up in the ledger, so "
        "a reader is being sent somewhere that does not exist:\n  "
        + "\n  ".join(offenders)
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

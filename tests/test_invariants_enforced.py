"""The linkage contract: INVARIANTS.md and the test suite must agree.

This does NOT prove any invariant holds. It proves that every `active` invariant is
*claimed* by a test, that every `proposed` one is honestly unclaimed, and that no file
in the repo cites an invariant id that was never declared. Efficacy is the Red-path's
job, and the Red-path is checked by a human neutralizing the guard and watching it go red.

One thing beyond linkage is checked, by the hooks in `_invariant_execution.py` that this
module registers: a claimant that only ever gets SKIPPED does not count as a claim. That
is weaker than proof, and stronger than what was here before — a regex over test source,
which could not tell a running test from a commented-out one.

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
    DuplicateInvariantError,
    Invariant,
    collect_citations,
    collect_markers,
    load_invariants,
)

# `_invariant_execution` records which claiming tests actually ran and fails the session when
# an active invariant's claimants all skipped. Registered from here rather than from
# conftest.py so the invariant machinery stays together, and because a session that never
# collects this module has no contract to enforce anyway.
# `test_the_execution_hooks_are_registered` below is what notices if this line stops working.
pytest_plugins = ["_invariant_execution"]

# `allow_duplicates=True` on purpose: a duplicated id is a real defect, but raising it at
# import time would turn one problem into a collection error that takes all ~110 other checks
# with it. `test_no_invariant_id_is_declared_twice` is where it is refused, as one legible
# failure naming both line numbers.
INVARIANTS = load_invariants(allow_duplicates=True)
MARKERS = collect_markers()


def test_invariants_file_parses():
    assert INVARIANTS, f"no invariant entries parsed out of {INVARIANTS_MD}"


def test_no_invariant_id_is_declared_twice():
    """Entries are keyed by id, so a second heading with the same id overwrites the first.

    This is not hypothetical: INVARIANTS.md carried two unrelated `### INV-SECRET-02`
    entries, 113 headings parsed to 112, and the earlier Statement was discarded unread
    while ten markers were credited to the survivor. Nothing in this file noticed, because
    every check ran against the parsed dict.
    """
    try:
        load_invariants()
    except DuplicateInvariantError as e:
        pytest.fail(str(e))


def test_the_execution_hooks_are_registered(pytestconfig):
    """The skipped-claimant check is only installed by the `pytest_plugins` line above.

    If a future pytest stops honouring `pytest_plugins` in a test module, that check stops
    running and every other test in this file still passes — which is the same silent
    vacuity the check exists to prevent. Fail loudly instead; move the hooks to
    tests/conftest.py if this ever goes red.
    """
    assert pytestconfig.pluginmanager.get_plugin("_invariant_execution") is not None, (
        "_invariant_execution is not registered, so no invariant's claimants are being "
        "watched for execution. See the pytest_plugins line at the top of this module."
    )


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

    def test_marker_decorator_is_recognised(self, tmp_path: Path):
        fid = _fake(3)
        t = tmp_path / "test_synthetic.py"
        t.write_text(f'@pytest.mark.invariant("{fid}")\ndef test_x(): pass\n', encoding="utf-8")
        assert fid in collect_markers(tmp_path), (
            "collect_markers no longer recognises the marker syntax the suite uses — every "
            "linkage check above would pass vacuously"
        )

    def test_module_level_pytestmark_claim_is_recognised(self, tmp_path: Path):
        """`pytestmark = pytest.mark.invariant(...)` claims every test in the module, and two
        files in this suite already use `pytestmark` for skipif, so the form will turn up."""
        fid = _fake(4)
        t = tmp_path / "test_synthetic_modmark.py"
        t.write_text(f'pytestmark = [pytest.mark.invariant("{fid}")]\ndef test_x(): pass\n',
                     encoding="utf-8")
        assert fid in collect_markers(tmp_path)

    def test_a_marker_that_is_not_code_is_not_a_claim(self, tmp_path: Path):
        """Commented out, or quoted in prose, is not a claim.

        collect_markers used to be a regex over file TEXT, so all three of these satisfied
        the linkage contract identically: an invariant could be "claimed" by a decorator
        someone commented out while debugging, and the contract stayed green. This module
        itself quotes the marker syntax twice in its own strings, and escaped being credited
        for them only because the id in those quotes is an f-string placeholder.
        """
        real, commented, quoted = _fake(5), _fake(6), _fake(7)
        t = tmp_path / "test_synthetic_prose.py"
        t.write_text(
            f'"""Docs sometimes quote @pytest.mark.invariant("{quoted}") as an example."""\n'
            f'# @pytest.mark.invariant("{commented}")\n'
            f'@pytest.mark.invariant("{real}")\n'
            'def test_x(): pass\n',
            encoding="utf-8",
        )
        found = collect_markers(tmp_path)
        assert real in found, "a real decorator stopped being credited"
        assert commented not in found, "a commented-out marker was credited as a claim"
        assert quoted not in found, "a marker quoted inside a docstring was credited as a claim"

    def test_duplicate_id_is_detected(self, tmp_path: Path):
        """The parser must refuse two headings with one id, naming both line numbers.

        A dict cannot hold both, so the survivor answers for a Statement it was never
        written for. INVARIANTS.md shipped in that state.
        """
        fid = _fake(8)
        md = tmp_path / "INVARIANTS.md"
        md.write_text(f"### {fid}\nStatus: active\nStatement: first\n\n"
                      f"### {fid}\nStatus: active\nStatement: second\n", encoding="utf-8")
        lax = load_invariants(md, allow_duplicates=True)
        assert lax[fid].fields["Statement"] == "second", (
            "the lax parse no longer drops the earlier entry, so this guard is demonstrating "
            "nothing — check that the loader still keys entries by id"
        )
        with pytest.raises(DuplicateInvariantError) as exc:
            load_invariants(md)
        msg = str(exc.value)
        assert fid in msg and "line 1" in msg and "line 5" in msg, (
            f"the refusal must name the id and both heading lines, or it does not say what to "
            f"fix: {msg!r}"
        )


@pytest.fixture(scope="module")
def unexecuted_active_claims():
    """The execution check's decision function, imported here rather than at the top of the
    module.

    A top-level import would pull `_invariant_execution` in before pytest gets to register
    it as a plugin, and pytest then warns on every single run of this suite that it can no
    longer rewrite that module's asserts.
    """
    from _invariant_execution import unexecuted_active_claims as fn
    return fn


class TestSkippedClaimIsNotAClaim:
    """Guard-of-guards for the execution check in `_invariant_execution.py`.

    It is driven through its pure decision function rather than by nesting a pytest session
    inside a test: what the hooks add is bookkeeping, and what can be wrong is the rule.
    """

    def _active(self, fid: str) -> dict:
        return {fid: Invariant(id=fid, status="active")}

    def test_all_claimants_skipped_is_reported(self, unexecuted_active_claims):
        fid = _fake(9)
        claims = {fid: {"tests/test_x.py::test_a", "tests/test_x.py::test_b"}}
        assert unexecuted_active_claims(claims, set(), self._active(fid)) == {
            fid: ["tests/test_x.py::test_a", "tests/test_x.py::test_b"]
        }, "an active invariant whose every claimant skipped was not reported"

    def test_one_executed_claimant_is_enough(self, unexecuted_active_claims):
        fid = _fake(10)
        claims = {fid: {"tests/test_x.py::test_a", "tests/test_x.py::test_b"}}
        executed = {"tests/test_x.py::test_b"}
        assert unexecuted_active_claims(claims, executed, self._active(fid)) == {}, (
            "one claimant that ran is enough; demanding all of them would fail every "
            "invariant that has a platform-specific test"
        )

    def test_proposed_invariant_is_not_judged(self, unexecuted_active_claims):
        """A `proposed` entry is honestly undefended; `test_proposed_invariant_is_not_claimed`
        is what has an opinion about it."""
        fid = _fake(11)
        claims = {fid: {"tests/test_x.py::test_a"}}
        invs = {fid: Invariant(id=fid, status="proposed")}
        assert unexecuted_active_claims(claims, set(), invs) == {}

    def test_an_invariant_nobody_selected_is_not_judged(self, unexecuted_active_claims):
        """`pytest tests/test_ui.py` must not fail over the hundred invariants it never
        selected. The cost is the blind spot documented on unexecuted_active_claims."""
        fid = _fake(12)
        assert unexecuted_active_claims({}, set(), self._active(fid)) == {}

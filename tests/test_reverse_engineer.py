"""INV-SECRET-02 — the honest limit of packing a secret.

Encryption protects the payload AT REST in the distributed binary. It cannot protect a secret
from someone who RUNS the binary: the launcher stages plaintext to disk so the interpreter can
run it, and the running user owns that plaintext. These guard the vocabulary and the wiring
that keep the busybody `reverse_engineer` persona honest — the persona itself does the
end-to-end builds; here we pin the classifications so a leak can never be quietly downgraded.
"""
from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))


def _busybody():
    spec = importlib.util.spec_from_file_location("bb_re", REPO / "tools" / "busybody.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def bb():
    return _busybody()


@pytest.mark.invariant("INV-SECRET-02")
def test_leaked_is_a_finding_and_exposed_is_not(bb):
    """The distinction the whole persona turns on. `EXPOSED` is a secret where haru-pack
    DOCUMENTS it can be recovered (staged plaintext, owned by the running user) — reality,
    not a defect. `LEAKED` is a secret where it must NOT be — the encrypted binary at rest,
    or a tree other users can read — and that is critical.

    Red-path: make LEAKED a note, and a plaintext key in an encrypted binary stops being a
    finding.
    """
    assert bb.severity_for({}, {"outcome": "LEAKED"}, ok=False) == "critical"
    assert bb.severity_for({}, {"outcome": "EXPOSED"}, ok=False) == "note"
    # both must be in the closed vocabulary, with meanings
    assert "LEAKED" in bb.OUTCOME_MEANING and "EXPOSED" in bb.OUTCOME_MEANING
    assert "must not" in bb.OUTCOME_MEANING["LEAKED"].lower() or \
           "defect" in bb.OUTCOME_MEANING["LEAKED"].lower()


@pytest.mark.invariant("INV-SECRET-02")
def test_the_persona_checks_all_four_edges(bb):
    """A persona that only checked the happy edge (encrypted-hides-at-rest) would imply the
    others are fine. All four must exist: at-rest, staged-plaintext, obfuscation, and
    other-user permissions."""
    names = {c["name"] for c in bb.CASES if c["persona"] == "reverse_engineer"}
    assert names == {
        "encrypted_binary_hides_the_secret_at_rest",
        "plaintext_source_is_recoverable_from_the_stage",
        "obfuscation_strips_the_plaintext_literal_from_the_stage",
        "the_staged_tree_is_not_readable_by_other_users",
    }, f"reverse_engineer edges changed: {names}"


@pytest.mark.invariant("INV-SECRET-02")
def test_the_at_rest_case_expects_absence_and_reports_leaked_on_presence(bb):
    """The at-rest case is the one surface encryption is supposed to close, so its acceptable
    outcome is RAN (secret absent) and a present secret must be LEAKED, never quietly RAN."""
    case = next(c for c in bb.CASES
                if c["name"] == "encrypted_binary_hides_the_secret_at_rest")
    assert case["expect"] == ("RAN",)
    src = inspect.getsource(case["fn"])
    assert '"outcome": "LEAKED"' in src, "a secret in the encrypted binary must be LEAKED"
    assert "RE_SECRET.encode() in out.read_bytes()" in src, (
        "the case must actually grep the binary, not assume"
    )


@pytest.mark.invariant("INV-SECRET-02")
def test_the_obfuscation_case_has_a_control_and_cannot_pass_vacuously(bb):
    """Its value is proving --obfuscate removed the literal. If the plain control stage does
    not contain the literal, the case proves nothing — it must refuse as REFUSED-UNRELATED
    rather than pass. This is the same lesson as the CRC32 false-pass."""
    case = next(c for c in bb.CASES
                if c["name"] == "obfuscation_strips_the_plaintext_literal_from_the_stage")
    src = inspect.getsource(case["fn"])
    assert "if not plain_hits:" in src and '"REFUSED-UNRELATED"' in src, (
        "a broken control must fail the case, not silently pass it"
    )
    assert "obf_hits" in src and '"LEAKED"' in src, (
        "a literal surviving obfuscation must be LEAKED"
    )


@pytest.mark.invariant("INV-SECRET-02")
def test_the_permission_case_checks_reachability_not_raw_bits(bb):
    """Owner-only is a real protection against OTHER users on a shared box. But the check has
    to be REACHABILITY, not raw inner bits: a 0644 file inside a 0700 directory is not
    exposed, because the sealed directory blocks the path.

    The first version flagged inner bits directly and reported a FALSE LEAKED — the staged
    root and the cache base are both 0700, gating the whole tree. Red-path: drop the
    ancestor-traversability walk and the case fails on any 0644 staged file, which is every
    real build.
    """
    case = next(c for c in bb.CASES
                if c["name"] == "the_staged_tree_is_not_readable_by_other_users")
    src = inspect.getsource(case["fn"])
    assert "S_IXOTH" in src and "S_IROTH" in src, (
        "the case must check other-traversable ancestors AND other-readable files"
    )
    assert "other_reachable" in src, (
        "a file is a leak only if genuinely reachable, not merely other-readable in isolation"
    )


@pytest.mark.invariant("INV-SECRET-02")
def test_the_reverse_engineer_cases_build_thick_for_an_exact_interpreter(bb):
    """Obfuscation binds to an exact Python minor; the staged interpreter must match. thick
    guarantees it (INV-OBF-01), so the persona's fixtures are thick — a thin fixture could
    stage a different Python and make the obfuscation case fail for the wrong reason."""
    src = inspect.getsource(_busybody()._reveng_build)
    assert '"--tier", "thick"' in src, "reverse_engineer fixtures must be thick"


@pytest.mark.invariant("INV-SECRET-02")
def test_the_staging_reality_is_documented_where_it_lives():
    """INV-DOC-02: a claim about a security boundary must be anchored to the code that makes
    it true. The stage writes plaintext to the regenerable cache — assert stage.nim still
    does what the invariant says, so the doc cannot drift from the mechanism."""
    stage = (REPO / "src" / "haru_pack" / "launcher" / "stage.nim").read_text()
    # the payload is extracted to a per-user cache dir, in plaintext, and hardened owner-only
    assert "extractAll" in stage, "the payload is extracted to disk (the soft spot)"
    assert "hardenDir" in stage, "the staged tree must be hardened to owner-only"

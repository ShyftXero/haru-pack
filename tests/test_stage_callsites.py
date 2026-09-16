"""Guard INVOCATION, not just guard behavior.

Why this file exists, stated plainly because it is the whole point:

tests/test_stage_hardening.py tests what `assertArchiveEntriesSafe`, `isValidUvVersion` and
`checkUvArchive` DO when you call them. The adversarial verifier deleted all three CALL SITES
— the `assertArchiveEntriesSafe(zipPath)` line in `stage.stageZip`, and both guard lines in
`uvfetch.ensureUv` — recompiled, and got 55/55 PASSED. Every one of those tests exercised the
predicate directly. None of them proved the shipping code ever invokes it.

That is linkage, not efficacy: a guard nothing calls is a guard that does not exist. It is the
same trap that already bit this repo once, when a secret-leak test scanned a DEFLATE-compressed
zip blob and so could never have seen the plaintext it searched for.

These are SOURCE-SHAPE assertions, and that is a real limitation worth naming: they prove the
call is written, not that it executes on every path. An end-to-end test that builds a launcher
and feeds it a hostile archive would be stronger, and INV-STAGE-02's Red-path describes it. This
is the cheap check that catches the specific regression the verifier demonstrated — deletion of
the call — and it runs in milliseconds with no Nim toolchain.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

LAUNCHER = Path(__file__).resolve().parent.parent / "src/haru_pack/launcher"
STAGE_NIM = LAUNCHER / "stage.nim"
UVFETCH_NIM = LAUNCHER / "uvfetch.nim"


def _body_of(src: str, proc_name: str) -> str:
    """Return the source of one Nim proc, from its `proc <name>` line to the next top-level proc."""
    m = re.search(rf"^proc {re.escape(proc_name)}\b", src, re.M)
    assert m, f"proc {proc_name} not found — it was renamed or removed"
    rest = src[m.end():]
    nxt = re.search(r"^proc \w", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


@pytest.mark.invariant("INV-STAGE-02")
def test_stagezip_actually_calls_the_archive_guard():
    """Red-path: delete `assertArchiveEntriesSafe(zipPath)` from stageZip. The hardening
    suite stays fully green; this goes red."""
    body = _body_of(STAGE_NIM.read_text(), "stageZip")
    assert re.search(r"^\s*assertArchiveEntriesSafe\(", body, re.M), (
        "stageZip does not call assertArchiveEntriesSafe. Every entry-safety test in "
        "test_stage_hardening.py calls the predicate directly, so they all still pass while "
        "the extraction path is unguarded."
    )
    # the guard must precede extraction, or it guards nothing
    guard = body.index("assertArchiveEntriesSafe(")
    extract = body.find("extractAll(")
    assert extract == -1 or guard < extract, (
        "assertArchiveEntriesSafe is called AFTER extractAll — the archive is already unpacked"
    )


@pytest.mark.invariant("INV-SUPPLY-04")
def test_ensureuv_actually_validates_the_version_before_building_the_url():
    """Red-path: delete the `if not isValidUvVersion(uvVersion)` guard from ensureUv."""
    body = _body_of(UVFETCH_NIM.read_text(), "ensureUv")
    assert re.search(r"isValidUvVersion\(", body), (
        "ensureUv does not call isValidUvVersion; the version string reaches URL "
        "construction unvalidated"
    )
    check = body.index("isValidUvVersion(")
    url = body.find('"https://')
    assert url == -1 or check < url, (
        "the version is validated after the URL is built — validate before interpolating"
    )


@pytest.mark.invariant("INV-SUPPLY-05")
def test_ensureuv_actually_checks_the_downloaded_archive():
    """Red-path: delete the `checkUvArchive` call from ensureUv."""
    body = _body_of(UVFETCH_NIM.read_text(), "ensureUv")
    assert re.search(r"checkUvArchive\(", body), (
        "ensureUv never calls checkUvArchive; the size cap and digest check are dead code "
        "and a fetched uv is written to disk and executed unverified"
    )
    check = body.index("checkUvArchive(")
    for writer in ("writeFile(", "extractAll("):
        pos = body.find(writer)
        assert pos == -1 or check < pos, (
            f"checkUvArchive is called after {writer} — the unverified bytes already hit disk"
        )


@pytest.mark.invariant("INV-STAGE-01")
def test_stage_reuse_goes_through_verification():
    """The reuse path must verify, not short-circuit.

    Red-path: restore the trust-on-first-use form (`if dirExists(final): return final`) at the
    top of stageZip.
    """
    body = _body_of(STAGE_NIM.read_text(), "stageZip")
    assert "verifyStagedDir(" in body, (
        "stageZip's reuse path does not call verifyStagedDir — the staged tree is used unexamined"
    )
    assert not re.search(r"if\s+dirExists\(final\):\s*return final", body), (
        "stageZip short-circuits on directory existence — the trust-on-first-use bug is back"
    )


@pytest.mark.invariant("INV-STAGE-01")
def test_the_executed_uv_path_is_not_exempt_from_verification():
    """`main.findUv` runs <stage>/vendor/uv before anything else. Exempting that path from
    the recorded manifest hands a same-uid attacker the one file guaranteed to execute.

    Red-path: add `if rel == "vendor/uv": return true` back to isRuntimeMutable.
    """
    body = _body_of(STAGE_NIM.read_text(), "isRuntimeMutable")
    assert not re.search(r'rel\s*==\s*"vendor/uv(\.exe)?"', body), (
        "vendor/uv is exempt from .stage-files again; the binary the launcher executes first "
        "is outside the integrity manifest"
    )
    for pat, what in [(r'"\.pyc"', ".pyc"), (r'"__pycache__"', "__pycache__")]:
        assert not re.search(pat, body), (
            f"{what} is exempt from verification again. Timestamp-mode bytecode is validated "
            f"only against the source's mtime and size, both forgeable by a same-uid attacker, "
            f"so an exempt {what} is executable code outside the manifest."
        )

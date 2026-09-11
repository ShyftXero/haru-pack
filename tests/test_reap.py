"""INV-REAP-01 — detached, own-subtree-only on-exit cleanup (Phase 2 of ADR 0004 §5).

The launcher (Nim) half of --reap: after the packed app exits, the stub spawns a DETACHED,
fire-and-forget deleter of the staged subtree it created THIS run and returns without waiting.
End-to-end — compile the real launcher, attach a real payload + a v2 stub-config with
`reap = true`, run it, then poll for the subtree to vanish. The build (Python) half — that
`--reap` bakes `reap = true` into the stub-config and receipt — is in tests/test_canary.py.

Red-path walked 2026-09-10 on this Linux host (neutralize -> observe red -> restore):
  * INV-REAP-01  comment out the `if reapWanted ...: reapDetached(reapTarget)` call in
                 main.launch -> the staged subtree persists after exit and
                 test_reap_deletes_only_its_own_subtree goes red.

See docs/adr/0004-reap-ram-staging.md and the INVARIANTS.md entry.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest
from _stage_helpers import build_payload_zip, make_payload, pack, run, stage_from, stub_toml2, wait_gone


@pytest.mark.invariant("INV-REAP-01")
def test_reap_deletes_only_its_own_subtree(nim_launcher, tmp_path):
    """After the app exits, the detached reaper deletes the created subtree — and ONLY that:
    the base path and a sentinel beside the subtree survive. Red-path: comment out the
    reapDetached call in main.launch -> the subtree persists and this goes red."""
    reapbase = tmp_path / "reapbase"; reapbase.mkdir()
    sentinel = reapbase / "KEEP_ME.txt"; sentinel.write_text("do not delete me\n")
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(reap=True, base_path=str(reapbase)))
    r = run(exe, tmp_path)
    assert r.returncode == 0 and "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stderr)
    stage = Path(stage_from(r.stdout))
    assert stage.parent == reapbase, stage        # subtree lives directly under the base path
    assert wait_gone(stage), f"detached reaper did not delete the staged subtree: {stage}"
    # own-subtree-only: the base path and the sentinel next to the subtree are untouched.
    assert reapbase.exists(), "reap deleted the base path itself"
    assert sentinel.exists(), "reap deleted a sibling of its own subtree"


@pytest.mark.invariant("INV-REAP-01")
def test_without_reap_the_subtree_survives(nim_launcher, tmp_path):
    """Control: reap is opt-in. With no reap key, the staged subtree is left in place (today's
    behaviour), so the deletion above is attributable to --reap and nothing else."""
    b = tmp_path / "b"; b.mkdir()
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe, stub_config=stub_toml2(base_path=str(b)))
    r = run(exe, tmp_path)
    assert r.returncode == 0 and "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stderr)
    stage = Path(stage_from(r.stdout))
    time.sleep(0.5)                                # give any (wrongly) spawned reaper time
    assert stage.exists(), f"the staged subtree vanished without --reap: {stage}"

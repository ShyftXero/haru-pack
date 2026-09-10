"""INV-CHAOS-01 — a chaos run's results survive the run being killed, and repeats group.

Adopted from lotek's BusyBody. Three properties, each learned from a real failure there:

  * Results are journalled as they happen, not serialised at the end. An interrupted run
    used to lose everything.
  * An interrupted run is visible AS interrupted. "No results file" and "the run died
    halfway" look identical otherwise, and the second is a much more interesting fact.
  * Findings are fingerprinted so repeats of one root cause group into one row. Without
    that, every run reads as a fresh set of unrelated failures.

Plus lotek's exit-code contract, which encodes a judgement worth keeping: an interrupt
beats findings, because "a run the operator killed did not finish, and reporting its
partial findings as a completed verdict is the same lie facing the other way."
"""
from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

import busybody_ledger as bl  # noqa: E402


def _load_busybody():
    spec = importlib.util.spec_from_file_location("busybody", REPO / "tools" / "busybody.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------- journal survives death

@pytest.mark.invariant("INV-CHAOS-01")
def test_each_record_is_on_disk_before_the_next_one_starts(tmp_path):
    """Red-path: buffer the journal and flush at the end. Kill the process and everything
    written so far disappears — which is what used to happen."""
    j = bl.Journal(tmp_path / "run", "bb-test")
    j.write("started", planned=["a", "b"])
    # read from a SEPARATE handle, without closing the writer: this is what another
    # process (or a post-mortem) sees while the run is still going
    mid = bl.read_jsonl(tmp_path / "run" / "journal.jsonl")
    assert len(mid) == 1, "the record was still buffered; a kill -9 here would lose it"
    j.write("case", name="a", ok=True)
    assert len(bl.read_jsonl(tmp_path / "run" / "journal.jsonl")) == 2
    j.close()


@pytest.mark.invariant("INV-CHAOS-01")
def test_a_torn_final_line_does_not_discard_the_whole_journal(tmp_path):
    """A process killed mid-write leaves a partial last line. Keeping the readable
    records matters more than rejecting the file."""
    d = tmp_path / "run"
    d.mkdir()
    (d / "journal.jsonl").write_text(
        '{"kind":"started","run":"x","at":1}\n'
        '{"kind":"case","run":"x","at":2,"ok":true}\n'
        '{"kind":"case","run":"x","at":3,"ok'          # torn
    )
    rows = bl.read_jsonl(d / "journal.jsonl")
    assert len(rows) == 2, "a torn final line threw away the records before it"


# ---------------------------------------------------------------- interrupted runs

@pytest.mark.invariant("INV-CHAOS-01")
def test_an_interrupted_run_is_reported_as_interrupted(tmp_path):
    """Red-path: drop the `finished` record, or the heartbeat. Then a run that died
    halfway is indistinguishable from one that simply has no results."""
    runs = tmp_path / "runs"
    d = runs / "bb-died"
    d.mkdir(parents=True)
    (d / "journal.jsonl").write_text(
        json.dumps({"kind": "started", "run": "bb-died", "at": 1,
                    "planned": ["a", "b", "c"]}) + "\n"
        + json.dumps({"kind": "case", "run": "bb-died", "at": 2, "name": "a",
                      "ok": True}) + "\n")
    (d / "heartbeat").write_text(str(time.time() - 10_000))    # long stale

    got = bl.scan_runs(runs)
    assert len(got) == 1
    assert got[0]["state"] == "INTERRUPTED"
    assert got[0]["cases"] == 1
    assert len(got[0]["planned"]) == 3, (
        "the planned list must survive, or you cannot tell 1-of-3 from 1-of-1"
    )


@pytest.mark.invariant("INV-CHAOS-01")
def test_a_finished_run_is_complete_and_a_fresh_heartbeat_is_live(tmp_path):
    runs = tmp_path / "runs"
    for name, extra, hb in (("bb-done", [{"kind": "finished", "run": "bb-done", "at": 9}], 0),
                            ("bb-live", [], time.time())):
        d = runs / name
        d.mkdir(parents=True)
        recs = [{"kind": "started", "run": name, "at": 1, "planned": ["a"]},
                {"kind": "case", "run": name, "at": 2, "name": "a", "ok": True}] + extra
        (d / "journal.jsonl").write_text("\n".join(json.dumps(r) for r in recs) + "\n")
        if hb:
            (d / "heartbeat").write_text(str(hb))

    states = {r["run"]: r["state"] for r in bl.scan_runs(runs)}
    assert states["bb-done"] == "complete"
    assert states["bb-live"] == "live", "a fresh heartbeat must not read as interrupted"


# ---------------------------------------------------------------- fingerprints

@pytest.mark.invariant("INV-CHAOS-01")
def test_volatile_details_do_not_split_one_root_cause():
    """The whole reason fingerprints exist. Two runs of the same fault differ in paths,
    timestamps, hex and numbers; they must land in one group."""
    a = ("haru-pack: payload digest mismatch at /tmp/bb-abc123/x, "
         "expected 9f7d002b3d0972f7 at 2026-09-09T10:00:00")
    b = ("haru-pack: payload digest mismatch at /tmp/bb-zzz999/x, "
         "expected 1122334455667788 at 2026-09-10T22:31:07")
    assert bl.normalize(a) == bl.normalize(b)
    assert bl.fingerprint("forger", "c", "REFUSED", a) == \
        bl.fingerprint("forger", "c", "REFUSED", b)


@pytest.mark.invariant("INV-CHAOS-01")
def test_genuinely_different_failures_stay_apart():
    """A fingerprint that collapses everything is as useless as none at all."""
    fps = {
        bl.fingerprint("forger", "c1", "REFUSED", "digest mismatch"),
        bl.fingerprint("forger", "c1", "CRASHED", "digest mismatch"),
        bl.fingerprint("vandal", "c1", "REFUSED", "digest mismatch"),
        bl.fingerprint("forger", "c2", "REFUSED", "digest mismatch"),
        bl.fingerprint("forger", "c1", "REFUSED", "something else entirely"),
    }
    assert len(fps) == 5, "distinct failures collapsed into one fingerprint"


@pytest.mark.invariant("INV-CHAOS-01")
def test_rollup_counts_repeats_and_keeps_first_seen(tmp_path):
    led = tmp_path / "findings.jsonl"
    fp = bl.fingerprint("forger", "c", "CRASHED", "boom")
    bl.ledger_append([
        {"fingerprint": fp, "run": "bb-1", "at": 100, "name": "c", "persona": "forger",
         "outcome": "CRASHED", "severity": "critical", "message": "boom", "remedy": "fix it"},
        {"fingerprint": fp, "run": "bb-2", "at": 200, "name": "c", "persona": "forger",
         "outcome": "CRASHED", "severity": "critical", "message": "boom"},
    ], path=led)
    got = bl.ledger_rollup(led)
    assert len(got) == 1
    g = got[0]
    assert g["count"] == 2 and g["runs"] == ["bb-1", "bb-2"]
    assert g["first_seen"] == 100 and g["last_seen"] == 200
    assert g["remedy"] == "fix it", "the remedy must survive into the rollup"


@pytest.mark.invariant("INV-CHAOS-01")
def test_the_ledger_lives_outside_the_repository():
    """lotek keeps its ledger beside the checkout because a file inside the tree is caught
    by git stash, worktree switches and branch changes — losing history exactly when you
    are hopping branches to investigate. haru-pack is developed in worktrees."""
    p = bl.ledger_path()
    assert REPO not in p.parents and p != REPO, (
        f"the findings ledger is inside the repository ({p}); a stash or a worktree "
        f"switch will take the history with it"
    )


# ---------------------------------------------------------------- exit codes + vocabulary

@pytest.mark.invariant("INV-CHAOS-01")
def test_severity_vocabulary_is_closed():
    """critical / warning / note. Not "error", not "info". Red-path: return a fourth
    value from severity_for and this fails."""
    bb = _load_busybody()
    for outcome, expect in (("CRASHED", "critical"), ("SILENT", "critical"),
                            ("HUNG", "critical"), ("REFUSED", "warning"),
                            ("CASE-ERROR", "note")):
        sev = bb.severity_for({}, {"outcome": outcome}, ok=False)
        assert sev in bl.SEVERITIES, f"{outcome} produced {sev!r}, outside the vocabulary"
        assert sev == expect
    assert bb.severity_for({}, {"outcome": "RAN"}, ok=True) == "note"


@pytest.mark.invariant("INV-CHAOS-01")
def test_a_harness_bug_is_not_reported_as_a_product_defect():
    """CASE-ERROR means busybody itself broke. Calling that `critical` would inflate the
    harness's own bugs into findings about haru-pack — which happened twice on the first
    real run, and is exactly the confusion the severity split exists to prevent."""
    bb = _load_busybody()
    assert bb.severity_for({}, {"outcome": "CASE-ERROR"}, ok=False) == "note"


# ---------------------------------------------------------------- reaping

@pytest.mark.invariant("INV-CHAOS-02")
def test_reaper_removes_tracked_dirs_and_reports_what_it_freed(tmp_path):
    r = bl.Reaper(log=lambda _m: None)
    a = r.track(tmp_path / "a")
    b = r.track(tmp_path / "b")
    for d in (a, b):
        d.mkdir()
        (d / "big").write_bytes(b"x" * 4096)
    n, freed = r.reap()
    assert n == 2 and freed >= 8192
    assert not a.exists() and not b.exists()


@pytest.mark.invariant("INV-CHAOS-02")
def test_held_dirs_survive_and_are_reported(tmp_path):
    """A finding's artifacts must not be reaped — that is the evidence. Everything else
    goes."""
    r = bl.Reaper(log=lambda _m: None)
    keep = r.track(tmp_path / "keep")
    drop = r.track(tmp_path / "drop")
    for d in (keep, drop):
        d.mkdir()
        (d / "f").write_text("x")
    r.hold(keep)
    r.reap()
    assert keep.exists(), "a held directory was reaped; the finding's artifacts are gone"
    assert not drop.exists()


@pytest.mark.invariant("INV-CHAOS-02")
def test_reap_never_raises_even_on_a_hostile_tree(tmp_path):
    """Reaping runs in a finally. If it can raise, it can mask the original failure —
    which is the one worth reading."""
    r = bl.Reaper(log=lambda _m: None)
    d = r.track(tmp_path / "weird")
    d.mkdir()
    (d / "dangling").symlink_to(tmp_path / "does-not-exist")
    (d / "sub").mkdir()
    (d / "sub").chmod(0o000)
    try:
        r.reap()          # must not raise
    finally:
        try:
            (d / "sub").chmod(0o755)
        except OSError:
            pass


@pytest.mark.invariant("INV-CHAOS-02")
def test_reaping_is_in_a_finally_not_on_the_success_path():
    """Red-path: move `reaper.reap()` out of the finally block.

    A chaos harness is the program most likely to be interrupted, and at the thick tier
    each work directory holds a staged interpreter. The first version removed a work dir
    only when a case succeeded, so a raising case or a Ctrl-C leaked it — measured at
    ~490 MB across three cases.
    """
    import ast
    src = (REPO / "tools" / "busybody.py").read_text()
    tree = ast.parse(src)
    main = next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "main")
    tries = [n for n in ast.walk(main) if isinstance(n, ast.Try) and n.finalbody]
    assert tries, "main() has no try/finally at all"
    in_finally = any(
        "reap" in ast.unparse(stmt)
        for t in tries for stmt in t.finalbody)
    assert in_finally, (
        "reaper.reap() is not reached from a finally block; an interrupted or raising run "
        "will leak its work directories"
    )


@pytest.mark.invariant("INV-CHAOS-02")
def test_orphans_are_not_reaped_while_a_run_is_live(tmp_path):
    """lotek's heartbeat rule: a fresh heartbeat means something may still be using those
    directories, so nothing is touched."""
    runs = tmp_path / "runs"
    live = runs / "bb-live"
    live.mkdir(parents=True)
    (live / "heartbeat").write_text(str(time.time()))
    n, freed = bl.reap_orphans(runs, log=lambda _m: None)
    assert (n, freed) == (0, 0), "orphans were reaped while a run was still live"


@pytest.mark.invariant("INV-CHAOS-02")
def test_pruning_keeps_the_most_recent_runs_and_never_a_live_one(tmp_path):
    runs = tmp_path / "runs"
    for i in range(5):
        d = runs / f"bb2026010{i}-000000"
        d.mkdir(parents=True)
        (d / "journal.jsonl").write_text('{"kind":"started"}\n')
    (runs / "bb20260100-000000" / "heartbeat").write_text(str(time.time()))
    bl.prune_runs(runs, keep=2, log=lambda _m: None)
    left = sorted(d.name for d in runs.iterdir())
    assert "bb20260100-000000" in left, "a live run was pruned"
    assert len(left) == 3, f"expected 2 kept + 1 live, got {left}"

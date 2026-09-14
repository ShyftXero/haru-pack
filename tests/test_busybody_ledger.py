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

import ast
import importlib.util
import json
import sys
import time
import pathlib
from pathlib import Path

import pytest

from _source import harness_modules, harness_source

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
                            ("HUNG", "critical"), ("SILENT-WEDGE", "critical"),
                            ("STALLED", "critical"), ("REFUSED", "warning"),
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
    # `_sweep` is where main()'s run body lives since the 2026-09-13 package split; the
    # finally block moved with it, intact.
    src = (REPO / "tools" / "busybody_run.py").read_text()
    tree = ast.parse(src)
    main = next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "_sweep")
    tries = [n for n in ast.walk(main) if isinstance(n, ast.Try) and n.finalbody]
    assert tries, "_sweep() has no try/finally at all"
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


# ---------------------------------------------------------------- blame + APP-CRASHED

@pytest.mark.invariant("INV-CHAOS-03")
def test_launcher_and_app_failures_are_told_apart():
    """The distinction that makes app-level personas usable.

    A Nim traceback out of the launcher is always a defect. A Python traceback out of the
    packaged application, when a case deliberately starved it, is the application declining
    the box it was given. Calling both CRASHED made a working, calibrated case
    (`tight_address_space` at 768 MB against numpy) look like a product defect.
    """
    bb = _load_busybody()
    assert bb.blame("", "haru-pack: no payload appended") == "launcher"
    assert bb.blame("", "Traceback (most recent call last):\nMemoryError") == "app"
    assert bb.blame("", "") == "unknown"

    assert bb.classify(1, "", "haru-pack: x\nError: unhandled exception [ValueError]",
                       False) == "CRASHED"
    assert bb.classify(1, "", "Traceback (most recent call last):\nMemoryError",
                       False) == "APP-CRASHED"


@pytest.mark.invariant("INV-CHAOS-03")
def test_app_crashed_is_not_automatically_fatal_but_launcher_crashed_is():
    """Red-path: add APP-CRASHED to FATAL. Every resource-limit case then reports a finding
    on any heavy package, which is the outcome those cases exist to produce."""
    bb = _load_busybody()
    assert "CRASHED" in bb.FATAL and "HUNG" in bb.FATAL and "SILENT" in bb.FATAL
    # A stall is a finding whatever the case expected (INV-CHAOS-09). It is in FATAL for
    # the same reason SILENT is: the run would otherwise exit 0 after watching nothing
    # happen for the whole quiet threshold.
    assert "STALLED" in bb.FATAL
    assert "APP-CRASHED" not in bb.FATAL, (
        "an application declining an imposed resource limit is not a haru-pack defect"
    )
    assert bb.severity_for({}, {"outcome": "APP-CRASHED"}, ok=False) == "note"
    assert bb.severity_for({}, {"outcome": "CRASHED"}, ok=False) == "critical"


@pytest.mark.invariant("INV-CHAOS-03")
def test_resource_thresholds_are_calibrated_not_guessed():
    """A ceiling only discriminates between packages if it sits BETWEEN their needs.

    The first version used 256 MB, below every package — so all failed identically and the
    case discriminated nothing. Measured band on this box: iniconfig ok at 512 MB, numpy
    needs 1024 MB, so 768 MB separates them.
    """
    bb = _load_busybody()
    assert 512 < bb.ADDRESS_SPACE_MB < 1024, (
        f"ADDRESS_SPACE_MB={bb.ADDRESS_SPACE_MB} is outside the measured band "
        f"(iniconfig ok at 512, numpy needs 1024); it will not discriminate"
    )


@pytest.mark.invariant("INV-CHAOS-03")
def test_there_are_app_level_personas_distinct_from_launcher_ones():
    """Launcher-level cases are payload-invariant by construction: the launcher is
    byte-identical in every binary. The 2026-09-10 sweep proved it — 575 runs, 23
    fingerprints. App-level personas exist so `--fixtures top25` can tell packages apart."""
    bb = _load_busybody()
    personas = {c["persona"] for c in bb.CASES}
    app_level = {"cartographer", "polyglot", "mute", "impatient", "hoarder"}
    assert app_level <= personas, f"missing app-level personas: {app_level - personas}"
    for name in app_level:
        assert any(c["persona"] == name for c in bb.CASES), f"{name} has no cases"


# ---------------------------------------------------------------- analysis is a tool

def _analyze():
    spec = importlib.util.spec_from_file_location(
        "busybody_analyze", REPO / "tools" / "busybody_analyze.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _journal(tmp_path, cases):
    """Write a minimal run directory: one `started`, the cases, one `finished`."""
    run = tmp_path / "run-synthetic"
    run.mkdir()
    lines = [{"kind": "started", "total": len(cases), "planned": []}]
    lines += cases
    lines += [{"kind": "finished"}]
    (run / "journal.jsonl").write_text(
        "\n".join(json.dumps(x) for x in lines) + "\n")
    return run


def _case(name, fixture, outcome="RAN", ok=True):
    return {"kind": "case", "name": name, "fixture": fixture, "persona": "p",
            "outcome": outcome, "ok": ok, "seconds": 1.0,
            "fingerprint": f"{name}:{outcome}"}


@pytest.mark.invariant("INV-CHAOS-04")
def test_a_sweep_that_confirmed_one_fact_many_times_says_so(tmp_path):
    """The number that makes a sweep look like more assurance than it bought.

    Twenty-five fixtures answering identically is one fact learned twenty-five times.
    Reporting only the run count hides that; the census has to state it.
    """
    a = _analyze()
    cases = [_case("c1", f"fixture-{i}") for i in range(25)]
    cases += [_case("c2", f"fixture-{i}") for i in range(25)]
    got = a.analyze_run(_journal(tmp_path, cases))

    assert len(got["cases"]) == 50
    assert got["diverged"] == {}, "no case was given a differing outcome"
    assert len(got["fingerprints"]) == 2, "two cases, one answer each"

    text = a.format_analysis(got)
    assert "NOTHING DIVERGED" in text, (
        "a 50-run sweep with 2 distinct results must say the sweep bought nothing"
    )
    assert "50 case run(s) produced 2 distinct result(s)" in text


@pytest.mark.invariant("INV-CHAOS-04")
def test_a_case_whose_answer_depends_on_the_package_is_named(tmp_path):
    """The other half: when a sweep DOES earn its cost, the report says which cases earned it
    — by name and by fixture, so the reader can go look."""
    a = _analyze()
    cases = [_case("flat", f"fixture-{i}") for i in range(4)]
    cases += [_case("varies", "fixture-light", "RAN"),
              _case("varies", "fixture-heavy", "APP-CRASHED", ok=False)]
    got = a.analyze_run(_journal(tmp_path, cases))

    assert set(got["diverged"]) == {"varies"}, (
        f"expected only `varies` to diverge, got {sorted(got['diverged'])}"
    )
    text = a.format_analysis(got)
    assert "NOTHING DIVERGED" not in text
    assert "varies" in text and "APP-CRASHED" in text
    assert "heavy" in text, "the report must name the fixture that differed"


@pytest.mark.invariant("INV-CHAOS-04")
def test_an_interrupted_run_is_not_reported_as_a_clean_sweep(tmp_path):
    """Partial results read as complete ones are how a killed sweep becomes a green light."""
    a = _analyze()
    run = tmp_path / "run-partial"
    run.mkdir()
    (run / "journal.jsonl").write_text("\n".join(json.dumps(x) for x in [
        {"kind": "started", "total": 100, "planned": []},
        _case("c1", "fixture-a"),
        {"kind": "interrupted", "detail": "SIGINT"},
    ]) + "\n")
    got = a.analyze_run(run)
    assert got["state"] == "INTERRUPTED"
    text = a.format_analysis(got)
    assert "INTERRUPTED" in text
    assert "1 of 100 planned" in text


@pytest.mark.invariant("INV-CHAOS-04")
def test_the_analysis_questions_are_reachable_from_the_command_line():
    """A tool nobody can invoke is a private one-liner with extra steps."""
    src = harness_source()
    for flag in ("--analyze", "--calibrate"):
        assert f'"{flag}"' in src, f"{flag} is not wired into the CLI"
    assert "format_analysis" in src, "--analyze must use the shared formatter"


def _journal_custom(tmp_path, name, lines):
    run = tmp_path / name
    run.mkdir()
    (run / "journal.jsonl").write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    return run


@pytest.mark.invariant("INV-CHAOS-14")
def test_analyze_is_a_gate_not_just_a_reader(tmp_path):
    """--analyze must exit non-zero when the run is not a clean, completed pass — otherwise a
    CI step that trusts it reads a false pass. RED-PATH: change `return analyze_exit_code(...)`
    in main back to `return 0`, and a findings / setup-failure / aborted run reports success.
    """
    a = _analyze()
    started = {"kind": "started", "total": 1, "planned": []}

    clean = a.analyze_run(_journal_custom(tmp_path, "clean",
        [started, _case("c1", "synthetic"), {"kind": "finished"}]))
    assert a.analyze_exit_code(clean) == 0, "a completed run with no findings is a pass"

    finding = a.analyze_run(_journal_custom(tmp_path, "finding",
        [started, _case("c1", "synthetic", "SILENT", ok=False), {"kind": "finished"}]))
    assert a.analyze_exit_code(finding) == 1, "a finding must not read clean"

    setup = a.analyze_run(_journal_custom(tmp_path, "setup",
        [{"kind": "started", "total": 0, "planned": []},
         {"kind": "setup_failure", "detail": "fixture build failed"}]))
    assert a.analyze_exit_code(setup) == 2, "a setup failure is not zero findings, it is no data"

    aborted = a.analyze_run(_journal_custom(tmp_path, "aborted",
        [started, _case("c1", "synthetic"),
         {"kind": "infra_failure", "detail": "No space left on device"}]))
    assert a.analyze_exit_code(aborted) == 2, "an environment abort is not a verdict"

    interrupted = a.analyze_run(_journal_custom(tmp_path, "interrupted",
        [{"kind": "started", "total": 5, "planned": []}, _case("c1", "synthetic"),
         {"kind": "interrupted", "completed": 1}]))
    assert a.analyze_exit_code(interrupted) == 1, "an incomplete run is not a clean pass"


@pytest.mark.invariant("INV-CHAOS-14")
def test_analyze_exit_code_is_wired_into_the_cli():
    """The gate is only real if main() actually returns it, not just prints the report."""
    code = _harness_code()
    assert "return analyze_exit_code(analysis)" in code, (
        "main()'s --analyze branch must return analyze_exit_code, or the gate is decorative"
    )


@pytest.mark.invariant("INV-CHAOS-04")
def test_differing_error_text_is_not_reported_as_divergence(tmp_path):
    """A fingerprint folds in the diagnostic TEXT, so the same outcome with two different
    messages counts as two distinct results. That granularity is right for triage and wrong
    for "did the sweep buy anything" — and conflating them made the census print
    "0 case(s) DIVERGED" on a sweep where nothing had.
    """
    a = _analyze()
    cases = []
    for i in range(25):
        c = _case("c1", f"pkg{i}")
        c["fingerprint"] = f"fp-{i}"      # 25 fingerprints, one outcome
        cases.append(c)
    got = a.analyze_run(_journal(tmp_path, cases))

    assert len(got["fingerprints"]) == 25
    assert got["diverged"] == {}, "the outcome was RAN on every fixture"

    text = a.format_analysis(got)
    assert "NOTHING DIVERGED" in text
    assert "0 of" not in text, "a sweep where nothing diverged must not claim 0 diverged"
    assert "fingerprints against 1 case(s)" in text, (
        "the fingerprint/outcome gap should be explained, not hidden"
    )


def _harness_code():
    """Every busybody module's code, comments and docstrings stripped.

    See `_module_code` below for why the stripping matters; this is the same thing over
    the whole harness rather than one file, because the harness is now twenty modules.
    """
    return "\n".join(_module_code(p) for p in harness_modules())


def _module_code(path):
    """A module's source with every comment and docstring removed.

    Source-shape assertions are only as good as what they read. A comment that MENTIONS a
    guard makes a "the guard is present" assertion pass with the guard deleted — which is
    the exact trap tests/test_sources.py documents. `ast.unparse` drops comments, and the
    docstrings are stripped explicitly.
    """
    tree = ast.parse(pathlib.Path(path).read_text())
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            node.body = body[1:]
    return ast.unparse(tree)


# ------------------------------------------------- the box failing is not a product finding

@pytest.mark.invariant("INV-CHAOS-05")
def test_a_disk_quota_failure_is_recognised_as_the_environment():
    """No persona imposes capacity limits.

    `hoarder` starves file descriptors, address space and TMPDIR writability — never disk
    space. So errno 122 or 28 coming out of a case means the box gave up, and every result
    after it is the same failure in a different costume.
    """
    bb = _load_busybody()
    assert bb.infra_failure_reason(
        {"stderr": "haru-pack: IOError: errno: 122 `Disk quota exceeded`"})
    assert bb.infra_failure_reason({"stderr": "OSError: [Errno 28] No space left on device"})
    assert bb.infra_failure_reason({"stdout": "", "stderr": ""}) == ""
    assert bb.infra_failure_reason(
        {"stderr": "haru-pack: no payload appended to this executable"}) == "", (
        "an ordinary launcher refusal must not be mistaken for an environment failure"
    )
    # the returned reason is the offending line, so the abort message is actionable
    assert "122" in bb.infra_failure_reason(
        {"stderr": "line one\nharu-pack: IOError: errno: 122 `Disk quota exceeded`\nlast"})


@pytest.mark.invariant("INV-CHAOS-05")
def test_an_environment_failure_aborts_the_sweep_and_spares_the_ledger():
    """Red-path, at the call sites — the checks are worthless if nothing invokes them.

    Deleting the `infra_failure_reason` guard scores the box's failure as chaos findings.
    Reverting `if bad and not aborted` to `if bad` writes them to the ledger permanently.
    """
    src = _harness_code()
    assert "infra_failure_reason(rec)" in src, (
        "every record must be tested for an environment failure as it is collected"
    )
    assert "raise InfraFailure(" in src, "detection without an abort is just a log line"
    assert "if bad and (not aborted):" in src, (
        "a run aborted on an environment failure must not write to the findings ledger"
    )
    assert "jr.write('infra_failure'" in src, (
        "the journal must record WHY the run stopped, or --analyze cannot tell"
    )


@pytest.mark.invariant("INV-CHAOS-05")
def test_scratch_is_freed_per_case_not_at_the_end_of_the_run(tmp_path):
    """The leak with a delayed fuse.

    Tracking every work dir and reaping only in the run-level `finally` was itself a fix for
    a leak-on-raise bug, and it traded a small leak for a large one: 925 thick-tier work dirs
    at ~145 MB each is about 100 GB. On this box the 24 GiB /tmp quota stopped it at case
    168 — 168 x 145 MB, almost exactly.
    """
    dirs = []
    reaper = bl.Reaper(log=lambda _m: None)
    for i in range(4):
        d = tmp_path / f"work{i}"
        d.mkdir()
        (d / "payload").write_bytes(b"x" * 4096)
        dirs.append(reaper.track(d))

    for d in dirs[:3]:
        reaper.release(d)

    live = [d for d in dirs if d.exists()]
    assert live == [dirs[3]], (
        f"released dirs must be gone immediately, still on disk: {live}"
    )
    assert reaper.reaped == 3 and reaper.freed >= 3 * 4096

    reaper.reap()          # the backstop still takes the remainder
    assert not any(d.exists() for d in dirs)


@pytest.mark.invariant("INV-CHAOS-05")
def test_release_leaves_held_directories_alone(tmp_path):
    """A finding's preserved artifacts must survive the very mechanism that frees scratch."""
    reaper = bl.Reaper(log=lambda _m: None)
    keep = reaper.track(tmp_path / "keep")
    keep.mkdir()
    (keep / "evidence").write_bytes(b"y" * 128)
    reaper.hold(keep)

    assert reaper.release(keep) == 0
    assert keep.exists(), "held directories are the artifacts of a finding; never released"


@pytest.mark.invariant("INV-CHAOS-05")
def test_the_case_loop_releases_scratch_and_the_finally_is_only_the_backstop():
    """Deleting the per-case release call reinstates the 100 GB sweep. Nothing else catches
    it, because the totals reported at the end are identical either way."""
    src = _harness_code()
    assert "free_dir(work)" in src, (
        "each completed case must free its own scratch; the run-level reap() is a backstop"
    )
    assert "reaper.reap()" in src, "the backstop must still exist for a raise or a Ctrl-C"
    assert "SCRATCH_CAP_GB" in src, (
        "a leak should stop the sweep at a number the operator chose"
    )
    # A worker process cannot share the parent's Reaper, so both go through one function.
    # Two copies would drift into a leak that only appears at one --jobs setting.
    led = _module_code(REPO / "tools" / "busybody_ledger.py")
    assert "def free_dir(" in led and "size = free_dir(d)" in led, (
        "Reaper.release and the parallel worker must share one implementation"
    )


@pytest.mark.invariant("INV-CHAOS-05")
def test_a_quota_is_invisible_to_df_and_the_report_says_so(tmp_path):
    """The trap that made this hard to see: /tmp reported 31 GiB free and refused the next
    write at 24 GiB, because the mount carries `usrquota`."""
    bb = _load_busybody()
    lines = bb.work_root_report(tmp_path)
    assert lines and "free per statvfs" in lines[0]

    mounts = pathlib.Path("/proc/mounts").read_text()
    if "usrquota" in mounts or "prjquota" in mounts:
        quota_mount = next(
            ln.split()[1] for ln in mounts.splitlines()
            if len(ln.split()) >= 4 and ("usrquota" in ln.split()[3]
                                         or "prjquota" in ln.split()[3]))
        text = " ".join(bb.work_root_report(pathlib.Path(quota_mount)))
        assert "quota" in text and "NOT the ceiling" in text, (
            f"{quota_mount} has a quota; the report must not present statvfs as the limit"
        )


@pytest.mark.invariant("INV-CHAOS-05")
def test_an_aborted_run_is_never_read_as_a_verdict(tmp_path):
    """--analyze must refuse to let a poisoned run look like results. The real one reported
    "30 of 37 cases DIVERGED by fixture"; none had. The five fixtures that passed everything
    were the five built before the quota ran out."""
    a = _analyze()
    run = tmp_path / "run-aborted"
    run.mkdir()
    recs = [{"kind": "started", "total": 925, "planned": []}]
    # two fixtures that ran clean, then one poisoned by the environment
    recs += [_case("c1", "early", "RAN"), _case("c1", "late", "REFUSED", ok=False)]
    recs += [{"kind": "infra_failure", "completed": 2,
              "detail": "landlord/hostile_umask on idna: errno: 122 `Disk quota exceeded`"}]
    (run / "journal.jsonl").write_text("\n".join(json.dumps(x) for x in recs) + "\n")

    got = a.analyze_run(run)
    assert got["state"] == "ABORTED (environment)"
    text = a.format_analysis(got)
    assert "THE BOX FAILED, NOT THE PRODUCT" in text
    assert "Discard this section" in text, (
        "the divergence a quota failure fabricates must be labelled as fabricated"
    )
    assert "122" in text, "the abort reason belongs in the report, not just the journal"


@pytest.mark.invariant("INV-CHAOS-03")
def test_every_non_ran_result_names_who_failed(tmp_path):
    """A "?" in the blame column is a hole in triage, not a finding.

    The 2026-09-10 top-25 sweep printed 25 of them. All were `not_executable`, whose OS
    refusal comes back through run_exe's OSError branch — which returned early without
    setting blame. Four parties exist and the two that this cannot infer from output
    (`os`, `harness`) have to be named by whoever knows.
    """
    bb = _load_busybody()

    victim = tmp_path / "noexec"
    victim.write_bytes(b"\x7fELF not really")
    victim.chmod(0o644)
    r = bb.run_exe(victim, tmp_path, env={"PATH": "/usr/bin:/bin"}, timeout=20)
    assert r["outcome"] == "REFUSED"
    assert r.get("blame") == "os", (
        f"the kernel refused the exec; blame was {r.get('blame')!r}. A missing blame shows "
        f"up in --analyze as a '?' bucket."
    )

    src = _harness_code()
    assert "'blame': 'harness'" in src, (
        "a CASE-ERROR is busybody breaking; it must never read as a statement about "
        "haru-pack"
    )


@pytest.mark.invariant("INV-CHAOS-03")
def test_the_blame_vocabulary_is_closed():
    """Four values, and the docstring that defines them lists exactly those four. An
    undocumented fifth is how a triage column turns back into free text."""
    bb = _load_busybody()
    doc = bb.blame.__doc__ or ""
    for party in ("launcher", "app", "os", "harness"):
        assert party in doc, f"{party} is produced but not documented in blame()"
    assert bb.blame("", "haru-pack: nope") == "launcher"
    assert bb.blame("", "Traceback (most recent call last):") == "app"
    assert bb.blame("", "") == "unknown"


# ---------------------------------------------------------------- parallel execution

@pytest.mark.invariant("INV-CHAOS-06")
def test_cases_that_measure_time_never_share_the_machine():
    """A case that sleeps for a fixed interval and then signals is asking "where had the
    process got to after 0.7 s?" — and the answer changes when seven other cases are
    competing for CPU. Those cases run in a separate serial pass.

    Red-path: drop `serial=True` from any of them and the case starts reporting the load
    instead of the product, intermittently, in a way that reads as a regression.
    """
    bb = _load_busybody()
    serial = {c["name"] for c in bb.CASES if c.get("serial")}
    expected = {"killed_mid_stage", "two_cold_starts_at_once",
                "interrupted_while_the_app_runs", "terminated_mid_run"}
    assert expected <= serial, f"timing-sensitive cases not marked serial: {expected - serial}"

    # and the marking has to be justified by the code, not just declared
    import ast
    import inspect
    for name in expected:
        fn = next(c["fn"] for c in bb.CASES if c["name"] == name)
        body = ast.unparse(ast.parse(inspect.getsource(fn).lstrip()))
        assert ("time.sleep" in body or "Popen" in body), (
            f"{name} is marked serial but does not appear to measure time; either the mark "
            f"is stale or the case changed"
        )


@pytest.mark.invariant("INV-CHAOS-06")
def test_the_worker_count_is_capped_not_merely_defaulted():
    """Each worker stages a real interpreter (measured peak 452 MB) and spawns processes with
    their own rlimits. Past the cap the timing cases measure the load."""
    bb = _load_busybody()
    assert bb.JOBS_DEFAULT == 4
    assert bb.JOBS_MAX == 8
    src = _harness_code()
    assert "min(a.jobs, JOBS_MAX)" in src, "--jobs must be clamped, not trusted"


@pytest.mark.invariant("INV-CHAOS-06")
def test_one_code_path_runs_a_case_whether_parallel_or_serial():
    """The parallel pass hands work items to a pool; the serial pass calls the same function
    inline. Two implementations would drift, and the drift would show up as "it only fails
    under --jobs 8", which is the least debuggable shape available."""
    src = _harness_code()
    assert src.count("def run_one(") == 1, "run_one must have exactly one definition"
    assert "run_one(fname, str(exe)" in src, "the serial pass must call run_one inline"
    assert "pool.imap(run_one, items)" in src, (
        "ordered imap: an unordered journal is not byte-comparable between two runs of the "
        "same sweep, which is what makes the fingerprint census reproducible"
    )


@pytest.mark.invariant("INV-CHAOS-06")
def test_keeping_artifacts_forces_serial():
    """--keep retains every work dir — 452 MB each, 131 GB for a top-25 sweep. Running 8
    wide makes that peak arrive 8x sooner without helping anyone read them."""
    src = _harness_code()
    assert "if a.keep and jobs > 1:" in src, "--keep must downgrade to one worker"


@pytest.mark.invariant("INV-CHAOS-06")
def test_a_missing_optional_dependency_does_not_stop_a_sweep():
    """mpire is in the dev group. --jobs is a convenience for whoever is iterating on the
    harness; a missing optional package must degrade to serial, not fail at the point where
    the work would have started."""
    src = _harness_code()
    assert "except ImportError" in src and "return None" in src
    assert "running serially" in src, (
        "falling back silently would make a 6x slowdown look like the machine"
    )


@pytest.mark.invariant("INV-CHAOS-06")
def test_the_worker_does_not_write_shared_state():
    """The journal and the findings ledger have exactly one writer: the parent. A worker that
    appended to the journal would interleave partial lines and break the fsync-per-line
    contract that makes an interrupted run readable (INV-CHAOS-01)."""
    bb = _load_busybody()
    import ast
    import inspect
    body = ast.unparse(ast.parse(inspect.getsource(bb.run_one).lstrip()))
    for forbidden in ("jr.write", "ledger_append", "jr.beat"):
        assert forbidden not in body, (
            f"run_one calls {forbidden} from a worker process; the parent is the only writer"
        )


# ---------------------------------------------------------------- where the ledger lives

@pytest.mark.invariant("INV-CHAOS-01")
def test_the_ledger_is_outside_every_worktree():
    """The findings ledger has to outlive the branch that produced the findings.

    Resolving it relative to __file__ put it at
    `.claude/worktrees/<name>-busybody-findings.jsonl` when run from a worktree — inside the
    directory that gets deleted when the worktree is removed, which defeats the entire
    reason for keeping it out of the repo. A week of findings would vanish with whichever
    branch happened to be last.

    Red-path: resolve from `Path(__file__).parent.parent` again and this fails whenever the
    suite runs in a worktree, which is where it usually runs.
    """
    where = bl.ledger_path()
    assert ".claude" not in where.parts, (
        f"the ledger is inside .claude ({where}); it dies with the worktree"
    )
    assert "worktrees" not in where.parts, f"the ledger is inside a worktree: {where}"
    assert where.name.endswith("-busybody-findings.jsonl")


@pytest.mark.invariant("INV-CHAOS-01")
def test_the_ledger_sits_beside_the_main_checkout_not_the_linked_one():
    """Same directory whichever worktree you are in, so `--triage` sees one history."""
    here = REPO
    main = bl.main_checkout(here)
    assert ".claude" not in main.parts, f"main_checkout returned a worktree: {main}"
    assert (main / ".git").exists(), (
        f"{main} does not look like the main checkout (no .git)"
    )
    if ".claude" in here.parts:
        assert main != here, (
            "running from a worktree, but main_checkout returned the worktree itself"
        )
    assert bl.ledger_path().parent == main.parent


@pytest.mark.invariant("INV-CHAOS-01")
def test_the_ledger_location_is_still_overridable(monkeypatch, tmp_path):
    """A fixed location is right for the default and wrong as the only option: the tests
    themselves must be able to write somewhere disposable."""
    target = tmp_path / "elsewhere.jsonl"
    monkeypatch.setenv("HARUPACK_BUSYBODY_LEDGER", str(target))
    assert bl.ledger_path() == target


@pytest.mark.invariant("INV-CHAOS-01")
def test_main_checkout_falls_back_to_the_path_rule_without_git(tmp_path):
    """The fallback is for a source tree that is not a git checkout at all. Worktrees this
    project creates live in <main>/.claude/worktrees/<name>, so the main checkout is the
    parent of `.claude`."""
    fake = tmp_path / "proj" / ".claude" / "worktrees" / "feature"
    fake.mkdir(parents=True)
    # no git repository anywhere above tmp_path, so git rev-parse fails and the rule applies
    assert bl.main_checkout(fake) == tmp_path / "proj"

    plain = tmp_path / "plain"
    plain.mkdir()
    assert bl.main_checkout(plain) == plain


# ---------------------------------------------------------------- the on-disk contract


def test_every_record_type_carries_the_schema_version(tmp_path):
    """docs/BUSYBODY-SCHEMA.md is the contract; this is the code agreeing with it.

    All three types, in one test, because the failure being guarded against is a record type
    that quietly stops carrying it — and a version only SOME rows have is worse than none,
    since a reader cannot then distinguish an old row from a new one written by the path that
    forgot. There are two ledger-row call sites already (`_finalize` and `_finish_compose`),
    which is exactly how that happens.
    """
    jr = bl.Journal(tmp_path / "run", "bb20260913-000000")
    jr.write("started", planned=["x"], tier="default")
    jr.write("case", name="x", ok=True)
    jr.close()
    journal = [json.loads(ln) for ln in
               (tmp_path / "run" / "journal.jsonl").read_text().splitlines()]
    assert journal and all(r.get("schema_version") == bl.SCHEMA_VERSION for r in journal), (
        f"a journal line is missing schema_version: {journal}")

    led = tmp_path / "findings.jsonl"
    bl.ledger_append([{"fingerprint": "abc123", "at": 1.0, "outcome": "CRASHED",
                       "severity": "critical", "message": "boom"}], path=led)
    rows = [json.loads(ln) for ln in led.read_text().splitlines()]
    assert rows[0].get("schema_version") == bl.SCHEMA_VERSION, rows

    roll = bl.ledger_rollup(led)
    assert roll[0].get("schema_version") == bl.SCHEMA_VERSION, roll


def test_a_record_written_before_the_schema_existed_still_reads(tmp_path):
    """Version 1 is defined as "no key at all", so nothing on disk needed migrating.

    This is the property that made stamping cheap. If an unversioned row had to be rejected
    or rewritten, adding the field would have meant a migration over every ledger anyone
    has — including the three orphaned ones recovered from dead worktrees.
    """
    led = tmp_path / "findings.jsonl"
    led.write_text(json.dumps({"fingerprint": "old", "at": 1.0, "outcome": "SILENT",
                               "severity": "critical", "message": "x"}) + "\n")
    groups = bl.ledger_rollup(led)
    assert len(groups) == 1 and groups[0]["fingerprint"] == "old"

"""INV-CHAOS-09..11 — the faults busybody injects, and the one it can only observe.

The contracts taken from lotek's BusyBody in the second round (docs/BRAINSTORM.md
section 1b, 2026-09-11). Each is here because it is cheap to half-implement and invisible
when it is:

  * A stall is declared from OUTSIDE every process being judged, never derived from one
    child's exit status or timeout, and once declared it is a finding whatever the case
    said it expected.
  * A result that resolved after a stall is a cascade of it, and a cascade cannot outrank
    the fault that caused it however many results fell into it.
  * A seeded fault is journalled BEFORE it is performed, so a fault that stops the
    recorder still leaves a record of itself.

The fourth contract taken that day — that a case can attack the BUILD rather than a built
binary — needed no invariant of its own in the end: `per_fixture=False` on the case
decorator already runs a case once per run, and the `wedge` persona already builds its own
artifact from (exe, work).

The ledger's own memory (journals, interrupts, fingerprints, reaping) is
tests/test_busybody_ledger.py; this module is the fault vocabulary on top of it.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from _source import harness_modules

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

import busybody_ledger as bl  # noqa: E402


# Every test that drives main() mutates CASES, so each one loads its own module instance
# rather than sharing a global registry with the test that ran before it.
def _load_busybody():
    spec = importlib.util.spec_from_file_location("busybody", REPO / "tools" / "busybody.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


OK = {"outcome": "RAN", "rc": 0, "seconds": 0, "stdout": "", "stderr": ""}


def _drive_main(bb, monkeypatch, tmp_path, argv) -> tuple:
    """Run the real main() over the cases currently registered, redirected into tmp_path.

    REPO is patched as well as OUT/RUNS because main() prints the report path relative to
    REPO on the way out, and a run directory outside it would raise there. tempfile.tempdir
    is patched too: it is what mkdtemp gives each case AND what reap_orphans globs `bb-*`
    under, so an unpatched one would let this test reap another run's work directories.
    """
    tdir = tmp_path / "tmp"
    tdir.mkdir(exist_ok=True)
    monkeypatch.setenv("HARUPACK_BUSYBODY_LEDGER", str(tmp_path / "findings.jsonl"))
    monkeypatch.setattr(tempfile, "tempdir", str(tdir))
    # Patched on busybody_config, not on the `busybody` facade. Every module reads these
    # as `cfg.NAME` precisely so one assignment is seen everywhere; rebinding the facade's
    # copy would leave the modules that do the work looking at the real repo.
    import busybody_config as cfg
    monkeypatch.setattr(cfg, "REPO", tmp_path)
    monkeypatch.setattr(cfg, "OUT", tmp_path / "out")
    monkeypatch.setattr(cfg, "RUNS", tmp_path / "out" / "runs")
    monkeypatch.setattr(sys, "argv", ["busybody.py", *argv])
    rc = bb.main()
    runs = sorted((tmp_path / "out" / "runs").iterdir())
    assert len(runs) == 1, f"expected exactly one run directory, got {runs}"
    return rc, runs[0], bl.read_jsonl(runs[0] / "journal.jsonl")


# ------------------------------------------------- a stall comes from outside the children

@pytest.mark.invariant("INV-CHAOS-09")
def test_no_single_process_outcome_can_ever_be_a_stall():
    """Red-path: return "STALLED" from classify() on `timed_out`.

    HUNG is one process failing to exit inside its timeout, which is all a single wait can
    see. STALLED is no process progressing, which needs several watched at once. Deciding it
    from one timeout turns every slow case on a loaded box into a system-wide stall.
    """
    bb = _load_busybody()
    blobs = ("", "hello", bb.MARKER, "haru-pack: refused: no payload appended",
             "Traceback (most recent call last):\nMemoryError",
             "Error: unhandled exception [ValueError]")
    seen = set()
    for rc in (0, 1, 2, -9, 137):
        for blob in blobs:
            for stream in (0, 1):
                for timed_out in (False, True):
                    out, err = (blob, "") if stream == 0 else ("", blob)
                    seen.add(bb.classify(rc, out, err, timed_out))
    assert "STALLED" not in seen, (
        "classify() declared a stall from one process's own exit; a stall is a statement "
        "about several processes and only an outside observer can make it"
    )
    assert "HUNG" in seen and "RAN" in seen, (
        f"the grid never reached the timeout or success paths, so it proves nothing: {seen}"
    )


@pytest.mark.skipif(sys.platform != "linux", reason="StallWatch samples /proc for CPU time")
@pytest.mark.invariant("INV-CHAOS-09")
def test_the_watchdog_declares_a_stall_while_every_child_is_still_alive(tmp_path):
    """The out-of-band half, on real processes: three children that are alive, burning no
    CPU and writing nothing. No child can report this — each one is fine — and none of them
    has an exit status yet, so the declaration cannot have come from one."""
    bb = _load_busybody()
    base = tmp_path / "stage"
    base.mkdir()
    announce = tmp_path / "run"
    announce.mkdir()
    # The watchdog announces through the work directory, not the journal: under --jobs a
    # case runs in a worker and the parent is the only journal writer, so the durable
    # copy has to be a file the worker owns.
    bb.Ctx.enter(announce, 7, "probe", "fake", announce)
    kids = [subprocess.Popen(["sleep", "30"]) for _ in range(3)]
    watch = bb.StallWatch(base, kids, quiet_s=0.6, tick_s=0.1)
    try:
        watch.start()
        deadline = time.monotonic() + 20
        while watch.stalled_at is None and time.monotonic() < deadline:
            time.sleep(0.05)
        alive = [p.poll() is None for p in kids]
        watch.stop()
    finally:
        for p in kids:
            p.kill()
            p.wait(timeout=10)
        bb.Ctx.clear()

    assert watch.stalled_at is not None, (
        f"three idle children never read as quiet in 20s ({watch.ticks} tick(s), longest "
        f"quiet stretch {watch.quiet_max:.1f}s of the {watch.quiet_s}s asked for)"
    )
    assert all(alive), (
        "a child had already exited when the stall was declared, so its own exit status "
        "could have carried the verdict and this test is not exercising the stall path"
    )
    recs = bb.Ctx.announced(announce)
    stalls = [r for r in recs if r["kind"] == "stall"]
    assert len(stalls) == 1, f"expected one stall record, got {[r['kind'] for r in recs]}"
    assert stalls[0]["stall_id"] == watch.stall_id and stalls[0]["case"] == "probe"
    assert stalls[0]["alive"] == 3 and stalls[0]["blame"] == "unknown", (
        "there is no orphaned staging directory here, so nothing points at the launcher"
    )
    assert not [r for r in recs if r["kind"] == "perturb"], (
        "the stall was filed as a perturbation; perturb means a fault the harness INJECTED, "
        "and mixing an observation in makes the seeded-kill record untrustworthy"
    )


@pytest.mark.invariant("INV-CHAOS-09")
def test_a_declared_stall_is_a_finding_whatever_the_case_expected(tmp_path, monkeypatch):
    """Red-path: remove "STALLED" from FATAL. This case names STALLED in its own `expect`
    set, so without the FATAL term it passes, the run exits 0, and a stall is reported as
    the expected outcome of a chaos case."""
    # Deliberately NOT asserting membership of FATAL first: `"STALLED" in bb.FATAL` would
    # short-circuit this test into a restatement of the constant it is supposed to be
    # checking the consequences of. The membership assertion lives in
    # tests/test_busybody_ledger.py; what this one reads is the verdict, the exit code and
    # the report a human is handed.
    bb = _load_busybody()
    # `CASES` is a single list shared by every busybody module since the 2026-09-13 split,
    # so clearing it in place would empty the catalogue for the rest of the session — the
    # reverse_engineer and examiner suites went red exactly that way. Swap in a private
    # list and let monkeypatch put the real one back.
    import busybody_config as cfg
    monkeypatch.setattr(cfg, "CASES", [])
    monkeypatch.setattr(bb, "CASES", cfg.CASES)

    @bb.case("herd", ("RAN", "STALLED"), "a case that tolerates a stall in its expect set")
    def tolerant_of_a_stall(exe: Path, work: Path) -> dict:
        return {"outcome": "STALLED", "rc": None, "seconds": 0, "stall_id": "abc123abc123",
                "stdout": "2 judged: HUNGx2 | WEDGE abc123abc123 blamed on unknown", "stderr": ""}

    rc, run_dir, recs = _drive_main(bb, monkeypatch, tmp_path, ["--fixtures", "/bin/true"])
    rec = next(r for r in recs if r["kind"] == "case")
    assert rec["outcome"] == "STALLED"
    assert rec["ok"] is False, "a case was allowed to declare a stall acceptable"
    assert rec["severity"] == "critical", f"a stall graded {rec['severity']}"
    assert rc == 1, "a declared stall did not reach the exit code"

    report = (run_dir / "report.txt").read_text()
    legend = [ln for ln in report.splitlines() if ln.strip().startswith("Always a finding")]
    assert legend and "STALLED" in legend[0], (
        f"the report's always-a-finding legend does not name STALLED: {legend}"
    )
    # OUTCOME_MEANING is printed verbatim as the legend and a missing key degrades to "?"
    # rather than raising — a silent way to ship an outcome nobody can look up.
    assert f"OUTCOME   STALLED — {bb.OUTCOME_MEANING['STALLED']}" in report
    assert "STALLED — ?" not in report
    assert "SEVERITY  always a finding, regardless of what was expected" in report


# ------------------------------------------------------------------- cascades cannot rank

@pytest.mark.invariant("INV-CHAOS-10")
@pytest.mark.parametrize("n", [2, 16, 64])
def test_one_stall_with_n_cascades_never_outranks_the_fault_that_caused_it(tmp_path, n):
    """Red-path: restore the count-only ordering key in ledger_rollup —
    `key=lambda g: (-g["count"], g["fingerprint"])`. One stall that takes N children with
    it then ranks above the single-count record of the stall itself, N times over, and
    `--triage` reads as N copies of the top problem. Parametrised because the defect is
    arithmetic: it is wrong at N=2 and looks more convincing the larger N gets.
    """
    led = tmp_path / "findings.jsonl"
    stall = bl.fingerprint("herd", "sixteen_cold_starts_at_once", "STALLED",
                           "no child was progressing")
    child = bl.fingerprint("herd", "sixteen_cold_starts_at_once", "HUNG",
                           "child never exited")
    rows = [{"fingerprint": stall, "run": "bb-1", "at": 100, "name": "stall",
             "persona": "herd", "outcome": "STALLED", "severity": "critical"}]
    rows += [{"fingerprint": child, "run": "bb-1", "at": 101 + i, "name": "stall",
              "persona": "herd", "outcome": "HUNG", "severity": "critical",
              "post_stall": True, "stall_id": "abc123abc123"} for i in range(n)]
    bl.ledger_append(rows, path=led)

    got = bl.ledger_rollup(led)
    fresh = [i for i, g in enumerate(got) if not g["post_stall"]]
    cascades = [i for i, g in enumerate(got) if g["post_stall"]]
    assert fresh and cascades, f"expected one group of each kind, got {got}"
    assert max(fresh) < min(cascades), (
        f"a cascade group of {n} outranked a fresh finding: "
        f"{[(g['count'], g['post_stall']) for g in got]}"
    )
    assert got[cascades[0]]["count"] == n, "the cascades did not group into one row"
    assert got[fresh[0]]["fingerprint"] == stall


@pytest.mark.invariant("INV-CHAOS-10")
def test_triage_counts_the_cascade_apart_from_the_finding(tmp_path, monkeypatch, capsys):
    """What the operator actually reads. The header counts fresh findings only, the
    cascades are named as consequences under their own heading, and the numbering runs on
    so `[2]` means one row tomorrow."""
    bb = _load_busybody()
    led = tmp_path / "findings.jsonl"
    monkeypatch.setenv("HARUPACK_BUSYBODY_LEDGER", str(led))
    stall = bl.fingerprint("herd", "sixteen_cold_starts_at_once", "STALLED", "nothing moved")
    child = bl.fingerprint("herd", "sixteen_cold_starts_at_once", "HUNG", "never exited")
    rows = [{"fingerprint": stall, "run": "bb-1", "at": 100, "name": "stall",
             "persona": "herd", "outcome": "STALLED", "severity": "critical",
             "message": "nothing moved"}]
    rows += [{"fingerprint": child, "run": "bb-1", "at": 101 + i, "name": "stall",
              "persona": "herd", "outcome": "HUNG", "severity": "critical",
              "message": "never exited", "post_stall": True} for i in range(16)]
    bl.ledger_append(rows, path=led)

    assert bb.print_triage() == 0
    out = capsys.readouterr().out
    assert "1 finding(s), 1 distinct" in out, (
        "sixteen consequences of one stall were counted as findings in the header"
    )
    assert "plus 16 cascade(s), 1 distinct" in out, "the cascades were dropped, not demoted"
    assert out.index("[1]") < out.index("CASCADES") < out.index("[2]"), (
        "the cascade group is not below the findings section, or the numbering restarted"
    )


# ------------------------------------------------- a seeded fault is recorded before it lands

@pytest.mark.invariant("INV-CHAOS-11")
def test_every_case_journals_its_fault_before_performing_it():
    """Red-path: move the `Ctx.perturb(...)` call in
    `sixteen_cold_starts_one_killed_mid_stage` below `target.send_signal(signal.SIGKILL)`.

    A source-shape check, and honest about being one: it compares the position of two
    statements inside one function body, so a fault performed inside a helper the case
    calls would slip past it. tests/test_stage_callsites.py exists for the same reason.
    The behavioural half — that the record survives the fault it announces — is the test
    below, and neither is sufficient alone.
    """
    faults = ("send_signal", ".kill", "os.kill", ".terminate")
    trees = [ast.parse(p.read_text()) for p in harness_modules()]
    checked = []
    for fn in [n for tree in trees for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef)]:
        calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call)]
        announced = [c for c in calls if "Ctx.perturb" in ast.unparse(c.func)]
        if not announced:
            continue
        performed = [c for c in calls
                     if any(f in ast.unparse(c.func) for f in faults)]
        assert performed, (
            f"{fn.name} journals a perturbation and then performs nothing this test knows "
            f"how to find; add the call shape to `faults` or the ordering is unchecked"
        )
        assert min(c.lineno for c in announced) < min(c.lineno for c in performed), (
            f"{fn.name} performs its fault at line {min(c.lineno for c in performed)} and "
            f"journals it at line {min(c.lineno for c in announced)}. A fault recorded "
            f"afterwards is unattributable, and the harness's own jitter then reads as a "
            f"product defect"
        )
        checked.append(fn.name)
    assert "sixteen_cold_starts_one_killed_mid_stage" in checked, (
        f"the seeded-kill case no longer journals its fault at all, so this test just "
        f"passed over {checked or 'an empty set'}"
    )


# A real run of main(), in a child process, whose second case kills the harness the
# instant after journalling what it is about to do. Run out-of-process because the fault
# IS a SIGKILL of the process running the cases.
_SELF_KILL_DRIVER = '''\
import importlib.util, os, signal, sys
from pathlib import Path

REPO, SANDBOX = Path(sys.argv[1]), Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("busybody", REPO / "tools" / "busybody.py")
bb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bb)
bb.REPO, bb.OUT, bb.RUNS = SANDBOX, SANDBOX / "out", SANDBOX / "out" / "runs"
bb.CASES.clear()


@bb.case("herd", ("RAN",), "journals a fault, performs it, and lives to be recorded")
def perturb_then_act(exe, work):
    bb.Ctx.perturb("kill_mid_stage", delay_s=1.25, victim=2, signal="SIGKILL")
    (work / "acted").write_text("x")
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "stdout": "", "stderr": ""}


@bb.case("herd", ("RAN",), "journals a fault that then stops the recorder")
def perturb_then_kill_the_harness(exe, work):
    bb.Ctx.perturb("kill_mid_stage", delay_s=0.0, victim="the harness itself",
                   signal="SIGKILL")
    os.kill(os.getpid(), signal.SIGKILL)
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "stdout": "", "stderr": ""}


# --jobs 1 on purpose: with a worker pool the SIGKILL below would take out a WORKER,
# the parent would record a CASE-ERROR and the run would survive — which proves nothing
# about a fault that stops the recorder. Inline is the only way to kill the recorder.
sys.argv = ["busybody.py", "--fixtures", "/bin/true", "--seed", "5", "--keep-runs", "99",
            "--jobs", "1", "--keep"]
raise SystemExit(bb.main())
'''


@pytest.mark.invariant("INV-CHAOS-11")
def test_the_perturb_record_survives_the_fault_it_announces(tmp_path):
    """Red-path: record the fault on the case record instead of before the action — drop
    the write from `Ctx.perturb` and fold its fields into the record `run_one` builds.

    A pure ordering assertion stays green under that change, because the driver writes the
    case record after the case returns either way. This does not: the second case here
    SIGKILLs the harness, so a fault recorded with the result is a fault with no record at
    all, which is what "journalled BEFORE it is performed" is for.
    """
    sandbox = tmp_path / "sandbox"
    (sandbox / "tmp").mkdir(parents=True)
    driver = tmp_path / "driver.py"
    driver.write_text(_SELF_KILL_DRIVER)
    proc = subprocess.run(
        [sys.executable, str(driver), str(REPO), str(sandbox)],
        capture_output=True, text=True, timeout=300, check=False,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "TMPDIR": str(sandbox / "tmp"),
             "HARUPACK_BUSYBODY_LEDGER": str(tmp_path / "findings.jsonl")})
    assert proc.returncode == -9, (
        f"the case did not kill the harness, so nothing was proved: rc={proc.returncode} "
        f"{proc.stdout[-400:]}{proc.stderr[-400:]}"
    )

    runs = sorted((sandbox / "out" / "runs").iterdir())
    recs = bl.read_jsonl(runs[-1] / "journal.jsonl")
    kinds = [r["kind"] for r in recs]
    # The first case returned, so the parent folded its announcement into the journal
    # ahead of its result. The second case never returned — it killed the recorder — so
    # the journal CANNOT hold its announcement, and that is exactly the point: the
    # durable copy is the fsynced file in the case's own work directory, written before
    # the signal. A fault recorded with the result would leave nothing at all here.
    assert kinds == ["started", "perturb", "case"], (
        f"expected the survivor's fault journalled before its own result, got {kinds}"
    )

    leftovers = sorted((sandbox / "tmp").glob("bb-perturb_then_kill_the_harness-*"))
    assert leftovers, "the killed case left no work directory to recover a record from"
    survived = [json.loads(x) for d in leftovers
                for x in (d / "perturbations.jsonl").read_text().splitlines() if x.strip()]
    assert len(survived) == 1 and survived[0]["victim"] == "the harness itself", (
        f"the announcement of the fault that stopped the recorder did not survive it: "
        f"{survived}"
    )

    first, second = [r for r in recs if r["kind"] == "perturb"] + survived
    result = next(r for r in recs if r["kind"] == "case")
    assert first["case"] == result["name"] == "perturb_then_act"
    assert recs.index(first) < recs.index(result), (
        "the fault was recorded after its own result; a fault whose moment came from a "
        "seed is unattributable if it is recorded afterwards"
    )
    assert (first["seed"], first["delay_s"], first["victim"]) == (5, 1.25, 2), (
        f"the seeded draw is not in the record, so the run cannot be reproduced: {first}"
    )
    assert second["case"] == "perturb_then_kill_the_harness"
    assert not [r for r in recs if r["kind"] == "case"
                and r["name"] == "perturb_then_kill_the_harness"], (
        "the self-killing case somehow produced a result record; the fault below its "
        "perturb call did not land and the test is not exercising the survival path"
    )
    assert "finished" not in kinds, "a SIGKILLed run must not look like a completed one"


# ------------------------------------------------------- a case can attack the build instead

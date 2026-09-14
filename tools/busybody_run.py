"""One whole sweep: guard, fixtures, passes, report.

`_Recorder` is the only writer to the journal. The parallel pass hands work items to a pool
and the serial pass calls `run_one` inline, but both funnel their records through it, which
keeps the append order deterministic and the one-fsync-per-line contract honest.

It was a closure carrying `nonlocal peak_scratch` plus four captured locals — a class with
the word `class` left out, and untestable without running a real sweep.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Behaviour unchanged.
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

import busybody_config as cfg
from busybody_guard import guard_single_instance
from busybody_ledger import (Journal, Reaper, human_bytes, is_finding, ledger_append,
                             ledger_path, prune_runs, reap_orphans)
from busybody_report import write_report
from busybody_runner import InfraFailure, dir_bytes, infra_failure_reason, work_root_report
from busybody_sweep import compose_sweep, run_one, worker_pool


def _make_fixtures(a, jr, run_dir: Path, reaper, paths) -> list:
    """The binaries the cases attack. Raises SystemExit(2) on a SETUP FAILURE.

    lotek calls it that: the harness never reached the starting line, so there are no
    results, and reporting zero findings would be a lie.
    """
    try:
        # Looked up in the registry rather than imported by name (INV-MODULARITY-04): a
        # fixture source knows about tiers, the top-25 list and flex-run, and none of that
        # is the sweep driver's business. `busybody.py` imports the catalogue, which is what
        # fills this in; an empty registry here means somebody reached `_sweep` without it.
        if source := cfg.FIXTURE_SOURCES.get(a.fixtures):
            return source(a.tier, reaper)
        if not cfg.FIXTURE_SOURCES and a.fixtures != "synthetic":
            raise SystemExit(
                f"no fixture sources are registered, so {a.fixtures!r} cannot be resolved. "
                f"Import the catalogue (`import busybody`) before running a sweep.")
        exe = Path(a.fixtures).expanduser().resolve()
        if not exe.exists():
            raise SystemExit(f"no such binary: {exe}")
        return [(exe.name, exe)]
    except SystemExit as e:
        jr.write("setup_failure", detail=str(e)[:400])
        print(f"SETUP FAILURE: {e}", file=sys.stderr)
        print(f"no cases ran; journal at {paths.relative(run_dir)}", file=sys.stderr)
        raise


class _Recorder:
    """Journals one case result, and enforces the scratch cap while doing it.

    The parent process is the ONLY writer. The parallel pass hands work items to a pool and
    the serial pass calls `run_one` inline, but both funnel their records through here,
    which keeps the append order deterministic and the one-fsync-per-line contract honest.
    """

    def __init__(self, jr, results: list, fixtures: list):
        self.jr, self.results, self.fixtures = jr, results, fixtures
        self.peak_scratch = 0

    def __call__(self, rec: dict) -> None:
        self.peak_scratch = max(self.peak_scratch, rec.get("scratch_bytes") or 0)
        if reason := infra_failure_reason(rec):
            raise InfraFailure(
                f"{rec['persona']}/{rec['name']} on {rec['fixture']}: {reason}")
        self.results.append(rec)
        # Announcements first, in the order the case made them: each was written and
        # fsynced to the work dir BEFORE its fault, and this puts them in the journal
        # ahead of the result they explain. A reader who sees a kill at 2.54s and then
        # a REFUSED knows which moment produced it.
        for note in rec.pop("announced", None) or []:
            # The note's own kind, not a fixed one: "perturb" is a fault the harness
            # injected and "stall" is one it observed, and a reader has to be able to
            # tell those apart.
            self.jr.write(note.get("kind") or "perturb",
                          **{k: v for k, v in note.items() if k != "kind"})
        self.jr.write("case", **{k: v for k, v in rec.items() if k != "why"})
        if len(self.results) % 25 == 0:
            self._check_scratch()
        self.jr.beat()
        ok = rec["ok"]
        print(f"  {'ok ' if ok else 'BAD'} {rec['persona']:14} {rec['name']:42} "
              f"{rec['outcome']:9}{'  ' if ok else '<-'}"
              + (f" [{rec['fixture']}]" if len(self.fixtures) > 1 else ""))

    def _check_scratch(self) -> None:
        live = dir_bytes(cfg.WORK_ROOT or Path(tempfile.gettempdir()))
        if live > cfg.SCRATCH_CAP_GB * 1024**3:
            raise InfraFailure(
                f"scratch root holds {human_bytes(live)} after {len(self.results)} "
                f"case(s), over the {cfg.SCRATCH_CAP_GB} GiB cap. Reaping is "
                f"per-case, so this is a leak, not normal growth.")


def _run_passes(a, picked: list, fixture_free: list, fixtures: list, jobs: int,
                run_dir: Path, record) -> None:
    """The parallel pass, the config pass, and the serial pass — in that order."""
    parallel_cases = [c for c in picked if not c.get("serial")]
    serial_cases = [c for c in picked if c.get("serial")]
    pool = worker_pool(jobs) if jobs > 1 and parallel_cases else None
    if pool is None:
        # Three ways to get here — --jobs 1, mpire missing, or nothing to parallelise —
        # and they must not print the same thing. Reporting "mpire is not installed"
        # when the real reason is "every selected case builds its own artifact" sends
        # the reader to install a package that would not have helped.
        if jobs > 1 and parallel_cases:
            print("mpire is not installed; running serially. "
                  "`uv sync --group dev` installs it.")
        parallel_cases, serial_cases = [], picked

    if parallel_cases:
        items = [(fname, str(exe), c["name"], str(run_dir), str(cfg.WORK_ROOT or ""),
                  a.keep, a.seed)
                 for fname, exe in fixtures for c in parallel_cases]
        print(f"  {len(items)} run(s) across {jobs} worker(s)"
              + (f", then {len(serial_cases) * len(fixtures)} timing-sensitive run(s) "
                 f"serially" if serial_cases else ""))
        with pool:
            # imap, not imap_unordered: ordered results keep the journal byte-comparable
            # between two runs of the same sweep, which is what makes the fingerprint
            # census reproducible rather than merely repeatable.
            for rec in pool.imap(run_one, items):
                record(rec)

    if fixture_free:
        print(f"\n-- config pass: {len(fixture_free)} case(s) that build their own "
              f"artifact (once, not per fixture)")
        first = fixtures[0][1] if fixtures else Path("/nonexistent")
        for c in fixture_free:
            record(run_one("(config)", str(first), c["name"], str(run_dir),
                           str(cfg.WORK_ROOT or ""), a.keep, a.seed))

    if serial_cases:
        if parallel_cases:
            print(f"\n-- serial pass: {len(serial_cases)} case(s) that measure time")
        for fname, exe in fixtures:
            if len(fixtures) > 1 and not parallel_cases:
                print(f"-- {fname} ({exe.stat().st_size / 1e6:.0f}MB)")
            for c in serial_cases:
                record(run_one(fname, str(exe), c["name"], str(run_dir),
                               str(cfg.WORK_ROOT or ""), a.keep, a.seed))


def _report_abort(e: InfraFailure, jr, results: list) -> None:
    jr.write("infra_failure", detail=str(e)[:400], completed=len(results))
    print(f"\n*** ABORTED — the environment failed, not haru-pack.\n"
          f"    {e}\n\n"
          f"    {len(results)} case(s) had already run. They are journalled but NOT\n"
          f"    written to the findings ledger: once scratch space is exhausted every\n"
          f"    later result is the same failure wearing a different persona's costume,\n"
          f"    and a ledger full of those is worse than an empty one.\n",
          file=sys.stderr)
    for ln in work_root_report(cfg.WORK_ROOT or Path(tempfile.gettempdir())):
        print(f"    {ln}", file=sys.stderr)
    print("\n    Re-run with --work-root DIR pointing at a filesystem with room.",
          file=sys.stderr)


def _finalize(a, jr, reaper, bb_reg: Path, run_dir: Path, run_id: str, results: list,
              interrupted: bool, aborted: bool, peak_scratch: int, paths) -> None:
    """Everything that must happen whether the sweep succeeded, raised, or was killed.

    Reaping is not conditional on success: a chaos harness is the program most likely to be
    interrupted, and at the thick tier each work directory holds a staged interpreter.
    """
    bad = [r for r in results if is_finding(r)]
    if bad and not aborted:
        ledger_append([{k: v for k, v in r.items()
                        if k in ("name", "persona", "outcome", "severity",
                                 "fingerprint", "inv", "remedy", "artifacts",
                                 "fixture", "seed", "post_stall", "stall_id")}
                       | {"run": run_id, "at": time.time(),
                          "message": (r.get("stderr") or r.get("stdout") or "")[:500]}
                       for r in bad])
    if results:
        (run_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        write_report(results, ", ".join(sorted({r["fixture"] for r in results})),
                     run_dir / "report.txt", run_id=run_id, interrupted=interrupted)
    if not interrupted and not aborted and results:
        jr.write("finished", cases=len(results), findings=len(bad),
                 peak_scratch_bytes=peak_scratch)
    jr.close()

    # Unconditional. This is the line the whole finally block exists for.
    print()
    reaper.reap()
    prune_runs(paths.runs, keep=a.keep_runs, log=lambda m: print(f"  {m}"))
    # Release the single-instance registry (INV-CHAOS-13) so the next sweep can start. A
    # crash that skips this leaves a marker whose pid is now dead, which the next run reaps.
    bb_reg.unlink(missing_ok=True)


def _summarize(run_dir: Path, results: list, interrupted: bool, aborted: bool,
               peak_scratch: int, paths) -> int:
    """What the operator reads last, and the exit code they get.

    lotek's exit-code contract. An interrupt WINS over findings: a run the operator killed
    did not finish, and reporting its partial findings as a completed verdict is the same
    lie facing the other way.
    """
    bad = [r for r in results if is_finding(r)]
    unresolved = [r for r in results if r.get("indeterminate")]
    if aborted:
        print(f"\n{len(results)} case(s) ran before the environment failed. This run is NOT"
              f"\na verdict on haru-pack — see the message above.")
        return 2
    # Indeterminates come out of the denominator, not out of one side of it. "14/15 behaved
    # as expected" with one indeterminate is two different lies depending on which way you
    # round it, and the honest sentence has three numbers in it.
    settled = len(results) - len(unresolved)
    print(f"\n{settled - len(bad)}/{settled} behaved as expected"
          + ("  (RUN INTERRUPTED — this is not the whole suite)" if interrupted else ""))
    if unresolved:
        print(f"{len(unresolved)} INDETERMINATE — the harness stopped observing before the "
              f"action\nresolved, so these are counted as neither a pass nor a finding:")
        for r in unresolved:
            print(f"  {r['persona']}/{r['name']}  {r.get('fixture', '?')}")
    if peak_scratch:
        print(f"peak scratch per case: {human_bytes(peak_scratch)}  "
              f"(cap {cfg.SCRATCH_CAP_GB} GiB on the root)")
    if results:
        print(f"report : {paths.relative(run_dir / 'report.txt')}   "
              f"<- read this; it explains every finding")
        print(f"journal: {paths.relative(run_dir / 'journal.jsonl')}")
    if bad:
        print(f"ledger : {ledger_path()}   (--triage to group by fingerprint)")
        print(f"\n{len(bad)} finding(s):")
        for r in bad:
            print(f"  [{r['severity']}] {r['outcome']:9} {r.get('fixture', '?')} "
                  f"{r['persona']}/{r['name']}" + (f"  {r['inv']}" if r.get("inv") else ""))
    if interrupted:
        return 130
    return 1 if bad else 0


def _sweep(a, picked: list, jobs: int, paths=None) -> int:
    """One whole run: guard, fixtures, passes, report.

    `paths` is built ONCE here, at the top of the run, and handed to everything below it.
    Nothing under this function asks the module where the repo is (INV-MODULARITY-04's
    sibling concern): a run's layout does not change while it is running, so it is a frozen
    value, and making it an argument is what an extraction would otherwise have to do by
    hand across a dozen call sites. It defaults to the module shim so `_sweep(a, picked,
    jobs)` keeps working for callers that have not been converted.
    """
    paths = paths if paths is not None else cfg.paths()
    # A run id from the wall clock, so run directories sort chronologically and a human
    # can say "the 14:05 run" without consulting anything.
    run_id = "bb" + time.strftime("%Y%m%d-%H%M%S")
    run_dir = paths.runs / run_id
    # Single-instance guard (INV-CHAOS-13): refuse to start (exit 3) while another sweep is
    # live; reap a dead run's stale registry. Done BEFORE creating the journal dir so a
    # refusal litters nothing. Released in the finally below.
    bb_reg = guard_single_instance(run_id, run_dir / "heartbeat",
                                   log=lambda m: print(f"  {m}"))
    jr = Journal(run_dir, run_id)
    reaper = Reaper(log=lambda m: print(f"  {m}"))

    results, interrupted, aborted = [], False, False
    record, fixtures = None, []
    try:
        reap_orphans(paths.runs, log=lambda m: print(f"  {m}"))
        try:
            fixtures = _make_fixtures(a, jr, run_dir, reaper, paths)
        except SystemExit:
            return 2

        if a.calibrate:
            if cfg.CALIBRATOR is None:
                print("--calibrate: no calibrator is registered; import the catalogue "
                      "(`import busybody`) first.", file=sys.stderr)
                return 2
            return cfg.CALIBRATOR(fixtures)

        # fixture-free cases run once; everything else once per fixture
        fixture_free = [c for c in picked if not c.get("per_fixture", True)]
        per_fixture = [c for c in picked if c.get("per_fixture", True)]
        total = len(fixtures) * len(per_fixture) + len(fixture_free)
        jr.write("started", planned=[c["name"] for c in picked], tier=a.tier,
                 fixtures=[n for n, _ in fixtures], cases=len(picked), total=total)
        jr.beat()
        print(f"\nbusybody: {len(picked)} case(s) x {len(fixtures)} fixture(s) "
              f"= {total} run(s)   run {run_id}")
        for ln in work_root_report(cfg.WORK_ROOT or Path(tempfile.gettempdir())):
            print(ln)
        print()

        record = _Recorder(jr, results, fixtures)
        if a.compose is not None or a.compose_only:
            return compose_sweep(a, fixtures, jr, run_dir, run_id, reaper, results,
                                 paths)
        _run_passes(a, per_fixture, fixture_free, fixtures, jobs, run_dir, record)
    except InfraFailure as e:
        aborted = True
        _report_abort(e, jr, results)
    except KeyboardInterrupt:
        interrupted = True
        # planned is cases x fixtures, matching what `started` recorded, so --analyze
        # can say "N of M finished" rather than comparing against the case count alone.
        jr.write("interrupted", completed=len(results),
                 planned=len(picked) * max(1, len(fixtures)))
        print("\n^C — interrupted. Everything completed so far is in the journal.",
              file=sys.stderr)
    finally:
        peak = record.peak_scratch if record is not None else 0
        _finalize(a, jr, reaper, bb_reg, run_dir, run_id, results, interrupted, aborted,
                  peak, paths)

    return _summarize(run_dir, results, interrupted, aborted,
                      record.peak_scratch if record is not None else 0, paths)

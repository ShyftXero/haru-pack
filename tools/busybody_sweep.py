"""One code path for running a case, and the pool that runs many.

`run_one` is the ONLY way a case is executed. The parallel pass hands work items to a pool
and the serial pass calls the same function inline, so a timing-sensitive case and a
parallel one cannot drift apart in how they are set up, limited or recorded.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from busybody_config import CASES  # noqa: E402
from busybody_ledger import ledger_append, prune_runs  # noqa: E402
from busybody_report import write_report  # noqa: E402

import json
import sys
import tempfile
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "src") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "src"))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from haru_pack import overlay  # noqa: E402,F401

import busybody_config as cfg  # noqa: E402
from busybody_config import (FATAL, MARKER, case)  # noqa: E402,F401
from busybody_runner import (Ctx, InfraFailure, blame, classify, clean_env,  # noqa: E402,F401
                             dir_bytes, infra_failure_reason, run_exe, stage_root,
                             warm, work_root_report)
from busybody_compose import (conflicts_in, describe_traits, sample_combos,  # noqa: E402,F401
                              singleton_cases, TRAITS)
from busybody_compose_run import run_stack  # noqa: E402,F401
from busybody_ledger import Journal, Reaper, fingerprint, free_dir, human_bytes  # noqa: E402,F401
from busybody_report import preserve, severity_for  # noqa: E402,F401

# ---------------------------------------------------------------- parallel execution

def run_one(fixture_name: str, exe_str: str, case_name: str, run_dir_str: str,
            work_root_str: str, keep: bool, seed: int = 0) -> dict:
    """Run one (case, fixture) pair and return its record. Safe to call in a worker process.

    Everything this needs arrives as arguments rather than through module state, and nothing
    it touches is shared: its own work directory, its own subprocesses, its own rlimits. The
    two things that ARE shared — the journal and the findings ledger — are deliberately not
    written here. The parent does that as records come back, which keeps the append order
    deterministic and the fsync-per-line contract intact with one writer.

    Args are strings because a work item crosses a process boundary; Path survives pickling
    but strings make it obvious that this is a message, not a reference. `seed` comes the
    same way rather than through module state, for the same reason: under --jobs the case
    runs in a worker that never saw the parent's globals.
    """
    c = next(x for x in CASES if x["name"] == case_name)
    exe, run_dir = Path(exe_str), Path(run_dir_str)
    work = Path(tempfile.mkdtemp(prefix=f"bb-{case_name}-",
                                 dir=work_root_str or None))
    Ctx.enter(work, seed, case_name, fixture_name, run_dir)
    try:
        try:
            r = c["fn"](exe, work)
        except Exception as e:
            r = {"outcome": "CASE-ERROR", "rc": None, "seconds": 0, "blame": "harness",
                 "stdout": "", "stderr": f"{type(e).__name__}: {e}"}
        r.setdefault("blame", blame(r.get("stdout", ""), r.get("stderr", "")))
        r["scratch_bytes"] = dir_bytes(work)
        # Read the announcements back before the work dir goes away. The file on disk is
        # the copy that survives this process being killed; this list is only so the
        # parent can journal them in order without touching the work dir.
        r["announced"] = Ctx.announced(work)

        ok = r["outcome"] in c["expect"] and r["outcome"] not in FATAL
        msg = (r.get("stderr") or r.get("stdout") or "").strip()
        rec = {**{k: c[k] for k in ("name", "persona", "why", "inv", "remedy")},
               **r, "ok": ok, "expect": list(c["expect"]), "fixture": fixture_name,
               "seed": seed,
               # Always present rather than sometimes-absent, so no consumer needs .get():
               # a cascade is a result that resolved after a stall was already declared.
               "post_stall": bool(r.get("post_stall")),
               "stall_id": r.get("stall_id", ""),
               "severity": severity_for(c, r, ok),
               "fingerprint": fingerprint(c["persona"], c["name"], r["outcome"], msg)}
        if not ok:
            rec["artifacts"] = preserve(run_dir, f"{fixture_name}--{case_name}", work,
                                        light=c.get("light", False))
        if keep:
            rec.setdefault("artifacts", str(work))
        return rec
    finally:
        Ctx.clear()
        # Same rule as the serial path, and the same function: the work dir goes away here,
        # not at the end of the run. With 8 workers, deferring it would multiply the peak
        # footprint by 8 on top of already holding the whole sweep. A worker cannot share
        # the parent's Reaper, so both go through free_dir().
        if not keep:
            free_dir(work)


def worker_pool(jobs: int):
    """An mpire pool, or None if mpire is not installed.

    mpire is a dev-group dependency: `--jobs` is a convenience for whoever is iterating on
    the harness, and a missing optional package must not stop a sweep from running. It falls
    back to serial and says so, rather than failing at the point where the work would start.
    """
    try:
        from mpire import WorkerPool
    except ImportError:
        return None
    return WorkerPool(n_jobs=jobs, use_dill=False)



def _compose_combos(a, seed: int) -> list | int:
    """Which stacks this pass will run. Returns the list, or an exit code.

    Three sources, and they answer different questions. `--compose-only` reproduces one
    exact stack; `--compose 1` runs every trait ALONE, which is the attribution baseline
    everything else is measured against; anything else samples conflict-free combinations.
    """
    if a.compose_only:
        names = tuple(n.strip() for n in a.compose_only.split(",") if n.strip())
        unknown = [n for n in names if n not in TRAITS]
        if unknown:
            print(f"unknown trait(s): {unknown}\n"
                  f"see --list-traits", file=sys.stderr)
            return 2
        if bad := conflicts_in(names):
            print(f"note: {bad[0]} and {bad[1]} cancel each other; running anyway because "
                  f"you asked for this exact stack", file=sys.stderr)
        return [names] * max(1, a.compose_runs)
    if a.compose == 1:
        return singleton_cases()
    return sample_combos(list(TRAITS), a.compose, a.compose_runs, seed)


def _announce_compose(a, combos: list, fixtures: list, run_id: str, seed: int,
                      force: bool, jr) -> None:
    """Say what is about to run, and under which rules, before any of it runs."""
    jr.write("started", planned=[",".join(c) for c in combos], tier=a.tier,
             fixtures=[n for n, _ in fixtures], cases=len(combos), total=len(combos),
             mode="compose", compose_k=a.compose, compose_seed=seed, forced=force)
    jr.beat()
    print(f"\nbusybody compose: {len(combos)} stack(s) of "
          f"{a.compose if a.compose else len(combos[0])} trait(s)   run {run_id}")
    print(f"seed: {seed}   (reproduce a stack with --compose-only a,b,c)")
    print("fallibility: " + ("OFF \u2014 every selected trait fires, because this pass is the "
                             "attribution baseline" if force else
                             "ON \u2014 a trait may decline to act; the FIRED set is what counts"))
    for ln in work_root_report(cfg.WORK_ROOT or Path(tempfile.gettempdir())):
        print(ln)
    print(f"\n  acceptable: RAN / REFUSED / APP-CRASHED.  never: {', '.join(FATAL)}\n")


def _stack_record(r: dict, combo: tuple, seed: int) -> dict:
    """One stack's result, in the same shape a case result has.

    A stack has no expectation of its own \u2014 only the FATAL floor \u2014 so `expect` is written
    as its negation, and the remedy is the exact command that reproduces it.
    """
    fired = r.get("fired") or []
    ok = r["outcome"] not in FATAL
    return {**r, "name": "+".join(fired) or "(nothing fired)",
            "persona": "compose", "fixture": "(stack)",
            "why": "; ".join(TRAITS[n]["why"] for n in fired)[:600],
            "inv": ", ".join(sorted({TRAITS[n]["inv"] for n in fired
                                     if TRAITS[n]["inv"]})),
            "remedy": ("Reproduce with: python tools/busybody.py --compose-only "
                       + ",".join(fired) + f" --compose-seed {seed}"),
            "ok": ok, "expect": ["not " + "/".join(FATAL)],
            "severity": "critical" if not ok else "note",
            "fingerprint": fingerprint("compose", "+".join(sorted(fired)),
                                       r["outcome"],
                                       (r.get("stderr") or "").strip())}


def _run_one_stack(a, exe, combo: tuple, i: int, n_combos: int, seed: int, force: bool,
                   jr, run_dir: Path, results: list) -> int:
    """Build, run and journal one stack. Returns the scratch it peaked at."""
    work = Path(tempfile.mkdtemp(prefix="bb-stack-", dir=cfg.WORK_ROOT or None))
    try:
        r = run_stack(exe, work, combo, seed, i, force=force)
        peak = dir_bytes(work)
        rec = _stack_record(r, combo, seed)
        fired, ok = r.get("fired") or [], rec["ok"]
        if not ok:
            rec["artifacts"] = preserve(run_dir, f"stack-{i:04d}", work)
        results.append(rec)
        # Announcements first, in the order the case made them: each was written and
        # fsynced to the work dir BEFORE its fault, and this puts them in the journal
        # ahead of the result they explain. A reader who sees a kill at 2.54s and then
        # a REFUSED knows which moment produced it.
        for note in rec.pop("announced", None) or []:
            # The note's own kind, not a fixed one: "perturb" is a fault the harness
            # injected and "stall" is one it observed, and a reader has to be able to
            # tell those apart.
            jr.write(note.get("kind") or "perturb",
                     **{k: v for k, v in note.items() if k != "kind"})
        jr.write("case", **{k: v for k, v in rec.items() if k != "why"})
        jr.beat()
        n_sel, n_fired = len(combo), len(fired)
        drop = f" ({n_sel - n_fired} did not fire)" if n_fired < n_sel else ""
        print(f"  {'ok ' if ok else 'BAD'} [{i + 1:>4}/{n_combos}] "
              f"{r['outcome']:12} {'+'.join(fired) or '(control run)'}{drop}")
        if not ok:
            print(f"       {(r.get('stderr') or '').strip()[:160]}")
        return peak
    finally:
        if not a.keep:
            free_dir(work)


def _finish_compose(a, results: list, run_dir: Path, run_id: str, peak: int, jr,
                    reaper) -> int:
    """Ledger, report, reap \u2014 and the exit code."""
    bad = [r for r in results if not r["ok"]]
    if bad:
        ledger_append([{k: v for k, v in r.items()
                        if k in ("name", "persona", "outcome", "severity", "fingerprint",
                                 "inv", "remedy", "artifacts", "fixture", "selected",
                                 "fired", "seed", "run_index", "post_stall", "stall_id")}
                       | {"run": run_id, "at": time.time(),
                          "message": (r.get("stderr") or r.get("stdout") or "")[:500]}
                       for r in bad])
    (run_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    write_report(results, "(stacks)", run_dir / "report.txt", run_id=run_id)
    jr.write("finished", cases=len(results), findings=len(bad),
             peak_scratch_bytes=peak)
    jr.close()
    reaper.reap()
    prune_runs(cfg.RUNS, keep=a.keep_runs, log=lambda m: print(f"  {m}"))

    print(f"\n{len(results) - len(bad)}/{len(results)} stack(s) stayed out of "
          f"{'/'.join(FATAL)}")
    print(f"peak scratch per stack: {human_bytes(peak)}")
    print(f"report : {(run_dir / 'report.txt').relative_to(cfg.REPO)}")
    if bad:
        print(f"\n{len(bad)} finding(s) \u2014 each with a --compose-only line to reproduce it:")
        for r in bad:
            print(f"  [{r['severity']}] {r['outcome']:12} {r['name']}")
            print(f"      {r['remedy']}")
        return 1
    return 0


def compose_sweep(a, fixtures, jr, run_dir: Path, run_id: str, reaper, results: list) -> int:
    """Stack traits and run them. Returns an exit code.

    Kept separate from the case sweep because the two answer different questions and share
    only the journal: a case has an expectation, a stack has only the FATAL floor.
    """
    seed = a.compose_seed if a.compose_seed is not None else int(run_id[2:].replace("-", ""))
    exe = fixtures[0][1] if fixtures else None

    # Fallibility off for the baseline and for an explicitly-named stack; see realize().
    force = bool(a.compose_only) or a.compose == 1

    combos = _compose_combos(a, seed)
    if isinstance(combos, int):
        return combos
    if not combos:
        print(f"no conflict-free stacks of {a.compose} trait(s) to run", file=sys.stderr)
        return 2

    _announce_compose(a, combos, fixtures, run_id, seed, force, jr)

    peak = 0
    for i, combo in enumerate(combos):
        peak = max(peak, _run_one_stack(a, exe, combo, i, len(combos), seed, force, jr,
                                        run_dir, results))
    return _finish_compose(a, results, run_dir, run_id, peak, jr, reaper)


# ── Single-instance run control (INV-CHAOS-13, adopted from lotek BusyBody #738) ──
# A busybody sweep stages a REAL interpreter per worker (tens of MB each at the thick tier), so
# two sweeps on one box thrash disk and memory — a thick top-50 sweep was killed by the OOM guard
# every time a second sweep ran alongside it (2026-09-12). A sweep therefore registers itself and
# REFUSES to start while another is genuinely LIVE, and REAPS a registry left by a DEAD run rather
# than trusting it (a bare pid is not proof; the heartbeat it owns is). Project-tagged: this
# NEVER reads or writes another project's busybody registry — lotek keeps its own /tmp dir, so do
# we. Checks pids directly with os.kill(pid, 0), so there is no ps-grep self-match trap.
#
# The registry lives at a FIXED path, NOT `tempfile.gettempdir()` — because a sweep sets its own
# `--work-root`/`$TMPDIR` to isolate scratch, and a gettempdir-derived registry would then move
# WITH that scratch dir, so two sweeps with different scratch roots would register in different
# places and never see each other — defeating the whole guard (found 2026-09-12: a top-100 sweep
# under a custom TMPDIR registered under that TMPDIR, not the shared location). `$HARUPACK_BUSYBODY_REGISTRY`
# overrides for an unusual host; otherwise it is a stable, shared /tmp path like lotek's.

"""What PAST sweeps say: the run list, and findings grouped by fingerprint.

Separate from `busybody_report` because it answers a different question with different
inputs. A report is written once, from one run's results, by the process that produced
them; history and triage READ many runs afterwards, from the ledger, and are the only
things here that a sweep never calls.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from busybody_report import _wrap  # noqa: E402

import busybody_config as cfg  # noqa: E402

import time

from busybody_ledger import (ledger_path, ledger_rollup,
                             scan_runs)



def print_history() -> int:
    runs = scan_runs(cfg.RUNS)
    if not runs:
        print("no runs yet")
        return 0
    print(f"{'run':22} {'state':12} {'cases':>5} {'findings':>8} {'casc':>5}  planned")
    print(f"{'-' * 22} {'-' * 12} {'-' * 5:>5} {'-' * 8:>8} {'-' * 5:>5}  -------")
    for r in runs:
        planned = len(r["planned"] or []) if r["planned"] else "?"
        print(f"{r['run']:22} {r['state']:12} {r['cases']:>5} {r['findings']:>8} "
              f"{r.get('cascades', 0):>5}  {planned}")
    if any(r.get("cascades") for r in runs):
        print()
        print("casc = results that failed AFTER a stall had already been declared. They are")
        print("counted apart from findings because they are one fault's consequences, not")
        print("that many independent faults. --triage lists them under their own heading.")
    interrupted = [r for r in runs if r["state"] == "INTERRUPTED"]
    if interrupted:
        print()
        print("INTERRUPTED means the run started, never wrote a finish record, and its")
        print("heartbeat has gone stale. The case count is what completed before it stopped,")
        print("NOT the whole suite — do not read those numbers as a result.")
        for r in interrupted:
            planned = len(r["planned"] or [])
            print(f"  {r['run']}: {r['cases']} of {planned} case(s) completed")
    return 0


def _seen_date(at) -> str:
    """The date a group was first seen, or "unknown" — never a fabricated 1970."""
    if not at:
        return "unknown"
    return time.strftime("%Y-%m-%d", time.localtime(at))


def _triage_group(i: int, g: dict) -> None:
    """One group, rendered. Factored so the fresh and cascade sections cannot drift."""
    print("-" * 78)
    print(f"[{i}] {g['count']} occurrence(s)   severity: {g['severity']}   "
          f"outcome: {g['outcome']}")
    print(f"    fingerprint : {g['fingerprint']}")
    print(f"    first seen  : {_seen_date(g.get('first_seen'))}"
          + (f"   last: {_seen_date(g.get('last_seen'))}"
             if _seen_date(g.get("last_seen")) != _seen_date(g.get("first_seen")) else ""))
    print(f"    cases       : {', '.join(g['cases'])}")
    print(f"    personas    : {', '.join(g['personas'])}")
    shown = g["runs"][:6]
    print(f"    seen in runs: {', '.join(shown)}"
          + (f"  (+{len(g['runs']) - 6} more)" if len(g["runs"]) > 6 else ""))
    if g.get("inv"):
        print(f"    invariant   : {g['inv']}")
    if g.get("sample"):
        print("    sample message:")
        for line in g["sample"].splitlines()[:4]:
            print(f"        {line[:70]}")
    if g.get("remedy"):
        print("    what to do:")
        for line in _wrap(" ".join(g["remedy"].split()), 68):
            print(f"        {line}")


def print_triage() -> int:
    groups = ledger_rollup()
    path = ledger_path()
    if not groups:
        print(f"no findings recorded in {path}")
        return 0
    # Split on the flag, not on the sort order: the ordering key already sinks cascades,
    # but reading the split off the order would break silently the day the key changes.
    fresh = [g for g in groups if not g.get("post_stall")]
    cascades = [g for g in groups if g.get("post_stall")]
    print("=" * 78)
    print(f"busybody triage — {sum(g['count'] for g in fresh)} finding(s), "
          f"{len(fresh)} distinct")
    if cascades:
        print(f"plus {sum(g['count'] for g in cascades)} cascade(s), "
              f"{len(cascades)} distinct")
    print(f"ledger: {path}")
    print("=" * 78)
    print()
    print("Grouped by fingerprint: paths, timestamps, hex and bare numbers are normalised")
    print("out, so repeats of one root cause appear as ONE group with a count and a")
    print("first-seen date. Fix the group, not the occurrences. Biggest group first.")
    print()
    n = 0
    for g in fresh:
        n += 1
        _triage_group(n, g)
    if cascades:
        print("-" * 78)
        print()
        print("CASCADES — after a declared stall, not independent findings")
        print()
        print("Each of these resolved once a stall had already been declared, so it failed")
        print("for the stall rather than for itself. They are listed for shape — how many")
        print("processes went down with one stall, and which — and they rank below every")
        print("fresh group no matter how many of them there are. Fix the stall above.")
        print()
        for g in cascades:
            n += 1
            _triage_group(n, g)
    print("-" * 78)
    return 0




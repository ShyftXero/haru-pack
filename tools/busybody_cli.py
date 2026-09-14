"""The command line: what the operator asked for, and which phase answers it.

`main()` reads as the list of phases a run has — parse, apply the global knobs, answer the
read-only questions and stop, select cases, sweep. Each phase is its own function, so none
of them can quietly acquire a second job.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Behaviour unchanged.
"""
from __future__ import annotations

import sys
from pathlib import Path

import busybody_config as cfg
from busybody_analyze import analyze_exit_code, analyze_run, format_analysis
from busybody_args import _parser
from busybody_compose import describe_traits
from busybody_config import JOBS_MAX
from busybody_history import print_history, print_triage
from busybody_run import _sweep


def _apply_globals(a) -> int:
    """Push the command line into `busybody_config`, and return the worker count.

    Assigned onto the MODULE rather than imported names: every case module already
    imported `cfg`, so rebinding an attribute here is seen by all of them. A `from
    busybody_config import HERD_N` anywhere would freeze the default at import time.
    """
    cfg.SCRATCH_CAP_GB = a.scratch_cap_gb

    jobs = max(1, min(a.jobs, JOBS_MAX))
    if a.jobs > JOBS_MAX:
        print(f"--jobs {a.jobs} clamped to {JOBS_MAX}: each worker stages a real "
              f"interpreter, and past this the\ntiming-sensitive cases measure the load "
              f"instead of the product.", file=sys.stderr)
    if a.keep and jobs > 1:
        # --keep retains every work dir; at 452 MB each that is 131 GB for a top-25 sweep,
        # and running 8 wide makes the peak arrive 8x sooner. Keeping artifacts is an
        # inspection workflow, so serial is the right shape for it.
        print("--keep implies --jobs 1 (every work dir is retained; parallel would make "
              "the peak arrive sooner without helping you read them)", file=sys.stderr)
        jobs = 1

    # The two flags that used to be decorative. --timeout was parsed and never read at
    # all; every wait in the file was whichever literal sat nearest. HERD_N below the
    # minimum cannot race, so 2 is a floor rather than an error.
    cfg.DEFAULT_TIMEOUT_S = a.timeout
    cfg.HERD_N = max(2, a.herd_n)

    if a.work_root:
        cfg.WORK_ROOT = Path(a.work_root).expanduser().resolve()
        # INV-LAUNCH-07: a work dir inside the repository lets uv discover haru-pack's own
        # pyproject.toml from it, and a staged run then adopts this project instead of the
        # one it packed. That bug clobbered the repo's .venv twice before the work dirs were
        # moved out. --work-root must not be a way to walk back into it.
        if cfg.WORK_ROOT == cfg.REPO or cfg.REPO in cfg.WORK_ROOT.parents:
            raise SystemExit(
                f"--work-root must be outside the repository (got {cfg.WORK_ROOT}).\n"
                f"A work dir under {cfg.REPO} lets uv discover haru-pack's own project from it, "
                f"so a\nstaged run adopts this checkout instead of the payload it was "
                f"built with. See INV-LAUNCH-07.")
        cfg.WORK_ROOT.mkdir(parents=True, exist_ok=True)
    return jobs


def _early_exit(a, paths) -> int | None:
    """The read-only questions. Returns an exit code, or None to carry on and run."""
    if a.list_traits:
        print(describe_traits())
        return 0
    if a.history:
        return print_history(paths)
    if a.triage:
        return print_triage()
    if a.analyze is None:
        return None
    runs = sorted(d for d in (paths.runs.iterdir() if paths.runs.is_dir() else [])
                  if d.is_dir())
    if not runs:
        print("no runs to analyse", file=sys.stderr)
        return 1
    target = runs[-1] if a.analyze == "latest" else paths.runs / a.analyze
    if not (target / "journal.jsonl").exists():
        print(f"no journal in {target}", file=sys.stderr)
        return 1
    analysis = analyze_run(target)
    print(format_analysis(analysis))
    # --analyze is a gate, not just a reader (INV-CHAOS-14): a run with findings, a setup
    # failure, or an environment abort must NOT exit 0, or a CI step that trusts --analyze
    # reads a false pass.
    return analyze_exit_code(analysis)


def _select(a) -> list | int:
    """Which cases this run will execute. Returns the list, or an exit code.

    Selection is fail-loud (INV-CHAOS-12). A requested persona/case name that matches
    nothing is a SETUP FAILURE (exit 2), never a silent drop: `--persona forger,typo` must
    not quietly run only forger and print a clean verdict, because a run that silently
    skipped what you asked for reads exactly like a healthy one. (Adopted from lotek's
    BusyBody #558 — an unmatched selection is fatal, not dropped.)
    """
    picked = cfg.CASES
    if a.persona:
        want = {s.strip() for s in a.persona.split(",") if s.strip()}
        known = {c["persona"] for c in cfg.CASES}
        if unknown := (want - known):
            print(f"unknown persona(s): {', '.join(sorted(unknown))}\n"
                  f"known personas: {', '.join(sorted(known))}", file=sys.stderr)
            return 2
        picked = [c for c in picked if c["persona"] in want]
    if a.case:
        want = {s.strip() for s in a.case.split(",") if s.strip()}
        known = {c["name"] for c in cfg.CASES}
        if unknown := (want - known):
            print(f"unknown case(s): {', '.join(sorted(unknown))}\n"
                  f"known cases: {', '.join(sorted(known))}", file=sys.stderr)
            return 2
        picked = [c for c in picked if c["name"] in want]
    if not picked:
        print("nothing selected", file=sys.stderr)
        return 1
    return picked


def _print_listing(picked: list) -> int:
    """`--list`: what would run, grouped by persona, and nothing else."""
    cur = None
    for c in picked:
        if c["persona"] != cur:
            cur = c["persona"]
            print(f"\n== {cur} ==")
        print(f"  {c['name']:42} expect={'/'.join(c['expect'])}")
        print(f"      {' '.join(c['why'].split())}")
    print(f"\n{len(picked)} case(s); nothing was run.")
    return 0


def main(doc: str = "") -> int:
    a = _parser(doc).parse_args()
    jobs = _apply_globals(a)
    # Built ONCE, here, after the flags have been applied and before anything reads a path.
    # Everything below takes it as an argument rather than asking the module where the repo
    # is; see busybody_config.Paths.
    paths = cfg.paths()
    if (rc := _early_exit(a, paths)) is not None:
        return rc
    picked = _select(a)
    if isinstance(picked, int):
        return picked
    if a.list:
        return _print_listing(picked)
    return _sweep(a, picked, jobs, paths)

"""Every flag busybody takes, and nothing else.

Its own module because it is pure declaration: it changes when a FLAG changes, never when
the harness changes, and keeping it next to the dispatch made `busybody_cli` grow by fifty
lines every time an option was added.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import argparse

import busybody_config as cfg
from busybody_config import JOBS_DEFAULT, JOBS_MAX


def _parser(doc: str) -> argparse.ArgumentParser:
    """Every flag the harness takes."""
    ap = argparse.ArgumentParser(description=doc,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--persona", default="", help="comma-separated personas")
    ap.add_argument("--case", default="", help="comma-separated case names")
    ap.add_argument("--tier", default="thick",
                    help="fixture tier; thick keeps network out of the results")
    ap.add_argument("--fixtures", default="synthetic",
                    help="'synthetic' (a two-line script), 'top25' (one binary per top-25 "
                         "package), or a path to an existing binary")
    ap.add_argument("--keep-runs", type=int, default=10,
                    help="how many past run directories to retain")
    ap.add_argument("--timeout", type=int, default=180,
                    help="default wall-clock ceiling for a case that does not set its own")
    ap.add_argument("--seed", type=int, default=0,
                    help="seed for faults whose MOMENT is chosen rather than fixed (the "
                         "herd persona's mid-stage kill). Distinct from --compose-seed, "
                         "which selects which traits stack")
    ap.add_argument("--herd-n", type=int, default=16, metavar="N",
                    help="how many processes the herd persona races on one stage key")
    ap.add_argument("--keep", action="store_true", help="keep each case's wreckage")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--triage", action="store_true",
                    help="group past findings by fingerprint and stop")
    ap.add_argument("--history", action="store_true",
                    help="list runs, marking any that were interrupted")
    ap.add_argument("--analyze", nargs="?", const="latest", default=None,
                    metavar="RUN", help="analyse a run (default: the most recent)")
    ap.add_argument("--work-root", metavar="DIR", default=None,
                    help="filesystem for scratch dirs (default $TMPDIR; move it if a long "
                         "sweep dies with errno 122)")
    ap.add_argument("--list-traits", action="store_true",
                    help="print the composable trait catalogue and stop")
    ap.add_argument("--compose", type=int, metavar="K", default=None,
                    help="stack K traits per run instead of running the named cases "
                         "(K=1 runs every trait alone, which is what composition is "
                         "measured against)")
    ap.add_argument("--compose-runs", type=int, default=120, metavar="N",
                    help="how many stacks to sample (default 120)")
    ap.add_argument("--compose-seed", type=int, default=None, metavar="S",
                    help="seed for stack selection and for each trait's per-action "
                         "perturbation probability (default: derived from the run id, and "
                         "always recorded)")
    ap.add_argument("--compose-only", metavar="A,B,C", default="",
                    help="run exactly this stack, repeatedly if --compose-runs > 1; "
                         "the way to reproduce a finding")
    ap.add_argument("-j", "--jobs", type=int, default=JOBS_DEFAULT, metavar="N",
                    help=f"run cases in N worker processes (default {JOBS_DEFAULT}, max "
                         f"{JOBS_MAX}). Timing-sensitive cases always run serially.")
    ap.add_argument("--scratch-cap-gb", type=float, default=cfg.SCRATCH_CAP_GB,
                    metavar="N", help=f"abort if the scratch root exceeds N GiB "
                                      f"(default {cfg.SCRATCH_CAP_GB}; guards against a leak)")
    ap.add_argument("--replay", metavar="SIGNATURE", default="",
                    help="reconstruct the run that produced a finding, from its signature "
                         "(a fingerprint prefix; 6 chars is plenty) and stop")
    ap.add_argument("--author", action="store_true",
                    help="write a corpus script covering what no recorded run has "
                         "exercised, to stdout, and stop. Proposes; never runs")
    ap.add_argument("--calibrate", action="store_true",
                    help="measure the resource band between fixtures and stop")
    return ap

#!/usr/bin/env python3
"""busybody — chaos testing for haru-pack binaries. Does it fail WELL?

    python tools/busybody.py                      # every persona
    python tools/busybody.py --persona forger     # one persona
    python tools/busybody.py --list               # what would run, and why
    python tools/busybody.py --keep               # leave the wreckage for inspection
    python tools/busybody.py --triage             # past findings, grouped by fingerprint
    python tools/busybody.py --history            # every run, including interrupted ones
    python tools/busybody.py --analyze [RUN]      # did the sweep buy anything? what diverged?
    python tools/busybody.py --calibrate          # find the band that separates two packages

THE POINT IS NOT "DOES IT BREAK"

Anything breaks if you hit it hard enough. What matters is HOW. A launcher that refuses a
tampered payload with one clear line is working. A launcher that prints a Nim traceback
full of build-machine paths, or hangs, or — worst — exits 0 having quietly done the wrong
thing, is not. Every case below declares which of those it expects.

Outcomes:

    RAN       exit 0 and the app's marker in stdout
    REFUSED   non-zero with a one-line haru-pack diagnostic   (a guard fired: good)
    CRASHED   non-zero with a language-level traceback        (FINDING: INV-LAUNCH-06)
    HUNG      no exit inside the timeout                      (FINDING)
    SILENT    exit 0 but the app never ran                    (FINDING, the worst kind)

A case passes when the outcome is in its `expect` set. The FATAL outcomes — CRASHED,
HUNG, SILENT, SILENT-WEDGE and STALLED — are never acceptable, whatever the case declared:
that is the whole standard.

THE PERSONAS

Each is a mindset that generates a family of faults, not a single test:

    butterfingers  Not malicious. Interrupted downloads, Ctrl-C mid-stage, kill -9,
                   truncated files. Everything an unlucky user does by accident.
    squatter       Got there first. Pre-creates the cache directory, plants a `.ready`
                   token, drops a `uv` earlier on PATH. Tests trust-on-first-use.
    forger         Edits the artifact. Flips payload bytes, recomputes the footer digest
                   to match, rewrites the manifest. Tests what integrity claims are worth.
    vandal         Waits until it works, then wrecks it. Modifies a staged file, deletes
                   one, opens the tree to the world. Tests reuse-time verification.
    landlord       Owns the building. Read-only cache, no HOME, hostile umask, empty PATH.
                   Tests behaviour in environments nobody designs for.
    twin           Two of them, at once, on the same stage. Tests the race.
    timetraveller  Moves the clock and lies about location. Tests licence claims —
                   and is EXPECTED to get through, because the docs say those checks are
                   advisory. A pass here would mean the docs are wrong.

  APP-LEVEL personas. The seven above attack the launcher, which is byte-identical in every
  binary — so they answer the same regardless of what was packed. These attack the packaged
  APPLICATION, and are expected to diverge by package under `--fixtures top25`:

    cartographer   Messes with WHERE. Awkward cwd, symlinked invocation, read-only working
                   directory, hostile argv. Tests the run-in-place contract.
    polyglot       Locale and encoding. The C locale, legacy codecs, unicode in paths.
    mute           I/O shape. Closed stdin, a slammed-shut stdout pipe.
    impatient      Signals to the APP, after staging — Ctrl-C and SIGTERM mid-run.
    hoarder        Resource ceilings. Few file descriptors, tight address space, a
                   read-only TMPDIR. The most package-dependent of the lot.

THE JOURNAL, THE HEARTBEAT AND THE LEDGER  (adopted from lotek's BusyBody)

Every case result is appended and flushed the moment it finishes, so an interrupted run —
Ctrl-C, timeout, machine gone — keeps everything up to the case in flight. A heartbeat file
is rewritten as the run proceeds, so `--history` can tell a run that DIED from one that is
still going and from one that finished: an interrupted run shows up AS interrupted rather
than simply being absent.

Findings are also appended to a ledger kept OUTSIDE the repository (lotek's reasoning: a
file inside the tree is caught by git stash, worktree switches and branch changes, losing
history exactly when you are moving between branches to investigate). `--triage` rolls that
ledger up by fingerprint, so three cases failing for one reason read as one problem with a
count and a first-seen date instead of three unrelated failures.

EXIT CODES are a contract, also lotek's:

    0    every case behaved as expected
    1    findings
    130  interrupted

An interrupt wins over findings. A run the operator killed did not finish, and reporting
its partial findings as a completed verdict is the same lie facing the other way.

NO AI REQUIRED. Cases are ordinary Python functions; read one and you know what it does.
The journal and ledger are JSON Lines — greppable, and `--triage` needs nothing but the
file itself.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

# ── the case catalogue ────────────────────────────────────────────────────────────────
# Every import below is here for its SIDE EFFECT: the `@case(...)` decorators inside each
# module run on import and append to `busybody_config.CASES`. Nothing in this file calls
# into them, so they look unused and an "unused import" cleanup silently deletes a whole
# persona — no error, just a smaller sweep that still reports a clean bill of health.
#
# `tests/test_busybody_ledger.py` asserts that every persona in the roster has at least
# one case, which is what catches it.
import busybody_cases_app        # noqa: E402,F401
import busybody_cases_config     # noqa: E402,F401
import busybody_cases_directives  # noqa: E402,F401
import busybody_cases_exam       # noqa: E402,F401
import busybody_cases_io         # noqa: E402,F401
import busybody_cases_launch     # noqa: E402,F401
import busybody_cases_repro      # noqa: E402,F401
import busybody_cases_reveng     # noqa: E402,F401
import busybody_cases_stage      # noqa: E402,F401
import busybody_cases_trojan     # noqa: E402,F401
import busybody_docker           # noqa: E402,F401
import busybody_herd             # noqa: E402,F401
import busybody_traits           # noqa: E402,F401  (the composable trait catalogue)

# ── re-exported so `import busybody as bb` still reaches what it always did ────────────
from busybody_cases_exam import EXAMS, _exam_script, _sit_exam  # noqa: E402,F401
from busybody_cases_reveng import _reveng_build  # noqa: E402,F401
from busybody_cli import main  # noqa: E402
from busybody_compose_run import (_build_composed, _elf_machine, _payload_members,  # noqa: E402,F401
                                  _static_verdict, run_stack)
from busybody_config import (ADDRESS_SPACE_MB, CASES, DEFAULT_TIMEOUT_S, FATAL,  # noqa: E402,F401
                             JOBS_DEFAULT, JOBS_MAX, MARKER, OUT, RUNS, SCRATCH_CAP_GB,
                             case)
from busybody_fixtures import build_fixture, build_top25_fixtures, calibrate  # noqa: E402,F401
from busybody_guard import guard_single_instance  # noqa: E402,F401
from busybody_herd import (herd_collect, herd_deadline, herd_start,  # noqa: E402,F401
                           herd_verdict, stage_key)
from busybody_history import print_history, print_triage  # noqa: E402,F401
from busybody_report import (OUTCOME_MEANING, preserve, severity_for,  # noqa: E402,F401
                             write_report)
from busybody_runner import (Ctx, InfraFailure, blame, classify, clean_env,  # noqa: E402,F401
                             dir_bytes, infra_failure_reason, run_exe, stage_root, warm,
                             work_root_report)
from busybody_stall import StallWatch  # noqa: E402,F401
from busybody_sweep import compose_sweep, run_one, worker_pool  # noqa: E402,F401

if __name__ == "__main__":
    raise SystemExit(main(__doc__))

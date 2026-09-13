"""Everything the whole harness shares: where things live, and the knobs --flags set.

**One rule for this module: read everything in it as `cfg.NAME`.** Never
`from busybody_config import HERD_N`.

`main()` rewrites `WORK_ROOT`, `SCRATCH_CAP_GB`, `DEFAULT_TIMEOUT_S` and `HERD_N` from the
command line AFTER every other module has been imported, so a module that copied a value at
import time would keep the default and the flag would look plumbed while doing nothing —
which is exactly what the note on `DEFAULT_TIMEOUT_S` below records happening once already.
`REPO`, `OUT` and `RUNS` follow the same rule for the same reason from the other direction:
the tests redirect them, and `monkeypatch.setattr(cfg, "RUNS", tmp)` only reaches the code
that reads them if nothing has taken a private copy.

The rest — `MARKER`, `FATAL`, `CASES`, `case`, the JOBS bounds, `STALL_QUIET_S`,
`ADDRESS_SPACE_MB` — is genuinely constant and safe to import by name, but reading
everything the same way costs nothing and removes the question.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Values unchanged.
"""
from __future__ import annotations

import os
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

OUT = REPO / "busybody" / "out"
# Overridable because the default scratch filesystem may be quota'd; see
# work_root_report(). None means "tempfile's default", i.e. $TMPDIR.
WORK_ROOT: Path | None = None
# A sweep that leaks scratch should die at a number the operator chose, not at
# whatever the filesystem happens to allow. The 2026-09-10 sweep reached the 24 GiB
# user quota on /tmp; nobody had asked for 24 GiB, and nobody found out until it
# had written 470 bogus findings.
SCRATCH_CAP_GB = 8.0
RUNS = OUT / "runs"
MARKER = "BUSYBODY_OK"

# Never acceptable, in any case, whatever it declared.
#   CRASHED       the LAUNCHER dumped a traceback on the user
#   HUNG          nothing exited
#   SILENT        exit 0 and the app never ran
#   SILENT-WEDGE  a contradictory config built cleanly, said nothing, and produced a
#                 damaged artifact. Fatal for the same reason SILENT is: the operator was
#                 given no reason to look, and the failure surfaces at the customer.
#   STALLED       several processes were alive and none of them was making progress. Only
#                 an observer OUTSIDE every one of them can say this, which is why it is
#                 not a value classify() can return — see the herd persona.
#   ESCAPED       the PACKED PROJECT executed code on the build host through a path that is
#                 not documented as executing anything, or was not named in the build log.
#   SMUGGLED      bytes that were never in the project reached the distributed artifact — a
#                 key from outside the tree, a member name that escapes on extraction, or an
#                 argv that will run on the customer's machine under the vendor's signature.
# APP-CRASHED is deliberately NOT here: an application that raises under a limit a persona
# imposed on purpose is behaving correctly, and a case must opt into accepting it.
#
# WARNED is not here either, and cannot be: it means haru-pack resolved a conflict AND said
# which side lost. That is the behaviour the wedge persona is asking for, not a defect.
FATAL = ("CRASHED", "HUNG", "SILENT", "SILENT-WEDGE", "STALLED", "ESCAPED", "SMUGGLED")

# SANCTIONED is deliberately NOT fatal, for the same reason EXPOSED is not: it means a
# project-controlled capability haru-pack DOCUMENTS ran, and the build log named it before
# it ran. Folding that into ESCAPED would train the reader to skip the one outcome that
# distinguishes "we chose this" from "nobody knew".

CASES = []


def case(persona: str, expect, why: str, inv: str = "", remedy: str = "",
         serial: bool = False, per_fixture: bool = True, light: bool = False):
    """Register a chaos case.

    `expect`  outcomes that are acceptable.
    `why`     what this case simulates and why it matters. Printed in the report.
    `inv`     the INVARIANTS.md entry that governs it, if any.
    `remedy`  what to do when it fails. Written into the report so the reader does not
              have to work it out, or ask anyone.
    `serial`  this case measures TIME, so it must not share the machine. A case that sleeps
              for a fixed interval and then signals is asking "where had the process got to
              after 0.7 s?" — and the answer changes when seven other cases are competing
              for CPU. Under --jobs these run in a separate serial pass, after the rest.
              Marking a case serial costs wall clock; not marking one that needs it costs
              a flaky result that looks like a regression.
    `per_fixture`
              whether this case has anything to say about the packed package. The runtime
              personas attack a binary, so they run once per fixture. The `wedge` persona
              attacks a DECLARATION and builds its own artifact, so running it 25 times
              would repeat one answer 25 times and inflate the census — the exact thing
              --analyze exists to expose.
    `light`   preserve only the top-level files of this case's work directory, not the
              whole tree. A herd case's work dir holds one shared stage plus N transient
              staging copies of it, and preserve() copytrees directories whole.
    """
    def deco(fn):
        CASES.append({"name": fn.__name__, "persona": persona,
                      "expect": tuple(expect) if isinstance(expect, (list, tuple)) else (expect,),
                      "why": why, "inv": inv, "remedy": remedy, "serial": serial,
                      "per_fixture": per_fixture, "light": light, "fn": fn})
        return fn
    return deco


# The number of workers is capped rather than merely defaulted. Chaos cases run real
# binaries that stage real interpreters, so each worker holds a work directory (measured
# peak 452 MB) and spawns processes with their own rlimits. 8 was the ceiling asked for on
# this 20-core box; past that the timing-sensitive cases start reporting the load rather
# than the product.
JOBS_DEFAULT = 4
JOBS_MAX = 8

# The default wait for a case that does not ask for its own. --timeout sets this; it was
# parsed and never read before 2026-09-11, so every wait in the file was whatever literal
# happened to be nearest. A flag that looks plumbed and is not is worse than no flag.
DEFAULT_TIMEOUT_S = 180


# ================================================================ herd

# Every case above this line is one process, or two. The failure they structurally
# cannot reach is a whole-system stall, because a stall is emergent: from inside a child
# the only available fact is "I am waiting", and waiting is also what a healthy child
# does while another one stages. Nobody inside can tell those apart, so the herd needs
# an observer that is not one of the processes it judges.
#
# haru-pack has exactly one shared mutable resource — the stage directory under
# $XDG_CACHE_HOME/haru-pack, keyed by payload digest. `twin` already races N=2 on it and
# asserts atomicity, so the shape was right and only the scale and the observer were
# missing.
#
# THREE CASES, not 3*N. --triage ranks fingerprint groups by count, so sixteen cases
# failing on one stall would outrank a genuine unique finding sixteen to one. Each case
# here reduces over its own children and returns exactly ONE record; which children were
# cascades of the stall is evidence inside that record, not sixteen more records.
#
# Cost, stated so it is not a surprise: staging takes no lock, so each child extracts
# its own .tmp- copy and then races an atomic move. Peak disk under one work directory
# is therefore N times the staged tree — at the thick tier roughly 200 MB each, ~3 GB at
# N=16. That is half of why --herd-n exists; the other half is reproducing on a box with
# fewer cores.

HERD_N = 16          # --herd-n sets this, the way --timeout sets DEFAULT_TIMEOUT_S

# How long all three stall conditions must hold CONTINUOUSLY before the watchdog says
# STALLED.
#
# PROVISIONAL, but no longer only against a proxy. What this number wants is the longest
# genuine no-progress stretch of a healthy 16-way cold start, and the thick tier — the
# slowest, so the one that sets the bound — still has not been measured: a thick fixture
# cannot be built on this box at all, because there is no pinned sha256 for the CPython
# it wants and haru-pack refuses to stage an unverified interpreter (correctly).
#
# MEASURED 2026-09-11 against a REAL default-tier fixture, all three herd cases, 16-way,
# from a cold cache: longest quiet stretch 0.0s, over 9 to 13 ticks per case, at 9.6-15.2s
# wall each. Same answer as the proxy below, now on the real launcher doing real staging.
# The remaining gap is the thick tier's interpreter extraction, which is strictly slower.
#
# What WAS measured, 2026-09-11 on this box (20 cores, 62 GB, NVMe), is a PROXY with the
# same phases: 16 concurrent processes, each copying a 47 MB zip into its own
# <key>.tmp-<pid> directory under one shared base, extracting it (4516 files), sha256-ing
# every extracted file and renaming the tree into place — stageZip minus the interpreter
# start, uv and the network. Watched by this exact StallWatch. Two runs, cold and warm
# page cache: 30s and 11s wall, 10 and 6 samples, and a longest quiet stretch of 0.0s in
# both. No two consecutive samples were ever quiet, on either run.
#
# So the proxy does not measure the healthy quiet period; it bounds it below the sampling
# interval, which was 1.3-1.7s (the byte walk alone costs 345-662ms at 16 x 4516 files,
# and the tick is that plus tick_s). And the proxy is missing the two slowest phases a
# real cold start has, so even that bound is a LOWER one. Hence 40s: an order of
# magnitude above anything observed, not 2x.
# TODO: measure the thick tier. `--persona herd --herd-n 16 --tier thick` three times,
# read the "longest quiet stretch" figure the verdict record already prints, and set this
# above the largest of the three. Blocked today on the missing CPython pin above, so the
# number stands on the default-tier measurement plus an order of magnitude of headroom.
#
# Erring high costs detection latency. Erring low costs the case its meaning, and the
# harness has that lesson written down: tight_address_space first used 256 MB, under
# what a bare interpreter needs, so every package failed identically and the case
# discriminated nothing while looking thorough. A threshold under the real quiet period
# of a healthy cold start does the same thing pointing the other way — it cries stall on
# a working run, and a case that always fires is a case nobody reads.
#
# The limit of the method, measured while validating it: an application that deliberately
# idles is indistinguishable from a stall by these three signals. A fixture that only
# slept produced 6s of continuous quiet on a 4-way healthy herd. So the herd cases
# hold for fixtures that stage, print and exit — which is every busybody fixture — and a
# packaged app that waits on a network or a prompt for longer than this does not belong
# in this persona at any threshold.
STALL_QUIET_S = 40.0

# The address-space ceiling the `hoarder` persona imposes, and the band
# `--calibrate` measures against. Shared, so the two cannot drift apart and
# report that a fixture "fits" a limit no case actually applies.
ADDRESS_SPACE_MB = 768

# ── Single-instance run control (INV-CHAOS-13) ────────────────────────────────────────
# The registry lives at a FIXED path, NOT `tempfile.gettempdir()` — because a sweep sets its
# own `--work-root`/`$TMPDIR` to isolate scratch, and a gettempdir-derived registry would then
# move WITH that scratch dir, so two sweeps with different scratch roots would register in
# different places and never see each other, defeating the whole guard. (Found 2026-09-12: a
# top-100 sweep under a custom TMPDIR registered under that TMPDIR, not the shared location.)
# `$HARUPACK_BUSYBODY_REGISTRY` overrides for an unusual host.
#
# It lives HERE rather than in busybody_guard because the tests redirect it, which makes it a
# rebindable setting, and this module is where those live (see this file's docstring).
BB_REGISTRY = Path(os.environ.get("HARUPACK_BUSYBODY_REGISTRY") or "/tmp/harupack-busybody")
BB_STALE_S = 900.0                       # heartbeat/birth older than this = wedged or dead -> reap
BB_FORCE_ENV = "HARUPACK_BUSYBODY_FORCE"

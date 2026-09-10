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

A case passes when the outcome is in its `expect` set. CRASHED, HUNG and SILENT are never
acceptable, whatever the case — that is the whole standard.

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

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from haru_pack import overlay  # noqa: E402

from busybody_analyze import analyze_run, format_analysis  # noqa: E402
from busybody_compose import (  # noqa: E402
    TRAITS, BuildCtx, RunCtx, conflicts_in, describe_traits, realize,
    sample_combos, singleton_cases)
from busybody_ledger import (  # noqa: E402
    Journal, Reaper, fingerprint, free_dir, human_bytes, ledger_append, ledger_path,
    ledger_rollup, prune_runs, reap_orphans, scan_runs)

import busybody_traits  # noqa: E402,F401  (imported for the trait registrations)

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
# APP-CRASHED is deliberately NOT here: an application that raises under a limit a persona
# imposed on purpose is behaving correctly, and a case must opt into accepting it.
#
# WARNED is not here either, and cannot be: it means haru-pack resolved a conflict AND said
# which side lost. That is the behaviour the wedge persona is asking for, not a defect.
FATAL = ("CRASHED", "HUNG", "SILENT", "SILENT-WEDGE")

CASES = []


def case(persona: str, expect, why: str, inv: str = "", remedy: str = "",
         serial: bool = False, per_fixture: bool = True):
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
    """
    def deco(fn):
        CASES.append({"name": fn.__name__, "persona": persona,
                      "expect": tuple(expect) if isinstance(expect, (list, tuple)) else (expect,),
                      "why": why, "inv": inv, "remedy": remedy, "serial": serial,
                      "per_fixture": per_fixture, "fn": fn})
        return fn
    return deco


# The number of workers is capped rather than merely defaulted. Chaos cases run real
# binaries that stage real interpreters, so each worker holds a work directory (measured
# peak 452 MB) and spawns processes with their own rlimits. 8 was the ceiling asked for on
# this 20-core box; past that the timing-sensitive cases start reporting the load rather
# than the product.
JOBS_DEFAULT = 4
JOBS_MAX = 8


# ---------------------------------------------------------------- outcome classification

TRACEBACK_MARKERS = (
    "Traceback (most recent call last)",      # Python
    "Error: unhandled exception",             # Nim
    "[IndexDefect]", "[RangeDefect]", "[ValueError]", "[OSError]",
    "sysFatal", "signal SIGSEGV", "core dumped",
)


# The harness's own environment running out of room is not a chaos finding. Disk quota and
# no-space are never imposed deliberately by any persona — `hoarder` starves file
# descriptors, address space and TMPDIR writability, never capacity — so seeing one of these
# means the box gave up, and every result after it is garbage.
#
# Measured 2026-09-10, the hard way: a 925-run sweep exhausted the user quota on /tmp at case
# 168 and reported 470 "findings", all of them the same environment failure wearing 30
# different persona costumes. --analyze showed the tell immediately (the same five fixtures
# passing every case, and those five were the first five built) but the run had already
# written 470 rows to the findings ledger.
INFRA_MARKERS = (
    "Disk quota exceeded", "errno: 122", "[Errno 122]",
    "No space left on device", "errno: 28", "[Errno 28]",
    "Read-only file system) while writing the journal",
)


def dir_bytes(d: Path) -> int:
    """Apparent size of a tree. Metadata only, so it is cheap enough to call per case."""
    total = 0
    for root, _dirs, files in os.walk(d, onerror=lambda _e: None):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


class InfraFailure(RuntimeError):
    """The box, not the product. Aborts the sweep instead of scoring it."""


def infra_failure_reason(r: dict) -> str:
    """Return the environment failure in this result, or "" if it is a real outcome."""
    blob = (r.get("stdout") or "") + (r.get("stderr") or "")
    for m in INFRA_MARKERS:
        if m in blob:
            line = next((ln.strip() for ln in blob.splitlines() if m in ln), m)
            return line[:200]
    return ""


def work_root_report(root: Path) -> list:
    """Lines describing the scratch filesystem, including the trap that bit us.

    `df` reports free space on the filesystem. A user quota is invisible to it, so a box can
    report 31 GB free and still refuse the harness's next write at 24 GB. If the mount says
    `usrquota` or `grpquota`, say so — that number is the real ceiling and it is not the one
    df prints.
    """
    lines = []
    try:
        st = os.statvfs(root)
        free_gb = st.f_bavail * st.f_frsize / 1024**3
        lines.append(f"scratch    : {root}  ({free_gb:.1f} GiB free per statvfs)")
    except OSError as e:
        lines.append(f"scratch    : {root}  (could not stat: {e})")
        return lines
    try:
        mounts = Path("/proc/mounts").read_text().splitlines()
    except OSError:
        return lines
    best, opts = "", ""
    for ln in mounts:
        parts = ln.split()
        if len(parts) >= 4 and str(root).startswith(parts[1]) and len(parts[1]) > len(best):
            best, opts = parts[1], parts[3]
    if any(q in opts for q in ("usrquota", "grpquota", "prjquota", "quota")):
        lines.append(f"             {best} has a quota ({opts.split(',')[-1]}). The number "
                     f"above is NOT the ceiling —")
        lines.append("             a per-user quota is invisible to statvfs. Use "
                     "--work-root to move scratch")
        lines.append("             somewhere unquota'd if a long sweep dies with errno 122.")
    return lines


def blame(out: str, err: str) -> str:
    """Who failed: the launcher, the packaged app, or the OS?

    An app-level case makes this distinction load-bearing. "haru-pack refused to run" and
    "the application started and then died" are different facts, and a run under a tiny
    memory limit is SUPPOSED to produce the second. Without the split, a persona that
    stresses the application reads as a launcher defect.

    The launcher prefixes every diagnostic with "haru-pack:", which is what makes this
    cheap. An app traceback has no such prefix.

    Four parties, not two. This function can only distinguish the first two from output, so
    the others are set explicitly by whoever knows:

      launcher  haru-pack reported it. Always a defect unless a case expected it.
      app       the packaged application reported it. Expected when a persona starved it.
      os        the kernel refused before either got a turn — `not_executable` chmods the
                binary to 000, so exec is denied. Calling that "app" would be a lie in the
                direction that hides defects.
      harness   busybody itself broke (CASE-ERROR). Never a statement about haru-pack.
      builder   `haru-pack build` reported it, or should have. The wedge persona attacks a
                declaration rather than a binary, so its findings belong to the build, not
                to the launcher — a config contradiction is fixed in a different file by a
                different person.

    Every non-RAN result carries one. A missing blame surfaces in --analyze as a "?" bucket,
    which is a hole in triage rather than a finding — there were 25 in the 2026-09-10 sweep,
    all from run_exe's OSError path returning early without setting it.
    """
    blob = (out or "") + (err or "")
    if "haru-pack:" in blob:
        return "launcher"
    if any(m in blob for m in TRACEBACK_MARKERS) or blob.strip():
        return "app"
    return "unknown"


def classify(rc, out: str, err: str, timed_out: bool) -> str:
    """Map a process outcome onto the vocabulary.

    CRASHED vs APP-CRASHED is the distinction that makes app-level personas usable. A Nim
    traceback out of the launcher is always a defect. A Python traceback out of the PACKAGED
    APPLICATION, when a case deliberately starved it, is the application declining to run in
    the box it was given — the correct answer, not a bug in haru-pack.

    Measured 2026-09-10: numpy under a 768 MB address-space ceiling raises during
    `import numpy._core.multiarray`. Calling that CRASHED made a working, calibrated case
    look like a product defect.
    """
    blob = (out or "") + (err or "")
    if timed_out:
        return "HUNG"
    if any(m in blob for m in TRACEBACK_MARKERS):
        return "CRASHED" if blame(out, err) == "launcher" else "APP-CRASHED"
    if rc == 0:
        return "RAN" if MARKER in out else "SILENT"
    return "REFUSED"


def run_exe(exe: Path, cwd: Path, env=None, timeout: int = 120, args=(),
            rlimits=None, argv0=None) -> dict:
    """Run a packed binary and classify what happened.

    `rlimits` applies resource limits in the child ({resource.RLIMIT_AS: (soft, hard)}),
    which is how the app-level personas starve an application without touching the host.
    `argv0` overrides argv[0] without renaming the file.
    """
    pre = None
    if rlimits:
        import resource

        def pre():          # noqa: E306 - runs in the child, after fork, before exec
            for what, limits in rlimits.items():
                try:
                    resource.setrlimit(what, limits)
                except (ValueError, OSError):
                    pass

    t0 = time.monotonic()
    try:
        argv = [argv0 or str(exe), *args]
        r = subprocess.run(argv, capture_output=True, text=True, executable=str(exe),
                           timeout=timeout, cwd=cwd, env=env, preexec_fn=pre)
        rc, out, err, to = r.returncode, r.stdout, r.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, out, err, to = None, (e.stdout or b"").decode("utf8", "replace"), \
            (e.stderr or b"").decode("utf8", "replace"), True
    except (PermissionError, OSError) as e:
        # The OS refused to exec the file at all. That is a refusal by the system, not a
        # haru-pack crash, and it is what "the executable bit got dropped" looks like.
        return {"outcome": "REFUSED", "rc": None, "seconds": round(time.monotonic() - t0, 1),
                "blame": "os", "stdout": "", "stderr": f"{type(e).__name__}: {e}"}
    outcome = classify(rc, out, err, to)
    return {"outcome": outcome, "rc": rc, "seconds": round(time.monotonic() - t0, 1),
            "blame": blame(out, err) if outcome != "RAN" else "none",
            "stdout": (out or "").strip()[-400:], "stderr": (err or "").strip()[-400:]}


# Variables that make a child process adopt the CALLER's Python environment. busybody runs
# real haru-pack binaries, which run uv, which honours these — so leaving them in place lets
# a chaos case reach back out and modify the environment busybody itself is running from.
#
# This is not hypothetical. The first run of `payload_reforged_with_valid_crcs` rebuilt this
# repository's own .venv against the staged interpreter, leaving .venv/bin/python a dangling
# symlink into a work directory that was then deleted. A chaos harness that damages the
# checkout it is testing is worse than no harness.
_CONTAMINATING = ("VIRTUAL_ENV", "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP",
                  "UV_PROJECT_ENVIRONMENT", "UV_PYTHON", "UV_CACHE_DIR", "CONDA_PREFIX")


def clean_env(cache: Path, **extra) -> dict:
    """A run in its own cache, isolated from the caller's Python environment."""
    env = dict(os.environ)
    for var in _CONTAMINATING:
        env.pop(var, None)
    env["XDG_CACHE_HOME"] = str(cache)
    env.update({k: v for k, v in extra.items() if v is not None})
    for k, v in extra.items():
        if v is None:
            env.pop(k, None)
    return env


def stage_root(cache: Path) -> Path | None:
    """The staged tree the launcher created under this cache, if any."""
    base = cache / "haru-pack"
    if not base.is_dir():
        return None
    dirs = [d for d in base.iterdir() if d.is_dir() and not d.name.endswith(".tmp")]
    return sorted(dirs)[0] if dirs else None


def warm(exe: Path, work: Path) -> tuple:
    """Run once so a stage exists. Returns (cache, result)."""
    cache = work / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    return cache, run_exe(exe, work, env=clean_env(cache))


# ================================================================ butterfingers

@case("butterfingers", ("REFUSED",),
      "A download that stopped halfway leaves a short file. It must be reported, not "
      "executed and not crashed on.",
      inv="INV-LAUNCH-05, INV-LAUNCH-06",
      remedy="A short file has no valid footer. overlay.findFooter should report that and "
             "exit; if you got a traceback, the top-level handler in main.nim is missing or "
             "the failure is a Defect (which CatchableError cannot catch) and needs an "
             "explicit bounds check instead.")
def truncated_binary(exe: Path, work: Path) -> dict:
    victim = work / "truncated"
    data = exe.read_bytes()
    victim.write_bytes(data[: len(data) // 2])
    victim.chmod(0o755)
    return run_exe(victim, work, env=clean_env(work / "c"))


@case("butterfingers", ("REFUSED",),
      "Only the launcher arrived; the payload never did. The footer is gone entirely.",
      inv="INV-LAUNCH-05",
      remedy="Expect 'no payload appended'. Anything else means findFooter is reading past "
             "the end of a short file.")
def payload_lopped_off(exe: Path, work: Path) -> dict:
    victim = work / "nopayload"
    info = overlay.verify(exe)
    victim.write_bytes(exe.read_bytes()[: info["payload_off"]])
    victim.chmod(0o755)
    return run_exe(victim, work, env=clean_env(work / "c"))


@case("butterfingers", ("RAN",),
      "Ctrl-C during the first-run staging, then run again. The half-written stage must "
      "not poison every later run — recovery is the whole point of a cache.",
      inv="INV-STAGE-01",
      remedy="A leftover .tmp- directory or a stage with no .ready must be discarded and "
             "rebuilt, not reused and not treated as fatal. Check stageZip's reuse path.",
      serial=True)
def killed_mid_stage(exe: Path, work: Path) -> dict:
    cache = work / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    p = subprocess.Popen([str(exe)], cwd=work, env=clean_env(cache),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.5)                       # let it get into staging
    p.send_signal(signal.SIGKILL)
    p.wait(timeout=30)
    return run_exe(exe, work, env=clean_env(cache))


@case("butterfingers", ("REFUSED", "RAN"),
      "A file manager copy that dropped the executable bit. Refusing is fine; a confusing "
      "crash is not.",
      remedy="Nothing to fix in haru-pack if this refuses — the OS did it. Recorded so the "
             "failure mode is known and does not get mistaken for corruption.")
def not_executable(exe: Path, work: Path) -> dict:
    victim = work / "noexec"
    shutil.copy2(exe, victim)
    victim.chmod(0o644)
    return run_exe(victim, work, env=clean_env(work / "c"))


# ================================================================ squatter

@case("squatter", ("REFUSED", "RAN"),
      "Something is already sitting at the stage path with a plausible .ready token. It "
      "token. It must be verified or replaced — never trusted and executed.",
      inv="INV-STAGE-01",
      remedy="SILENT here means the squatter's code ran: the trust-on-first-use bug is "
             "back. stageZip must validate the .ready token against this payload's digest "
             "and re-hash every file in .stage-files before reusing a tree.")
def precreated_stage_with_fake_ready(exe: Path, work: Path) -> dict:
    cache, first = warm(exe, work)
    root = stage_root(cache)
    if root is None:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0,
                "stdout": "no stage produced", "stderr": ""}
    shutil.rmtree(root)
    root.mkdir(parents=True)
    (root / ".ready").write_text("1")                 # the old, trusted-blindly token
    (root / "app").mkdir()
    (root / "app" / "evil.py").write_text("print('SQUATTER WAS HERE')\n")
    r = run_exe(exe, work, env=clean_env(cache))
    if "SQUATTER WAS HERE" in r["stdout"]:
        r["outcome"] = "SILENT"                       # ran the squatter's tree
    return r


@case("squatter", ("RAN",),
      "A `uv` earlier on PATH than the bundled one. A thick binary claims to be hermetic, "
      "so it must ignore it.",
      inv="INV-LAUNCH-04",
      remedy="SILENT means findUv consulted PATH before the bundled binary. The thick tier "
             "must use its own vendor/uv unconditionally and die if it is missing.")
def uv_planted_on_path(exe: Path, work: Path) -> dict:
    fake = work / "fakebin"
    fake.mkdir(parents=True, exist_ok=True)
    uv = fake / "uv"
    uv.write_text("#!/bin/sh\necho 'PLANTED UV RAN' >&2\nexit 3\n")
    uv.chmod(0o755)
    env = clean_env(work / "c2", PATH=f"{fake}:{os.environ.get('PATH', '')}")
    r = run_exe(exe, work, env=env)
    if "PLANTED UV RAN" in r["stderr"]:
        r["outcome"] = "SILENT"
    return r


@case("squatter", ("REFUSED", "RAN"),
      "The cache directory exists but is owned by nobody in particular and world-writable "
      "— a shared /tmp-style cache.",
      inv="INV-STAGE-01",
      remedy="Refusing is the stronger behaviour. If it runs, confirm assertSafePath still "
             "rejects group/world-writable stage paths on POSIX.")
def world_writable_cache(exe: Path, work: Path) -> dict:
    cache = work / "wwcache"
    (cache / "haru-pack").mkdir(parents=True, exist_ok=True)
    os.chmod(cache / "haru-pack", 0o777)
    return run_exe(exe, work, env=clean_env(cache))


# ================================================================ forger

@case("forger", ("REFUSED",),
      "One byte flipped inside the payload, footer untouched. This is exactly what "
      "INV-LAUNCH-01's digest check exists to catch.",
      inv="INV-LAUNCH-01",
      remedy="A RAN here means the launcher is not verifying its payload digest — the "
             "check was removed or is running after staging. It must happen before "
             "openContainer and before stageZip.")
def payload_byte_flipped(exe: Path, work: Path) -> dict:
    victim = work / "flipped"
    data = bytearray(exe.read_bytes())
    info = overlay.verify(exe)
    data[info["payload_off"] + 64] ^= 0xFF
    victim.write_bytes(bytes(data))
    victim.chmod(0o755)
    return run_exe(victim, work, env=clean_env(work / "c"))


@case("forger", ("RAN",),
      "The real version of the tamper attack: rebuild the payload zip properly — valid "
      "CRC32s and all — then recompute the footer digest to match. This is EXPECTED to "
      "succeed. INV-LAUNCH-01 says in its own Note that the footer digest is not a MAC, "
      "and this case is what that sentence means in practice. A first draft of this case "
      "just flipped a byte and got REFUSED, which looked like tamper-detection but was "
      "actually the zip's own CRC32 refusing a corrupt archive — an incidental check that "
      "an attacker simply would not trip.",
      inv="INV-LAUNCH-01 (Note), INV-LAUNCH-03",
      remedy="RAN is the documented, expected outcome and is why INV-LAUNCH-03 (a real "
             "signature) is still open. If this ever REFUSES, the payload gained genuine "
             "authentication: update INV-LAUNCH-01's Note, and promote INV-LAUNCH-03 if a "
             "signature is what did it.")
def payload_reforged_with_valid_crcs(exe: Path, work: Path) -> dict:
    """Craft a valid replacement payload rather than corrupting the existing one."""
    import io
    import zipfile

    info = overlay.verify(exe)
    data = exe.read_bytes()
    off, ln = info["payload_off"], info["payload_len"]
    original = data[off:off + ln]
    if original[:2] != b"PK":
        return {"outcome": "RAN", "rc": 0, "seconds": 0,
                "stdout": "payload is not a plain zip (encrypted build); case not applicable",
                "stderr": ""}

    buf = io.BytesIO()
    replaced = False
    with zipfile.ZipFile(io.BytesIO(original)) as src, \
         zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            body = src.read(item.filename)
            if item.filename.endswith("app.py") and not replaced:
                body = b"print('FORGED PAYLOAD RAN')\n"
                replaced = True
            dst.writestr(item, body)
    forged = buf.getvalue()

    launcher = work / "stub"
    launcher.write_bytes(data[:off])
    victim = work / "reforged"
    overlay.attach(launcher, forged, victim)      # writes a correct footer for the new bytes
    victim.chmod(0o755)

    r = run_exe(victim, work, env=clean_env(work / "c"))
    if "FORGED PAYLOAD RAN" in r["stdout"]:
        # Expected: the substituted code ran. Report it as RAN, since the documented
        # behaviour is that a recomputed digest is accepted.
        r["outcome"] = "RAN"
        r["stdout"] = "FORGED PAYLOAD RAN (expected — the footer digest is not a MAC)"
    return r


@case("forger", ("REFUSED",),
      "Absurd payload extent in the footer: 2**63 bytes at an impossible offset. Must be "
      "rejected by size, not discovered by allocating (INV-LAUNCH-05).",
      inv="INV-LAUNCH-05",
      remedy="CRASHED means footerFault is not validating the extent against the file size "
             "before use. A RangeDefect is a Defect, not a CatchableError, so it cannot be "
             "caught downstream — it has to be checked up front.")
def footer_extent_is_nonsense(exe: Path, work: Path) -> dict:
    import struct
    victim = work / "badextent"
    data = bytearray(exe.read_bytes())
    at = overlay.verify(exe)["footer_at"]
    struct.pack_into("<Q", data, at + 12, 2 ** 63)    # payloadOff
    victim.write_bytes(bytes(data))
    victim.chmod(0o755)
    return run_exe(victim, work, env=clean_env(work / "c"))


@case("forger", ("REFUSED",),
      "A second, later footer appended after the real one. Backward scan finds the last "
      "magic, so an attacker who appends wins unless the extent is validated.",
      inv="INV-LAUNCH-05",
      remedy="The appended footer names an extent outside the file, so the size check "
             "should reject it. A crash means that check is missing or runs too late.")
def second_footer_appended(exe: Path, work: Path) -> dict:
    import struct
    victim = work / "twofooters"
    data = bytearray(exe.read_bytes())
    fake = (overlay.MAGIC + struct.pack("<HHQQ", 1, 0, len(data) + 999999, 4096)
            + b"\x00" * 32 + overlay.TAIL)
    victim.write_bytes(bytes(data) + fake)
    victim.chmod(0o755)
    return run_exe(victim, work, env=clean_env(work / "c"))


@case("forger", ("RAN", "REFUSED"),
      "HARUPACK_DEV_STAGE pointed at an attacker's tree. A release build must IGNORE the "
      "variable and run its own payload — so RAN is the correct outcome here, and SILENT "
      "(the attacker's tree executing) is the failure. Refusing outright is also fine. "
      "The first version of this case expected REFUSED, which was simply wrong: ignoring "
      "an environment variable is not the same as rejecting the binary.",
      inv="INV-LAUNCH-02",
      remedy="SILENT means a release build still honours HARUPACK_DEV_STAGE — the "
             "`when defined(haruDev)` gate is gone. Verify with: strings <binary> | grep "
             "HARUPACK_DEV_STAGE (should print nothing).")
def dev_stage_redirect(exe: Path, work: Path) -> dict:
    evil = work / "evil-stage"
    (evil / "app").mkdir(parents=True, exist_ok=True)
    (evil / "manifest.toml").write_text(
        'name = "evil"\nkind = "script"\nentrypoint = ["evil.py"]\n')
    (evil / "app" / "evil.py").write_text("print('DEV STAGE HIJACK')\n")
    r = run_exe(exe, work, env=clean_env(work / "c", HARUPACK_DEV_STAGE=str(evil)))
    if "DEV STAGE HIJACK" in r["stdout"]:
        r["outcome"] = "SILENT"
    elif r["outcome"] == "RAN":
        r["outcome"] = "RAN"          # ignored the variable and ran normally: correct
    return r


# ================================================================ vandal

@case("vandal", ("REFUSED",),
      "Run once successfully, then edit a staged file. The next run must notice — this is "
      "INV-STAGE-01's whole reason to exist.",
      inv="INV-STAGE-01",
      remedy="SILENT means the modified file ran: verifyStagedDir is not re-hashing "
             "recorded files on reuse, or the file was wrongly treated as runtime-mutable. "
             "Check isRuntimeMutable's exemption list — it has been wrong twice.")
def staged_file_modified_after_success(exe: Path, work: Path) -> dict:
    cache, first = warm(exe, work)
    root = stage_root(cache)
    if root is None:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0, "stdout": "no stage", "stderr": ""}
    victims = [p for p in root.rglob("*.py") if p.is_file()]
    if not victims:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0,
                "stdout": "no staged .py to vandalise", "stderr": ""}
    v = victims[0]
    v.chmod(v.stat().st_mode | stat.S_IWUSR)
    v.write_text("print('VANDALISED')\n")
    r = run_exe(exe, work, env=clean_env(cache))
    if "VANDALISED" in r["stdout"]:
        r["outcome"] = "SILENT"
    return r


@case("vandal", ("REFUSED",),
      "Delete a recorded file from a working stage. Missing is as bad as modified.",
      inv="INV-STAGE-01",
      remedy="verifyStagedDir must treat a missing recorded file as fatal, not skip it.")
def staged_file_deleted(exe: Path, work: Path) -> dict:
    cache, _ = warm(exe, work)
    root = stage_root(cache)
    if root is None:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0, "stdout": "no stage", "stderr": ""}
    victims = [p for p in root.rglob("*.py") if p.is_file()]
    if not victims:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0, "stdout": "nothing to delete",
                "stderr": ""}
    victims[0].unlink()
    return run_exe(exe, work, env=clean_env(cache))


@case("vandal", ("REFUSED", "RAN"),
      "Open the whole staged tree to the world after it worked. Group/other-writable code "
      "is code anyone can replace before the next run.",
      inv="INV-STAGE-01",
      remedy="Refusing is stronger. If it runs, the mode check on the stage root is not "
             "being applied on the reuse path.")
def stage_opened_to_the_world(exe: Path, work: Path) -> dict:
    cache, _ = warm(exe, work)
    root = stage_root(cache)
    if root is None:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0, "stdout": "no stage", "stderr": ""}
    os.chmod(root, 0o777)
    return run_exe(exe, work, env=clean_env(cache))


@case("vandal", ("REFUSED", "RAN"),
      "Replace the stage directory with a symlink pointing somewhere else entirely.",
      inv="INV-STAGE-01",
      remedy="assertSafePath uses lstat specifically to catch this. A run means the symlink "
             "was followed.")
def stage_replaced_with_symlink(exe: Path, work: Path) -> dict:
    cache, _ = warm(exe, work)
    root = stage_root(cache)
    if root is None:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0, "stdout": "no stage", "stderr": ""}
    elsewhere = work / "elsewhere"
    elsewhere.mkdir(exist_ok=True)
    shutil.rmtree(root)
    root.symlink_to(elsewhere, target_is_directory=True)
    return run_exe(exe, work, env=clean_env(cache))



@case("vandal", ("REFUSED",),
      "Modify a native library (.so/.pyd) in a staged tree, not a .py file. Verification "
      "must cover compiled artifacts too — they are the ones an attacker would rather "
      "replace, and the ones a naive 'check the Python files' implementation misses. "
      "Measured 2026-09-10: catches a flipped byte in a wheel's .so AND in the bundled "
      "interpreter's own libpython. NOTE: this was added believing it would be "
      "payload-sensitive (pure-Python packages having no .so to modify). That was wrong "
      "at the thick tier, where every payload ships an interpreter and therefore ships "
      ".so files — iniconfig, which is pure Python, caught a modified libpython. The case "
      "is worth keeping for what it does prove; it does NOT vary by package.",
      inv="INV-STAGE-01",
      remedy="SILENT or RAN means .stage-files does not record native libraries, or "
             "isRuntimeMutable exempts them. Compiled code must be covered by the same "
             "digest manifest as source.")
def native_library_modified_after_success(exe: Path, work: Path) -> dict:
    cache, _ = warm(exe, work)
    root = stage_root(cache)
    if root is None:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0, "stdout": "no stage", "stderr": ""}
    libs = [p for p in root.rglob("*.so") if p.is_file()] + \
           [p for p in root.rglob("*.pyd") if p.is_file()]
    # Prefer something inside the app's own venv over the bundled interpreter's stdlib.
    libs.sort(key=lambda p: (".venv" not in str(p), len(str(p))))
    if not libs:
        # Only reachable at a tier that bundles no interpreter; at thick this never fires.
        return {"outcome": "REFUSED", "rc": None, "seconds": 0,
                "stdout": "", "stderr": "SKIPPED: no native library in the payload"}
    v = libs[0]
    v.chmod(v.stat().st_mode | stat.S_IWUSR)
    data = bytearray(v.read_bytes())
    data[len(data) // 2] ^= 0xFF          # flip a byte in the middle of the machine code
    v.write_bytes(bytes(data))
    return run_exe(exe, work, env=clean_env(cache))


# ================================================================ landlord

@case("landlord", ("REFUSED",),
      "The cache directory is read-only. Nothing can be staged; say so instead of dying "
      "in a way nobody can act on.",
      inv="INV-LAUNCH-06",
      remedy="Expect a clear 'cannot write to cache' style message naming the path. A "
             "traceback here is the classic unhandled OSError.")
def read_only_cache(exe: Path, work: Path) -> dict:
    cache = work / "rocache"
    cache.mkdir(parents=True, exist_ok=True)
    os.chmod(cache, 0o555)
    try:
        return run_exe(exe, work, env=clean_env(cache))
    finally:
        os.chmod(cache, 0o755)


@case("landlord", ("REFUSED", "RAN"),
      "No HOME and no XDG_CACHE_HOME. The launcher has to put the stage somewhere; "
      "whatever it decides, it must not crash deciding.",
      inv="INV-LAUNCH-06",
      remedy="getHomeDir() with no HOME is the usual culprit. Either fall back or refuse "
             "with a message; do not propagate the exception.")
def no_home_at_all(exe: Path, work: Path) -> dict:
    env = clean_env(work / "unused-cache")
    env.pop("HOME", None)
    env.pop("XDG_CACHE_HOME", None)          # clean_env sets it; this case removes both
    return run_exe(exe, work, env=env)


@case("landlord", ("REFUSED", "RAN"),
      "An empty PATH. A thick binary should not care; anything else should complain "
      "clearly rather than exploding.",
      remedy="A thick binary should not consult PATH at all. Other tiers should say they "
             "cannot find uv, naming what they looked for.")
def empty_path(exe: Path, work: Path) -> dict:
    return run_exe(exe, work, env=clean_env(work / "c", PATH=""))


@case("landlord", ("RAN",),
      "A paranoid umask (077). Files created during staging must still be usable by the "
      "process that made them.",
      inv="INV-STAGE-01",
      remedy="Staging hardens permissions deliberately; make sure it does not strip the "
             "owner's own read/execute bits under a restrictive umask.")
def hostile_umask(exe: Path, work: Path) -> dict:
    old = os.umask(0o077)
    try:
        return run_exe(exe, work, env=clean_env(work / "umaskcache"))
    finally:
        os.umask(old)


# ================================================================ twin

@case("twin", ("RAN",),
      "Two first runs at the same instant on one cold cache. Both should end up working: "
      "the loser of the race must not get a half-built stage.",
      inv="INV-STAGE-01",
      remedy="Staging is meant to be atomic: build in a per-process .tmp- directory, then "
             "move into place. A failure here means the move is not atomic or the loser "
             "reads a partially written tree.",
      serial=True)
def two_cold_starts_at_once(exe: Path, work: Path) -> dict:
    cache = work / "racecache"
    cache.mkdir(parents=True, exist_ok=True)
    env = clean_env(cache)
    a = subprocess.Popen([str(exe)], cwd=work, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    b = subprocess.Popen([str(exe)], cwd=work, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    outs = []
    for p in (a, b):
        try:
            o, e = p.communicate(timeout=180)
            outs.append((p.returncode, o, e))
        except subprocess.TimeoutExpired:
            p.kill()
            outs.append((None, "", "timeout"))
    worst = "RAN"
    detail = []
    for rc, o, e in outs:
        c = classify(rc, o, e, rc is None)
        detail.append(f"rc={rc} {c}")
        if c in FATAL or (c == "REFUSED" and worst == "RAN"):
            worst = c
    return {"outcome": worst, "rc": outs[0][0], "seconds": 0,
            "stdout": " ; ".join(detail), "stderr": (outs[0][2] or "")[-300:]}


# ================================================================ timetraveller

@case("timetraveller", ("RAN",),
      "Spoof the location the geo check reads. HARUPACK_GEO is supplied by the person "
      "being restricted, so this MUST get through — the docs say the check is advisory. "
      "A refusal here would mean the documentation understates what geo does.",
      inv="see THREAT_MODEL.md",
      remedy="RAN is correct and expected. If this ever refuses, the geo check became "
             "load-bearing and README/THREAT_MODEL must stop calling it advisory.")
def geo_spoofed(exe: Path, work: Path) -> dict:
    return run_exe(exe, work, env=clean_env(work / "c", HARUPACK_GEO="XX"))


@case("timetraveller", ("RAN",),
      "An unencrypted binary must ignore licence variables entirely rather than taking a "
      "detour through code that does not apply to it.",
      remedy="An unencrypted payload must not enter the licence path at all.")
def licence_vars_on_an_unencrypted_binary(exe: Path, work: Path) -> dict:
    return run_exe(exe, work, env=clean_env(work / "c", HARUPACK_SECRET="not-a-secret",
                                            HARUPACK_GEO="ZZ"))



OUTCOME_MEANING = {
    "RAN": "the app ran and printed its marker",
    "REFUSED": "haru-pack stopped with a non-zero exit and a diagnostic (a guard fired)",
    "CRASHED": "a raw language-level traceback reached the user",
    "HUNG": "no exit within the timeout",
    "SILENT": "exit 0, but the app never ran",
    "APP-CRASHED": "the packaged application raised; the launcher was not at fault",
    "CASE-ERROR": "the chaos case itself failed; this is a bug in busybody, not in haru-pack",
    "WARNED": "a contradictory config built, and the build said which side it overrode",
    "SILENT-WEDGE": ("a contradictory config built with no mention of the conflict, and the "
                     "artifact carries the damage"),
    "EXPOSED": ("a secret was recovered from a surface haru-pack DOCUMENTS as recoverable "
                "(the staged plaintext on the running user's disk). Not a defect; the honest "
                "reality the reverse_engineer persona keeps visible"),
    "LEAKED": ("a secret was recovered from a surface that is supposed to protect it — the "
               "encrypted binary at rest, or a tree readable by other users. A defect"),
    "REFUSED-UNRELATED": ("the build refused, but for something other than the wedge — the "
                          "case never reached what it meant to test"),
}


def write_report(results: list, exe_name: str, path: Path, run_id: str = "",
                 interrupted: bool = False) -> None:
    """A report a human reads on its own. No JSON, no cross-referencing, no AI.

    Every finding carries: what was done, what happened, what should have happened, why the
    case exists at all, the invariant that governs it, and the next step. If you are holding
    this file and nothing else, that has to be enough.
    """
    bad = [r for r in results if not r["ok"]]
    W = 78
    L = []
    L.append("=" * W)
    L.append("busybody report — haru-pack chaos testing")
    L.append("=" * W)
    L.append("")
    L.append(f"run          : {run_id or '(unrecorded)'}")
    L.append(f"fixture      : {exe_name}")
    L.append(f"cases run    : {len(results)}")
    L.append(f"as expected  : {len(results) - len(bad)}")
    L.append(f"findings     : {len(bad)}")
    if interrupted:
        L.append("")
        L.append("  *** THIS RUN WAS INTERRUPTED ***")
        L.append("  The cases below are what completed before it stopped, not the whole")
        L.append("  suite. Do not read the counts above as a result.")
    L.append("")
    L.append("WHAT THIS TOOL CHECKS")
    L.append("")
    L.append("  Not whether haru-pack can be broken — anything can. Whether it breaks WELL.")
    L.append("  A clear refusal is a pass. A traceback, a hang, or a silent success is not,")
    L.append("  in any case, ever.")
    L.append("")
    L.append("OUTCOMES AND WHAT THEY MEAN")
    L.append("")
    for k, v in OUTCOME_MEANING.items():
        L.append(f"  {k:11} {v}")
    L.append("")
    L.append("  Always a finding, whatever the case expected: CRASHED, HUNG, SILENT.")
    L.append("")

    L.append("-" * W)
    L.append("SUMMARY")
    L.append("-" * W)
    L.append("")
    L.append(f"  {'persona':14} {'case':42} {'outcome':9} {'severity':8} verdict")
    L.append(f"  {'-' * 14} {'-' * 42} {'-' * 9} {'-' * 8} -------")
    for r in results:
        L.append(f"  {r['persona']:14} {r['name']:42} {r['outcome']:9} "
                 f"{r.get('severity', ''):8} {'ok' if r['ok'] else 'FINDING'}")
    L.append("")

    if not bad:
        L.append("-" * W)
        L.append("NO FINDINGS")
        L.append("-" * W)
        L.append("")
        L.append("  Every case behaved as expected. Note what that does and does not mean:")
        L.append("  these are the faults somebody thought of. A clean run is evidence, not")
        L.append("  proof. Adding a case that fails is more valuable than re-running these.")
        L.append("")
    else:
        L.append("-" * W)
        L.append(f"FINDINGS ({len(bad)})")
        L.append("-" * W)
        for i, r in enumerate(bad, 1):
            L.append("")
            L.append(f"[{i}] {r['persona']} / {r['name']}")
            L.append("")
            L.append(f"    OUTCOME   {r['outcome']} — {OUTCOME_MEANING.get(r['outcome'], '?')}")
            L.append(f"    EXPECTED  {' or '.join(r['expect'])}")
            if r["outcome"] in FATAL:
                L.append("    SEVERITY  always a finding, regardless of what was expected")
            if r.get("inv"):
                L.append(f"    INVARIANT {r['inv']}  (see INVARIANTS.md)")
            if r.get("fingerprint"):
                L.append(f"    FINGERPRINT {r['fingerprint']}  "
                         f"(`--triage` groups repeats of this)")
            if r.get("artifacts"):
                L.append(f"    ARTIFACTS {r['artifacts']}")
            L.append(f"    EXIT      {r['rc']}")
            L.append("")
            L.append("    WHAT THIS CASE SIMULATES")
            for line in _wrap(" ".join(r["why"].split()), W - 8):
                L.append(f"        {line}")
            if r.get("remedy"):
                L.append("")
                L.append("    WHAT TO DO")
                for line in _wrap(" ".join(r["remedy"].split()), W - 8):
                    L.append(f"        {line}")
            for stream in ("stderr", "stdout"):
                if r.get(stream):
                    L.append("")
                    L.append(f"    {stream.upper()} (last {len(r[stream])} chars)")
                    for line in r[stream].splitlines()[-8:]:
                        L.append(f"        {line[:W - 8]}")
        L.append("")

    L.append("-" * W)
    L.append("HOW TO RE-RUN ONE CASE")
    L.append("-" * W)
    L.append("")
    L.append("  python tools/busybody.py --case <case name>  --keep")
    L.append("")
    L.append("  --keep leaves each case's working directory under busybody/out/ so you can")
    L.append("  inspect the binary and the cache it produced.")
    L.append("")
    path.write_text("\n".join(L) + "\n")


def _wrap(text: str, width: int) -> list:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines or [""]



# ---------------------------------------------------------------- severity, artifacts

def severity_for(c: dict, r: dict, ok: bool) -> str:
    """Closed vocabulary — critical / warning / note. Never "error", never "info".

    A fixed set means a reader learns three words once, and a report cannot quietly grow a
    fourth level nobody has calibrated. Taken from lotek, which uses the same three.
    """
    if ok:
        return "note"
    if r["outcome"] in ("CRASHED", "SILENT", "HUNG", "SILENT-WEDGE"):
        return "critical"      # a traceback at the user, the wrong code running, or a wedge
    if r["outcome"] == "APP-CRASHED":
        return "note"          # the app declined the box it was given; not haru-pack's doing
    if r["outcome"] == "CASE-ERROR":
        return "note"          # busybody's own bug, not haru-pack's — say so, do not inflate
    if r["outcome"] == "REFUSED-UNRELATED":
        return "note"          # the CASE missed its target; fix the case before believing it
    if r["outcome"] == "LEAKED":
        return "critical"      # a secret where it must not be
    if r["outcome"] == "EXPOSED":
        return "note"          # documented reality, kept visible, not a defect
    return "warning"           # refused where it should have run, or the reverse


def preserve(run_dir: Path, case_name: str, work: Path) -> str:
    """Copy a failing case's wreckage somewhere it will still exist tomorrow.

    Unconditional for findings: `--keep` is a flag people remember only after the
    interesting run, and you cannot triage a crash you threw away.
    """
    dest = run_dir / "findings" / case_name
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    kept = []
    for child in sorted(work.iterdir()):
        try:
            if child.is_file() and child.stat().st_size < 300 * 1024 * 1024:
                shutil.copy2(child, dest / child.name)
                kept.append(child.name)
            elif child.is_dir():
                shutil.copytree(child, dest / child.name, symlinks=True,
                                ignore=shutil.ignore_patterns("*.tar.gz", "*.whl", "*.so"),
                                dirs_exist_ok=True)
                kept.append(child.name + "/")
        except (OSError, shutil.Error):
            continue
    (dest / "WHAT-IS-THIS.txt").write_text(
        f"Preserved automatically because case {case_name!r} produced a finding.\n"
        f"--keep is a flag people remember only after the interesting run, so preserving a\n"
        f"finding's artifacts is unconditional.\n\n"
        f"Contents: {', '.join(kept) or '(nothing copyable)'}\n\n"
        f"Re-run just this case:\n"
        f"    python tools/busybody.py --case {case_name} --keep\n")
    return str(dest.relative_to(REPO))


# ---------------------------------------------------------------- history and triage

def print_history() -> int:
    runs = scan_runs(RUNS)
    if not runs:
        print("no runs yet")
        return 0
    print(f"{'run':22} {'state':12} {'cases':>5} {'findings':>8}  planned")
    print(f"{'-' * 22} {'-' * 12} {'-' * 5:>5} {'-' * 8:>8}  -------")
    for r in runs:
        planned = len(r["planned"] or []) if r["planned"] else "?"
        print(f"{r['run']:22} {r['state']:12} {r['cases']:>5} {r['findings']:>8}  {planned}")
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


def print_triage() -> int:
    groups = ledger_rollup()
    path = ledger_path()
    if not groups:
        print(f"no findings recorded in {path}")
        return 0
    print("=" * 78)
    print(f"busybody triage — {sum(g['count'] for g in groups)} finding(s), "
          f"{len(groups)} distinct")
    print(f"ledger: {path}")
    print("=" * 78)
    print()
    print("Grouped by fingerprint: paths, timestamps, hex and bare numbers are normalised")
    print("out, so repeats of one root cause appear as ONE group with a count and a")
    print("first-seen date. Fix the group, not the occurrences. Biggest group first.")
    print()
    for i, g in enumerate(groups, 1):
        print("-" * 78)
        print(f"[{i}] {g['count']} occurrence(s)   severity: {g['severity']}   "
              f"outcome: {g['outcome']}")
        print(f"    fingerprint : {g['fingerprint']}")
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
    print("-" * 78)
    return 0



# ================================================================================
# APP-LEVEL PERSONAS
#
# Everything above this line attacks the LAUNCHER, and the launcher is byte-identical in
# every binary haru-pack produces. That is why the 2026-09-10 top-25 sweep produced 575
# runs and only 23 distinct fingerprints: each case answered the same 25 times.
#
# These personas attack the PACKAGED APPLICATION instead — how the thing inside meets a
# hostile environment. That genuinely differs per package: numpy dlopens a BLAS, click
# inspects whether stdout is a terminal, pygments cares about the locale, torch wants
# address space, and iniconfig does none of it. Run these with `--fixtures top25` and the
# fingerprints should actually diverge.
#
# The expectation for most of them is "RAN or REFUSED, never CRASHED / HUNG / SILENT" —
# an application legitimately cannot start under a 64 MB address-space limit, and failing
# cleanly there is correct. What must never happen is a wedge, a raw traceback from the
# launcher, or a silent exit 0. The `blame` field records whether a non-zero exit came
# from the launcher or from the app, which is the distinction these personas turn on.
# ================================================================================

# ---------------------------------------------------------------- cartographer

@case("cartographer", ("RAN",),
      "Run the binary from a directory whose name contains spaces, unicode and a quote. "
      "haru-pack's headline claim is that a binary behaves like a compiled program in the "
      "folder it was launched from, and cwd is passed to the child — so a path the shell "
      "would need to quote is exactly where naive path handling breaks.",
      inv="INV-LAUNCH-07",
      remedy="A CRASHED or SILENT here means a path is being interpolated into a command "
             "string somewhere instead of passed as argv. Find it; nothing in the launcher "
             "should build a shell command from a path.")
def launched_from_an_awkward_directory(exe: Path, work: Path) -> dict:
    odd = work / "a dir with spaces 'and' quotes \u00e9\u00fc\u4f60\u597d"
    odd.mkdir(parents=True, exist_ok=True)
    return run_exe(exe, odd, env=clean_env(work / "c"))


@case("cartographer", ("RAN",),
      "Invoke through a symlink rather than the real path. Packaging tools that locate "
      "their own payload by argv[0] break here; haru-pack uses getAppFilename(), so this "
      "should be a non-event — and the case exists to keep it one.",
      inv="INV-LAUNCH-01",
      remedy="A refusal means self-location followed the symlink to somewhere without the "
             "payload. getAppFilename() must resolve the real executable.")
def invoked_through_a_symlink(exe: Path, work: Path) -> dict:
    link = work / "via-symlink"
    link.symlink_to(exe)
    return run_exe(link, work, env=clean_env(work / "c"))


@case("cartographer", ("RAN", "REFUSED", "APP-CRASHED"),
      "Run from a read-only working directory. An application that writes beside itself "
      "fails; one that does not, does not — which is precisely the kind of per-package "
      "difference the launcher-level cases cannot show.",
      remedy="Either outcome is acceptable, but the blame field must say `app` when it "
             "fails: the launcher has no business writing to cwd.")
def read_only_working_directory(exe: Path, work: Path) -> dict:
    ro = work / "readonly"
    ro.mkdir(parents=True, exist_ok=True)
    os.chmod(ro, 0o555)
    try:
        return run_exe(exe, ro, env=clean_env(work / "c"))
    finally:
        os.chmod(ro, 0o755)


@case("cartographer", ("RAN",),
      "argv passthrough: extra arguments, ones that look like flags, and shell "
      "metacharacters. README promises args reach the program 'like python' with no "
      "injected `--`, so this is a documented contract.",
      remedy="If the app never sees these, the launcher is swallowing or reordering argv. "
             "If the shell interprets them, something is building a command string.")
def hostile_argv_passthrough(exe: Path, work: Path) -> dict:
    return run_exe(exe, work, env=clean_env(work / "c"),
                   args=["--not-a-haru-flag", "-x", "a b c", "$(echo pwned)", "a;b|c", "--"])


# ---------------------------------------------------------------- polyglot

@case("polyglot", ("RAN", "APP-CRASHED"),
      "The C locale, no LANG, and legacy encoding forced on. Packages that decode text "
      "diverge sharply here — pygments, pyyaml and charset-normalizer all care, iniconfig "
      "does not.",
      remedy="A UnicodeDecodeError blamed on the app is a per-package fact worth "
             "recording. One blamed on the launcher means the launcher is decoding "
             "something it should be passing through as bytes.")
def c_locale_and_legacy_encoding(exe: Path, work: Path) -> dict:
    return run_exe(exe, work, env=clean_env(work / "c", LC_ALL="C", LANG="C",
                                            PYTHONUTF8="0", PYTHONIOENCODING="ascii"))


@case("polyglot", ("RAN",),
      "A stage path containing non-ASCII. The cache directory carries the payload digest, "
      "but its parent is the user's — and users have unicode in their home directory.",
      inv="INV-STAGE-01",
      remedy="A failure here means a path is being encoded with the wrong codec, most "
             "likely where the stage token is written or compared.")
def unicode_in_the_cache_path(exe: Path, work: Path) -> dict:
    cache = work / "caché-\u4f60\u597d"
    cache.mkdir(parents=True, exist_ok=True)
    return run_exe(exe, work, env=clean_env(cache))


# ---------------------------------------------------------------- mute

@case("mute", ("RAN",),
      "stdin closed outright. Anything that prompts, or that checks whether it can, has "
      "to cope — including the launcher's own licence prompt, which is guarded on isatty.",
      inv="INV-SECRET-01",
      remedy="A HUNG here is the serious one: something is waiting on input that will "
             "never arrive. The secret prompt must be reached only when stdin is a tty.")
def stdin_is_closed(exe: Path, work: Path) -> dict:
    t0 = time.monotonic()
    try:
        r = subprocess.run([str(exe)], stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=120, cwd=work, env=clean_env(work / "c"))
        rc, out, err, to = r.returncode, r.stdout, r.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, out, err, to = None, (e.stdout or b"").decode("utf8", "replace"), \
            (e.stderr or b"").decode("utf8", "replace"), True
    return {"outcome": classify(rc, out, err, to), "rc": rc,
            "seconds": round(time.monotonic() - t0, 1), "blame": blame(out, err),
            "stdout": (out or "").strip()[-400:], "stderr": (err or "").strip()[-400:]}


@case("mute", ("RAN", "REFUSED", "APP-CRASHED"),
      "stdout closed while the app is writing to it — the `| head -1` case. A program that "
      "ignores SIGPIPE and keeps writing dies on EPIPE; one that does not, exits 0. Varies "
      "by how much the packaged app prints.",
      remedy="A raw BrokenPipeError traceback is the finding: exiting quietly on a closed "
             "pipe is normal behaviour for a command-line program.")
def stdout_closed_early(exe: Path, work: Path) -> dict:
    t0 = time.monotonic()
    p1 = subprocess.Popen([str(exe)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          cwd=work, env=clean_env(work / "c"), text=True)
    try:
        p1.stdout.close()          # slam the read end shut
        err = p1.stderr.read()
        rc = p1.wait(timeout=120)
        to = False
    except subprocess.TimeoutExpired:
        p1.kill()
        rc, err, to = None, "", True
    # No marker is reachable — stdout is gone — so judge on rc and stderr alone.
    outcome = ("HUNG" if to else
               classify(rc, "", err, False) if any(m in err for m in TRACEBACK_MARKERS)
               else "RAN" if rc == 0 else "REFUSED")
    return {"outcome": outcome, "rc": rc, "seconds": round(time.monotonic() - t0, 1),
            "blame": blame("", err), "stdout": "(closed by the test)",
            "stderr": (err or "").strip()[-400:]}


# ---------------------------------------------------------------- impatient

@case("impatient", ("RAN", "REFUSED"),
      "Ctrl-C while the APPLICATION is running, not while staging. main.nim installs a "
      "custom SIGINT handler specifically so the child owns Ctrl-C and the launcher does "
      "not die first — a comment in the source says so, and nothing tested it until now. "
      "TIMING-SENSITIVE, and honestly so: the signal goes 0.7s in, so whether it lands "
      "mid-run depends on how long the app takes to start. Measured 2026-09-10 — numpy "
      "(slow import) REFUSED, iniconfig (finishes first) RAN. That divergence is a fact "
      "about import speed on this box, not a stable property of either package; do not "
      "read a change here as a regression without checking the machine.",
      inv="INV-LAUNCH-06",
      remedy="A HUNG means the signal reached neither process and the run is wedged. A "
             "launcher traceback means the parent took the signal instead of the child.",
      serial=True)
def interrupted_while_the_app_runs(exe: Path, work: Path) -> dict:
    cache, first = warm(exe, work)       # stage first, so the interrupt lands on the app
    if first["outcome"] != "RAN":
        return {**first, "stderr": "SKIPPED: first run did not succeed, nothing to interrupt"}
    t0 = time.monotonic()
    p1 = subprocess.Popen([str(exe)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          cwd=work, env=clean_env(cache), text=True)
    time.sleep(0.7)
    p1.send_signal(signal.SIGINT)
    try:
        out, err = p1.communicate(timeout=60)
        rc, to = p1.returncode, False
    except subprocess.TimeoutExpired:
        p1.kill()
        out, err, rc, to = "", "", None, True
    outcome = ("HUNG" if to else
               "CRASHED" if any(m in (out + err) for m in TRACEBACK_MARKERS) else
               "RAN" if (rc == 0 and MARKER in out) else "REFUSED")
    return {"outcome": outcome, "rc": rc, "seconds": round(time.monotonic() - t0, 1),
            "blame": blame(out, err), "stdout": (out or "").strip()[-400:],
            "stderr": (err or "").strip()[-400:]}


@case("impatient", ("REFUSED", "RAN"),
      "SIGTERM instead of SIGINT — what a process supervisor or `docker stop` sends. The "
      "launcher must not leave the child orphaned and running.",
      remedy="Check for a stray child process afterwards. An orphan holding the stage is "
             "how a later run finds a directory being written to.",
      serial=True)
def terminated_mid_run(exe: Path, work: Path) -> dict:
    cache, _ = warm(exe, work)
    t0 = time.monotonic()
    p1 = subprocess.Popen([str(exe)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          cwd=work, env=clean_env(cache), text=True)
    time.sleep(0.7)
    p1.terminate()
    try:
        out, err = p1.communicate(timeout=60)
        rc, to = p1.returncode, False
    except subprocess.TimeoutExpired:
        p1.kill()
        out, err, rc, to = "", "", None, True
    outcome = ("HUNG" if to else
               "CRASHED" if any(m in (out + err) for m in TRACEBACK_MARKERS) else
               "RAN" if (rc == 0 and MARKER in out) else "REFUSED")
    return {"outcome": outcome, "rc": rc, "seconds": round(time.monotonic() - t0, 1),
            "blame": blame(out, err), "stdout": (out or "").strip()[-400:],
            "stderr": (err or "").strip()[-400:]}


# ---------------------------------------------------------------- hoarder

@case("hoarder", ("RAN", "REFUSED", "APP-CRASHED"),
      "A 64-file descriptor limit. Staging opens a lot of files and a package with many "
      "shared objects opens more — torch and numpy will feel this, iniconfig will not. The "
      "single most package-dependent case in the suite.",
      remedy="Failing is acceptable; the blame field should say which side ran out. A "
             "launcher-blamed failure with no message is the bad shape — it means an fd "
             "error was swallowed.")
def few_file_descriptors(exe: Path, work: Path) -> dict:
    import resource
    return run_exe(exe, work, env=clean_env(work / "c"),
                   rlimits={resource.RLIMIT_NOFILE: (64, 64)})


#: Calibrated, not guessed. A resource ceiling only discriminates between packages if it
#: sits BETWEEN their requirements. Measured 2026-09-10 on this box, after a warm stage:
#:   iniconfig  ok at 512 MB
#:   numpy      FAILS at 512 and 768 MB, ok at 1024 MB
#: 768 MB therefore separates them. The first version used 256 MB, which was below BOTH —
#: every package failed identically and the case discriminated nothing. If this stops
#: diverging, re-run tools/busybody.py --calibrate rather than nudging the number.
ADDRESS_SPACE_MB = 768


@case("hoarder", ("RAN", "REFUSED", "APP-CRASHED"),
      f"A {ADDRESS_SPACE_MB} MB address-space ceiling, calibrated to sit BETWEEN a config "
      "parser and a numeric stack: iniconfig runs in 512 MB, numpy needs 1024 MB. This is "
      "the case that actually diverges by package — and the reason it does is that the "
      "threshold was measured rather than chosen. Failing cleanly is correct on the heavy "
      "side; the finding would be a crash or a wedge.",
      remedy="A clean non-zero exit blamed on the app is the expected result for a heavy "
             "package. CRASHED with a Nim traceback means an allocation failure inside the "
             "launcher is unhandled. If EVERY package now behaves the same, the threshold "
             "has drifted out of the band — recalibrate, do not just raise it.")
def tight_address_space(exe: Path, work: Path) -> dict:
    import resource
    # Warm the stage first with no limit: otherwise this measures whether STAGING fits in
    # the ceiling, which is the same answer for every package and not the question.
    cache, first = warm(exe, work)
    if first["outcome"] != "RAN":
        return {**first, "stderr": "SKIPPED: could not stage before applying the limit"}
    return run_exe(exe, work, env=clean_env(cache),
                   rlimits={resource.RLIMIT_AS: (ADDRESS_SPACE_MB * 1024 * 1024,) * 2})


@case("hoarder", ("RAN", "REFUSED", "APP-CRASHED"),
      "TMPDIR pointing at a read-only directory. Packages that write temporary files fail; "
      "ones that do not, do not. Staging itself must not depend on TMPDIR being writable, "
      "because the stage lives in the cache directory.",
      remedy="If the LAUNCHER fails here, staging is using TMPDIR when it should be using "
             "the cache directory it already chose.")
def read_only_tmpdir(exe: Path, work: Path) -> dict:
    ro = work / "ro-tmp"
    ro.mkdir(parents=True, exist_ok=True)
    os.chmod(ro, 0o555)
    try:
        return run_exe(exe, work, env=clean_env(work / "c", TMPDIR=str(ro)))
    finally:
        os.chmod(ro, 0o755)


# ================================================================ fixture + driver

APP = '''# /// script
# requires-python = ">=3.12"
# ///
import sys
print("BUSYBODY_OK", sys.version_info[:2])
'''


def build_fixture(tier: str, log=print) -> Path:
    """One real binary, built once, copied per case."""
    OUT.mkdir(parents=True, exist_ok=True)
    exe = OUT / f"fixture-{tier}"
    if exe.exists():
        log(f"reusing {exe.name}")
        return exe
    src = OUT / "app.py"
    src.write_text(APP)
    haru = shutil.which("haru-pack") or str(REPO / ".venv" / "bin" / "haru-pack")
    log(f"building fixture ({tier}) — once, then every case gets a copy")
    r = subprocess.run([haru, "build", str(src), "-o", str(exe), "--tier", tier],
                       capture_output=True, text=True, timeout=1800)
    if r.returncode != 0 or not exe.exists():
        raise SystemExit("fixture build failed:\n" + (r.stderr or r.stdout)[-1500:])
    return exe



def _flexrun():
    """Reuse the flex harness's project builder rather than a second copy of it."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("flexrun", REPO / "tools" / "flex-run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_top25_fixtures(tier: str, reaper, log=print) -> list:
    """One binary per top-25 package, so the chaos cases run against real payloads.

    The synthetic fixture is a two-line script: its payload is a handful of files. A real
    package brings native libraries, deep trees, and thousands of staged files — which is
    what the staging, verification and truncation cases are actually about.

    THICK on purpose. Every case runs with a pristine cache directory (otherwise the
    tampering cases prove nothing, since a warm stage is reused). At the default tier that
    would mean each of several hundred case-runs re-downloading an interpreter and the
    package's dependencies; thick puts them in the payload, so the runs need no network at
    all and are the same speed for every case.
    """
    from haru_pack import tomlio
    manifest = REPO / "flex" / "packages.toml"
    if not manifest.exists():
        raise SystemExit("flex/packages.toml missing — run tools/gen-package-manifest.py")
    pkgs = [p for p in tomlio.load(manifest).get("package", []) if p.get("list") == "top25"]
    if not pkgs:
        raise SystemExit("no top25 packages in flex/packages.toml")

    flex = _flexrun()
    haru = shutil.which("haru-pack") or str(REPO / ".venv" / "bin" / "haru-pack")
    fixdir = OUT / "fixtures"
    fixdir.mkdir(parents=True, exist_ok=True)

    built, failed = [], []
    log(f"building {len(pkgs)} top-25 fixture(s) at tier={tier} — once, then reused")
    for i, pkg in enumerate(pkgs, 1):
        name = pkg["name"]
        exe = fixdir / f"fixture-{name}"
        if exe.exists():
            log(f"  [{i}/{len(pkgs)}] {name}: reusing")
            built.append((name, exe))
            continue
        work = reaper.track(Path(tempfile.mkdtemp(prefix="bb-fixture-", dir=WORK_ROOT)))
        proj = flex.make_project({**pkg, "smoke": (pkg.get("smoke") or "").replace(
            "FLEX_OK", MARKER) or f"print('{MARKER}')"}, work)
        r = subprocess.run([haru, "build", str(proj), "-o", str(exe), "--tier", tier],
                           capture_output=True, text=True, timeout=3600)
        if r.returncode != 0 or not exe.exists():
            failed.append((name, (r.stderr or r.stdout).strip()[-200:]))
            log(f"  [{i}/{len(pkgs)}] {name}: BUILD FAILED")
            continue
        log(f"  [{i}/{len(pkgs)}] {name}: {exe.stat().st_size / 1e6:.0f}MB")
        built.append((name, exe))

    if failed:
        log(f"{len(failed)} fixture(s) could not be built; those packages are skipped, "
            f"not silently passed:")
        for name, err in failed:
            log(f"  {name}: {err[:120]}")
    if not built:
        raise SystemExit("no fixtures built")
    return built



# ---------------------------------------------------------------- calibration

def calibrate(fixtures: list, log=print) -> int:
    """Find the resource band that separates a light package from a heavy one.

    A ceiling only discriminates between packages if it sits BETWEEN their requirements.
    The first `tight_address_space` guessed 256 MB, which is below what a bare interpreter
    needs — every package failed identically and the case discriminated nothing while
    looking thorough. This measures instead of guessing, and prints a number to paste.

    Staging is warmed at no limit first, so what gets measured is the APPLICATION's
    requirement rather than the staging step's — which is the same for every package and
    not the question.
    """
    import resource
    from busybody_analyze import RESOURCE_LADDER

    if len(fixtures) < 2:
        log("calibration needs at least two fixtures to find a band between them.")
        log("Try:  python tools/busybody.py --calibrate --fixtures top25")
        return 2

    log("=" * 78)
    log("busybody calibration — RLIMIT_AS")
    log("=" * 78)
    log("")
    log("Each fixture is staged once with no limit, then run at each ceiling. The lowest")
    log("ceiling at which it still works is its requirement. A threshold placed between")
    log("the smallest and largest requirement is one that tells packages apart.")
    log("")
    log(f"  {'fixture':24} {'requires':>10}   ladder")
    log(f"  {'-' * 24} {'-' * 10:>10}   {'-' * 30}")

    needs = {}
    for name, exe in fixtures:
        work = Path(tempfile.mkdtemp(prefix="bb-calibrate-", dir=WORK_ROOT))
        try:
            cache, first = warm(exe, work)
            if first["outcome"] != "RAN":
                log(f"  {name:24} {'?':>10}   SKIPPED: would not run unrestricted")
                continue
            marks, need = [], None
            for mb in RESOURCE_LADDER:
                r = run_exe(exe, work, env=clean_env(cache), timeout=180,
                            rlimits={resource.RLIMIT_AS: (mb * 1024 * 1024,) * 2})
                ok = r["outcome"] == "RAN"
                marks.append(f"{mb}={'ok' if ok else 'x'}")
                if ok:
                    need = mb
                    break
            needs[name] = need
            log(f"  {name:24} {(str(need) + 'MB') if need else '>ladder':>10}   "
                f"{' '.join(marks)}")
        finally:
            shutil.rmtree(work, ignore_errors=True)

    log("")
    measured = {k: v for k, v in needs.items() if v}
    if len(measured) < 2:
        log("Not enough measurements to name a band.")
        return 1
    lo, hi = min(measured.values()), max(measured.values())
    if lo == hi:
        log(f"Every fixture needs {lo}MB. No band exists at this granularity, so RLIMIT_AS")
        log("cannot separate these packages — pick fixtures with more contrast (a config")
        log("parser against a numeric stack), or discriminate on something else.")
        return 1
    candidates = [m for m in RESOURCE_LADDER if lo <= m < hi]
    pick = candidates[len(candidates) // 2] if candidates else (lo + hi) // 2
    log(f"Band: {lo}MB (lightest) .. {hi}MB (heaviest).")
    log(f"Recommended threshold: {pick}MB")
    log("")
    log("Paste into tools/busybody.py, WITH this measurement beside it:")
    log(f"    ADDRESS_SPACE_MB = {pick}")
    log("")
    for k, v in sorted(measured.items(), key=lambda kv: kv[1]):
        log(f"    #:   {k:22} ok at {v}MB")
    log("")
    log("This number is machine-specific. It is not a constant of nature — re-run")
    log("calibration on a different box rather than assuming it transfers.")
    if pick == ADDRESS_SPACE_MB:
        log("")
        log(f"(Current ADDRESS_SPACE_MB is already {ADDRESS_SPACE_MB} — no change needed.)")
    return 0


# ---------------------------------------------------------------- wedge: hostile config

# A "wedge" is a configuration where two directives cannot both be honoured. Every other
# persona attacks a binary that was already built; this one attacks the DECLARATION, and it
# is a different class of bug — a wedge that builds cleanly ships an artifact whose
# behaviour nobody predicted from reading the config.
#
# Three acceptable answers, and one that is not:
#
#   REFUSED       the build stopped and the message named BOTH sides of the contradiction.
#                 Best outcome: the wedge cannot reach a customer.
#   WARNED        it built, and said what it had to override to do so. Acceptable when one
#                 side has documented precedence.
#   RAN           it built AND the predicted artifact damage did not occur, because the
#                 wedge was not actually a contradiction. The case is wrong, not the tool.
#   SILENT-WEDGE  it built, said nothing, and the artifact carries the damage. A FINDING.
#
# The last one is why this persona exists. Each case names the artifact property it expects
# to be damaged, so a finding is not "config was weird" but "config was weird AND here is
# the resulting binary's specific defect".

WEDGE_HINTS = ("warning", "conflict", "contradict", "ignored", "overrid", "precedence",
               "but ", "instead of", "cannot", "refus", "expired", "excluded")


def _wedge_project(work: Path, decl: str, app: str = "", extra: dict | None = None) -> Path:
    """A minimal project with a hostile haru_pack.toml. Returns the project directory."""
    proj = work / "proj"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "app.py").write_text(app or APP)
    (proj / "haru_pack.toml").write_text(decl)
    for name, body in (extra or {}).items():
        f = proj / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body)
    return proj


def _build(proj: Path, out: Path, *args, timeout: int = 900) -> tuple:
    haru = shutil.which("haru-pack") or str(REPO / ".venv" / "bin" / "haru-pack")
    r = subprocess.run([haru, "build", str(proj), "-o", str(out), *args],
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout or ""), (r.stderr or "")


def _wedge(work: Path, decl: str, *, sides: tuple, damage, build_args=(),
           app: str = "", extra: dict | None = None) -> dict:
    """Build a wedged project and classify what haru-pack did about it.

    `sides`  the two halves of the contradiction, as substrings that a good diagnostic would
             mention. A message that names only one half is not much better than silence:
             it tells you what happened without telling you what it collided with.
    `damage` callable(exe) -> str. Runs the artifact and returns a description of the
             predicted damage, or "" if the artifact is actually fine. Only consulted when
             the build succeeded quietly.
    """
    proj = _wedge_project(work, decl, app=app, extra=extra)
    out = work / "wedged"
    rc, so, se = _build(proj, out, *build_args)
    blob = (so + se)
    low = blob.lower()

    if rc != 0 or not out.exists():
        named = [x for x in sides if x.lower() in low]
        if not named:
            # It refused, but for something other than the wedge — so this case did not
            # actually exercise its contradiction, and calling it a pass would be the same
            # mistake `payload_edited_and_footer_recomputed` made when it took a CRC32
            # rejection as proof of tamper detection. The case is what needs fixing here,
            # not necessarily the product.
            return {"outcome": "REFUSED-UNRELATED", "rc": rc, "seconds": 0,
                    "blame": "builder", "stdout": "", "stderr": (
                        f"build refused without mentioning either side of {sides}, so the "
                        f"wedge itself was never reached: {blob.strip()[-300:]}")}
        return {"outcome": "REFUSED", "rc": rc, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": (
                    f"build refused, naming {len(named)}/{len(sides)} side(s) of the "
                    f"conflict {sides}: {blob.strip()[-300:]}")}

    said = any(h in low for h in WEDGE_HINTS) and any(x.lower() in low for x in sides)
    if said:
        return {"outcome": "WARNED", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": blob.strip()[-300:], "stderr": ""}

    harm = damage(out) if damage else ""
    if harm:
        return {"outcome": "SILENT-WEDGE", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": (
                    f"built with no mention of the conflict {sides}, and the artifact is "
                    f"damaged: {harm}")}
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} built quietly and the artifact was undamaged", "stderr": ""}


def _run_artifact(exe: Path, work: Path, args=()) -> tuple:
    """Run a wedged artifact once. Returns (outcome, message)."""
    r = run_exe(exe, work, env=clean_env(work / "wc"), timeout=180, args=args)
    return r["outcome"], (r.get("stderr") or r.get("stdout") or "").strip()[:200]


@case("wedge", ("REFUSED", "WARNED"),
      "The declared entrypoint is a file the payload builder deliberately excludes. "
      "`_SECRET_PATTERNS` drops `secrets.*` so a credentials file cannot be packed by "
      "accident — but the same rule silently removes a file someone named as the "
      "entrypoint. Two correct rules, one artifact, and they disagree.",
      inv="INV-CHAOS-07",
      remedy="Name both sides: the entrypoint that was requested and the ignore rule that "
             "removed it. Refusing is better than shipping a binary with no entrypoint.",
      per_fixture=False)
def entrypoint_is_excluded_by_secret_hygiene(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        return "" if outcome == "RAN" else f"artifact does not run: {outcome} {msg}"
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\nentrypoint = ["secrets.py"]\n',
        sides=("secrets.py", "entrypoint"),
        damage=damage,
        extra={"secrets.py": APP},
    )


@case("wedge", ("REFUSED", "WARNED"),
      "haru_pack.toml pins an interpreter older than the project says it needs. The "
      "declaration beats discovery by design, so the pin wins and the binary ships a "
      "Python the application cannot run on. Nothing about the build looks wrong.",
      inv="INV-CHAOS-07",
      remedy="Compare the declared python against requires-python and say which one lost. "
             "Precedence is fine; silent precedence on an incompatible version is not.",
      per_fixture=False)
def declared_python_is_older_than_the_app_requires(exe: Path, work: Path) -> dict:
    app = ('# a 3.12-only construct: PEP 695 type parameter syntax\n'
           'type Alias = int\n'
           'def f[T](x: T) -> T: return x\n'
           f'print("{MARKER}", f(1))\n')

    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        return "" if outcome == "RAN" else f"artifact does not run: {outcome} {msg}"
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\npython = "3.9"\n',
        sides=("3.9", "python"),
        damage=damage,
        app=app,
        extra={"pyproject.toml": '[project]\nname = "wedged"\n'
                                 'requires-python = ">=3.12"\nversion = "0"\n'},
    )


@case("wedge", ("REFUSED", "WARNED"),
      "`app_subdir` climbs out of the payload with `..`. Every path the launcher resolves "
      "is relative to the payload root, so a subdir that escapes it either writes files "
      "the launcher will never look for, or writes them somewhere it should not.",
      inv="INV-CHAOS-07",
      remedy="Reject an app_subdir that is absolute or contains `..`. This is the same "
             "class as a zip-slip and deserves the same flat refusal.",
      per_fixture=False)
def app_subdir_escapes_the_payload(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        return "" if outcome == "RAN" else f"artifact does not run: {outcome} {msg}"
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\napp_subdir = "../escaped"\n',
        sides=("app_subdir", ".."),
        damage=damage,
    )


@case("wedge", ("REFUSED", "WARNED"),
      "The licence expires before the binary is built. Encryption accepts the policy and "
      "seals it in, producing an artifact that is dead on arrival — it will refuse every "
      "run, forever, and the refusal will look like a licensing bug to whoever receives it.",
      inv="INV-CHAOS-07",
      remedy="An expiry in the past is a typo, not a policy. Refuse at build time, where "
             "the person who can fix it is still watching.",
      per_fixture=False)
def licence_expires_before_it_is_built(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        # REFUSED here is the artifact being dead on arrival, which IS the damage
        return "" if outcome == "RAN" else f"artifact is dead on arrival: {outcome} {msg}"
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\n\n[encryption]\nenabled = true\n'
        'expires = "2001-01-01"\nembed_secret = true\n',
        sides=("2001", "expire"),
        damage=damage,
        # A secret is required before the expiry is even looked at — refusing without one
        # is a correct guard, and without this the case never reached its own wedge.
        build_args=("--secret", "wedge-test-key"),
    )


@case("wedge", ("REFUSED", "WARNED", "RAN"),
      "`--tier thin` says bundle nothing; the declaration asks to bundle python and uv. "
      "One of them is not happening. Which one, and does the binary's actual size agree "
      "with the tier it claims?",
      inv="INV-CHAOS-07",
      remedy="Tier is the coarse control and should win, but say so. A 60 MB binary from a "
             "`thin` build, or a 6 MB one that claims to bundle Python, is a lie about "
             "what the artifact needs at runtime.",
      per_fixture=False)
def thin_tier_asked_to_bundle_everything(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        # thin must not carry an interpreter. Size is the cheap, robust check.
        mb = out.stat().st_size / 1e6
        if mb > 20:
            return (f"thin-tier artifact is {mb:.0f}MB, so it bundled what thin says it "
                    f"does not; the tier no longer predicts the runtime requirement")
        return ""
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\nbundle = ["python", "uv"]\n',
        sides=("thin", "bundle"),
        damage=damage,
        build_args=("--tier", "thin"),
    )


@case("wedge", ("REFUSED", "WARNED", "RAN"),
      "`cwd_policy` is set to a value that does not exist. The launcher reads it with a "
      "string default, so an unknown value is not an error anywhere — it silently takes "
      "whichever branch the comparison falls through to, and the binary resolves relative "
      "paths differently than the config says it will.",
      inv="INV-CHAOS-07",
      remedy="Validate the enum at build time against the values the launcher actually "
             "implements. A typo'd policy should not be indistinguishable from a chosen one.",
      per_fixture=False)
def cwd_policy_is_not_a_policy(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        if outcome != "RAN":
            return f"artifact does not run: {outcome} {msg}"
        # It ran. The damage is that an invalid enum was accepted in silence — a typo is
        # now indistinguishable from a decision. Report it as a note-level wedge.
        return ("an unknown cwd_policy was accepted without comment, so a typo and a "
                "deliberate choice produce identical builds")
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\ncwd_policy = "sideways"\n',
        sides=("cwd_policy", "sideways"),
        damage=damage,
    )


@case("wedge", ("REFUSED", "WARNED"),
      "A machine-locked binary with no key anywhere. The policy demands a specific host, "
      "`embed_secret` is off, and no secret is supplied — so the artifact can never be "
      "decrypted by anyone, including the person who built it.",
      inv="INV-CHAOS-07",
      remedy="A policy with no reachable key is unusable by construction. Refuse, and name "
             "the missing key rather than the policy.",
      per_fixture=False)
def locked_to_a_machine_with_no_key(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        return "" if outcome == "RAN" else f"artifact cannot be decrypted: {outcome} {msg}"
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\n\n[encryption]\nenabled = true\n'
        'machine = "some-other-host"\nembed_secret = false\n',
        sides=("machine", "secret"),
        damage=damage,
    )


@case("wedge", ("REFUSED", "WARNED", "RAN"),
      "Three names for one artifact: pyproject says one thing, haru_pack.toml another, "
      "`-o` a third. Precedence exists and is documented, but a build that never mentions "
      "the two it discarded leaves the operator to guess which name the manifest carries "
      "— and the manifest name is what the launcher reports about itself.",
      inv="INV-CHAOS-07",
      remedy="`-o` names the FILE; `name` names the artifact in the manifest. If those "
             "differ, say so once — they are different fields and conflating them is how "
             "a binary reports a name nobody recognises.",
      per_fixture=False)
def three_names_for_one_artifact(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        return "" if outcome == "RAN" else f"artifact does not run: {outcome} {msg}"
    return _wedge(
        work,
        # The entrypoint is declared so that ENTRYPOINT ambiguity is not what gets
        # refused. The wedge under test is the name, and a case has to isolate its wedge
        # or it measures whichever guard happens to fire first.
        'name = "from-haru-toml"\nkind = "script"\nentrypoint = ["app.py"]\n',
        sides=("from-haru-toml", "wedged"),
        damage=damage,
        extra={"pyproject.toml": '[project]\nname = "from-pyproject"\nversion = "0"\n'},
    )


# ---------------------------------------------------------------- examiner: sit the exam

# A hello-world fixture proves a module imported. That is a low bar: `import numpy` succeeds
# long before `numpy` is usable, because the failure modes of a bundled native package are in
# the parts an import does not touch — a missing .so a submodule loads lazily, a data file,
# an f2py-generated extension, a locale-dependent codec path.
#
# The examiner makes the payload sit the package's OWN test suite, inside the thick binary,
# with nothing to download. That is the strongest available statement that a thick artifact
# carried a working library rather than an importable one.
#
# Checked 2026-09-10, all 25 top-PyPI packages: only TWO ship a runnable test suite in the
# wheel — numpy (13 test packages) and certifi. The other 23 would need sdists, which is a
# second acquisition path for no extra assurance, so this persona covers the two that can.
# Both are declared as data below rather than hardcoded in logic.
EXAMS = {
    "numpy": {
        # Bounded on purpose: the full suite is ~40k tests. These two modules exercise the
        # native core and the f2py/linalg surfaces where a truncated payload actually shows
        # up, and they run in a bearable time.
        "deps": ["numpy", "pytest", "hypothesis"],
        "modules": ["_core/tests/test_numeric.py", "linalg/tests/test_linalg.py"],
        "why_this_package": ("native BLAS, lazily-imported submodules, compiled extensions "
                             "and packaged data files — everything a payload can truncate "
                             "without breaking `import numpy`"),
    },
    "certifi": {
        "deps": ["certifi", "pytest"],
        "modules": ["tests"],
        "why_this_package": ("tiny, but it ships a real suite and its whole job is a data "
                             "file, which is exactly the kind of thing a payload drops"),
    },
}


def _exam_script(pkg: str, spec: dict) -> str:
    """A PEP 723 script that runs the installed package's own tests from inside the binary."""
    deps = ", ".join(f'"{d}"' for d in spec["deps"])
    mods = ", ".join(f'"{m}"' for m in spec["modules"])
    # Pinned to 3.12 deliberately. `>=3.11` resolves to whatever python-build-standalone
    # published most recently for that series, and the supply-chain guard refuses an
    # interpreter with no publisher digest in pins.toml — correctly. A test fixture is not a
    # reason to widen the pin set, so it asks for a version that is already pinned.
    return f"""# /// script
# requires-python = "==3.12.*"
# dependencies = [{deps}]
# ///
# Run the packaged library's own test suite from inside the packed binary. The package
# under test is located through its __file__ rather than by guessing a path, so this works
# wherever the launcher staged the payload.
import pathlib
import sys

import pytest

import {pkg}

root = pathlib.Path({pkg}.__file__).parent
targets = [str(root / m) for m in [{mods}]]
missing = [t for t in targets if not pathlib.Path(t).exists()]
if missing:
    print("PAYLOAD INCOMPLETE: test files absent from the staged package:", missing)
    sys.exit(2)

rc = pytest.main(["-q", "--no-header", "-x", "-p", "no:cacheprovider", *targets])
if rc == 0:
    print("{MARKER}", "{pkg} passed its own tests inside the binary")
sys.exit(rc)
"""


def _sit_exam(pkg: str, work: Path) -> dict:
    spec = EXAMS[pkg]
    proj = work / "exam"
    proj.mkdir(parents=True, exist_ok=True)
    src = proj / f"exam_{pkg}.py"
    src.write_text(_exam_script(pkg, spec))

    out = work / f"exam-{pkg}"
    rc, so, se = _build(proj / f"exam_{pkg}.py", out, "--tier", "thick", timeout=2400)
    if rc != 0 or not out.exists():
        return {"outcome": "REFUSED", "rc": rc, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"thick build failed: {(so + se).strip()[-400:]}"}

    # Nothing to download: thick sets UV_OFFLINE=1 inside the launcher, and the proxy vars
    # are pointed at a closed port so any library-level HTTP attempt fails loudly rather
    # than quietly succeeding and hiding a payload gap.
    env = clean_env(work / "ec", http_proxy="http://127.0.0.1:1",
                    https_proxy="http://127.0.0.1:1", no_proxy="")
    r = run_exe(out, work, env=env, timeout=2400)
    r["exam_mb"] = round(out.stat().st_size / 1e6, 1)
    return r


@case("examiner", "RAN",
      "numpy runs its own test suite from inside a thick binary, offline. `import numpy` "
      "succeeds long before numpy is usable: the failure modes of a bundled native package "
      "live in the parts an import never touches — a lazily-loaded .so, an f2py extension, "
      "a packaged data file. This is the strongest available statement that a thick payload "
      "carried a working library and not merely an importable one.",
      inv="INV-TIER-01",
      remedy="A failure here is a payload completeness bug, not a numpy bug. Compare the "
             "staged tree against the wheel: something the suite reaches was not packed. "
             "`PAYLOAD INCOMPLETE` in the output means the test files themselves are absent.",
      per_fixture=False, serial=True)
def numpy_passes_its_own_tests_inside_the_binary(exe: Path, work: Path) -> dict:
    return _sit_exam("numpy", work)


@case("examiner", "RAN",
      "certifi runs its own test suite from inside a thick binary, offline. Tiny, but its "
      "entire job is to ship a data file — exactly the kind of thing a payload builder "
      "drops while leaving the module importable.",
      inv="INV-TIER-01",
      remedy="A failure here means the CA bundle or the test data did not make it into the "
             "payload. Check the payload's ignore patterns against what the wheel ships.",
      per_fixture=False, serial=True)
def certifi_passes_its_own_tests_inside_the_binary(exe: Path, work: Path) -> dict:
    return _sit_exam("certifi", work)



# ------------------------------------------------- reverse_engineer: rummage the extraction
# The dev who must embed an API key and ship it. Encryption protects the payload AT REST in
# the binary; but the launcher stages plaintext to disk so the interpreter can run it, and
# any user who can RUN the binary owns that plaintext. This persona plants a known secret and
# proves each edge of that boundary rather than asserting it (INV-SECRET-02).

RE_SECRET = "sk_live_REVENG_" + "a1b2c3d4e5f60718"


def _reveng_app(secret: str) -> str:
    return (f'API_KEY = "{secret}"\n'
            'def main():\n'
            f'    print("{MARKER} ran; key length", len(API_KEY))\n'
            'if __name__ == "__main__":\n    main()\n')


def _reveng_build(work: Path, name: str, *extra) -> tuple:
    proj = work / f"re-{name}"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "app.py").write_text(_reveng_app(RE_SECRET))
    out = work / f"re-bin-{name}"
    # thick so the staged interpreter matches an obfuscation target exactly, and so the run
    # needs no network (INV-OBF-01, INV-TIER-01).
    rc, so, se = _build(proj / "app.py", out, "--tier", "thick", *extra, timeout=2400)
    return (rc == 0 and out.exists()), out, (so + se).strip()[-400:]


def _reveng_run_and_stage(exe: Path, work: Path, tag: str) -> Path | None:
    """Run the binary so it stages, then return the staged tree root under an isolated
    cache. The stage is the whole point — that is where the plaintext lands."""
    cache = work / f"cache-{tag}"
    r = run_exe(exe, work, env=clean_env(cache), timeout=600)
    if r["outcome"] not in ("RAN", "APP-CRASHED"):
        return None
    return stage_root(cache)


def _grep_tree(root: Path, needle: bytes) -> list:
    hits = []
    for f in root.rglob("*"):
        if f.is_file():
            try:
                if needle in f.read_bytes():
                    hits.append(str(f.relative_to(root)))
            except OSError:
                pass
    return hits


@case("reverse_engineer", "RAN",
      "An ENCRYPTED build must not carry the secret in plaintext in the binary at rest. This "
      "is what encryption buys: someone who has the exe but does not run it cannot read the "
      "key out of it. The persona greps the whole binary for the planted literal.",
      inv="INV-SECRET-02",
      remedy="A LEAKED here means the payload was appended in plaintext despite --encrypt — "
             "check that the secret was threaded into build() and the payload is ciphertext "
             "(INV-BUILD-02). This is the one surface encryption is supposed to close.",
      per_fixture=False, serial=True)
def encrypted_binary_hides_the_secret_at_rest(exe: Path, work: Path) -> dict:
    ok, out, note = _reveng_build(work, "enc", "--encrypt", "--secret", "reveng-build-key")
    if not ok:
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"encrypted build failed: {note}"}
    present = RE_SECRET.encode() in out.read_bytes()
    if present:
        return {"outcome": "LEAKED", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": (
                    "the planted secret is in the ENCRYPTED binary's bytes at rest; "
                    "encryption did not close its one surface")}
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} secret absent from the encrypted binary at rest "
                      f"({out.stat().st_size / 1e6:.0f}MB scanned)", "stderr": ""}


@case("reverse_engineer", "EXPOSED",
      "A PLAIN build leaks its source to the stage. The launcher writes the decrypted (here, "
      "never-encrypted) payload to the running user's cache in plaintext and leaves it there "
      "— it is the regenerable cache, not a temp dir. This case keeps that reality VISIBLE: "
      "if it ever stops being exposed, the staging model changed and the docs must too.",
      inv="INV-SECRET-02",
      remedy="EXPOSED is the expected, documented outcome — not a bug to fix but a fact to "
             "keep true and keep documented. A secret that must never be recovered must "
             "never be shipped in an artifact the client holds.",
      per_fixture=False, serial=True)
def plaintext_source_is_recoverable_from_the_stage(exe: Path, work: Path) -> dict:
    ok, out, note = _reveng_build(work, "plain")
    if not ok:
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"plain build failed: {note}"}
    root = _reveng_run_and_stage(out, work, "plain")
    if root is None:
        return {"outcome": "REFUSED", "rc": None, "seconds": 0, "blame": "launcher",
                "stdout": "", "stderr": "binary did not stage; nothing to rummage"}
    hits = _grep_tree(root, RE_SECRET.encode())
    if hits:
        return {"outcome": "EXPOSED", "rc": 0, "seconds": 0, "blame": "unknown",
                "stdout": "", "stderr": (
                    f"planted secret recovered from the staged plaintext at {root.name}/: "
                    f"{hits[:4]} — the documented soft spot")}
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} secret NOT in the stage — unexpected; staging model may "
                      f"have changed, re-read INV-SECRET-02", "stderr": ""}


@case("reverse_engineer", "RAN",
      "Obfuscation must strip the plaintext literal from the staged source. Build the same "
      "app plain and with --obfuscate pyarmor, run both, rummage both stages: the literal is "
      "in the plain stage and GONE from the obfuscated one. This is the measured value of "
      "--obfuscate — cost raised, not a boundary — and the case proves it both ways so a "
      "no-op obfuscator cannot pass.",
      inv="INV-OBF-01",
      remedy="A LEAKED means obfuscation did not remove the literal (obfuscator no-op'd, or "
             "the swap failed). If the plain side is ALSO clean the case is vacuous — the "
             "control must show the literal, or the test proves nothing.",
      per_fixture=False, serial=True)
def obfuscation_strips_the_plaintext_literal_from_the_stage(exe: Path, work: Path) -> dict:
    okp, plain, notep = _reveng_build(work, "ctl")
    if not okp:
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"control (plain) build failed: {notep}"}
    oko, obf, noteo = _reveng_build(work, "obf", "--obfuscate", "pyarmor")
    if not oko:
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"obfuscated build failed (pyarmor/uv?): {noteo}"}

    plain_root = _reveng_run_and_stage(plain, work, "ctl")
    obf_root = _reveng_run_and_stage(obf, work, "obf")
    if plain_root is None or obf_root is None:
        return {"outcome": "REFUSED", "rc": None, "seconds": 0, "blame": "launcher",
                "stdout": "", "stderr": "a binary did not stage; cannot compare"}

    plain_hits = _grep_tree(plain_root, RE_SECRET.encode())
    obf_hits = _grep_tree(obf_root, RE_SECRET.encode())
    if not plain_hits:
        return {"outcome": "REFUSED-UNRELATED", "rc": 0, "seconds": 0, "blame": "harness",
                "stdout": "", "stderr": (
                    "the CONTROL (plain) stage did not contain the literal, so this case "
                    "cannot prove obfuscation did anything — the control is broken")}
    if obf_hits:
        return {"outcome": "LEAKED", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": (
                    f"the plaintext literal survived obfuscation, present in the obfuscated "
                    f"stage: {obf_hits[:4]}")}
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} literal present in plain stage ({plain_hits[:2]}) and GONE "
                      f"from the obfuscated stage — --obfuscate did its job", "stderr": ""}


@case("reverse_engineer", "RAN",
      "The staged plaintext must not be readable by OTHER users on the box. It is owner-only "
      "by design (hardenDir strips group/other), which is a real protection on a shared "
      "host even though it does nothing against the user who runs the binary. The persona "
      "checks the mode bits of the staged tree.",
      inv="INV-SECRET-02",
      remedy="A LEAKED here means a staged file is group- or world-readable; check hardenDir "
             "and the umask handling in stage.nim. On a shared host this exposes the secret "
             "to every other account.",
      per_fixture=False, serial=True)
def the_staged_tree_is_not_readable_by_other_users(exe: Path, work: Path) -> dict:
    ok, out, note = _reveng_build(work, "perm")
    if not ok:
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"build failed: {note}"}
    root = _reveng_run_and_stage(out, work, "perm")
    if root is None:
        return {"outcome": "REFUSED", "rc": None, "seconds": 0, "blame": "launcher",
                "stdout": "", "stderr": "binary did not stage"}
    import stat as _stat
    # REACHABILITY, not raw bits. A 0644 file inside a 0700 directory is NOT exposed: another
    # user is blocked at the sealed directory and never reaches the file. The first version
    # flagged inner bits directly and reported a false LEAKED — the staged root and the cache
    # base are both 0700, which gates the whole tree (verified 2026-09-10). A file leaks only
    # if it is other-readable AND every ancestor directory up to the cache base is
    # other-traversable.
    base = root.parent            # <cache>/haru-pack, the per-user gate
    stop = base.parent            # the cache dir itself; do not walk above it

    def other_reachable(f: Path) -> bool:
        try:
            if not (f.stat().st_mode & _stat.S_IROTH):
                return False       # not other-readable: not a leak whatever the ancestors
        except OSError:
            return False
        d = f.parent
        while True:
            try:
                if not (d.stat().st_mode & _stat.S_IXOTH):
                    return False   # a sealed ancestor blocks the path
            except OSError:
                return False
            if d == base or d == stop or d.parent == d:
                return True        # reached the gate and every step was traversable
            d = d.parent

    leaked = [str(f.relative_to(root)) for f in root.rglob("*")
              if f.is_file() and other_reachable(f)]
    if leaked:
        return {"outcome": "LEAKED", "rc": 0, "seconds": 0, "blame": "launcher",
                "stdout": "", "stderr": (
                    f"{len(leaked)} staged file(s) are genuinely reachable by other users "
                    f"(other-readable, with an other-traversable path from the cache base): "
                    f"{leaked[:4]}")}
    # Confirm the gate is actually a gate, not an accident of this run.
    base_mode = base.stat().st_mode & 0o777
    gated = not (base.stat().st_mode & (_stat.S_IXOTH | _stat.S_IROTH))
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} staged tree sealed: cache base {base.name} is "
                      f"{oct(base_mode)} ({'owner-only gate' if gated else 'NOT gated'}); "
                      f"{sum(1 for _ in root.rglob('*'))} inner paths unreachable by others",
            "stderr": ""}
# ------------------------------------------------------- quotamaster: real mounts, in docker

# Some target hostility cannot be faked in-process. A noexec mount is the clearest example:
# staging writes an interpreter and then execs it, so a cache on a noexec filesystem fails at
# exec with EACCES. That is a real and common deployment configuration — /tmp is noexec on
# any hardened host, and CIS benchmarks recommend it — and mount(2) needs privileges this
# harness should never ask for.
#
# So these run the artifact inside a container where the mount options are chosen by docker
# rather than by us. The image is a plain glibc base: thick binaries carry their own
# interpreter, so nothing else is needed, and using a stock image keeps the case honest about
# what the binary actually requires of a host.

DOCKER_IMAGE = "debian:12-slim"


def _docker_available() -> str:
    """"" if docker can run, else the reason it cannot."""
    if not shutil.which("docker"):
        return "docker is not installed"
    r = subprocess.run(["docker", "image", "inspect", DOCKER_IMAGE],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        pull = subprocess.run(["docker", "pull", "-q", DOCKER_IMAGE],
                              capture_output=True, text=True, timeout=600)
        if pull.returncode != 0:
            return f"{DOCKER_IMAGE} unavailable: {(pull.stderr or '').strip()[:120]}"
    return ""


def _docker_run(exe: Path, work: Path, *, cache_opts: str, extra=(),
                timeout: int = 600) -> dict:
    """Run `exe` in a container whose cache mount carries `cache_opts`."""
    stage = work / "docker"
    stage.mkdir(parents=True, exist_ok=True)
    inner = stage / exe.name
    shutil.copy2(exe, inner)
    inner.chmod(0o755)

    argv = ["docker", "run", "--rm", "--network", "none",
            "-v", f"{stage}:/w",
            "--tmpfs", f"/cache:{cache_opts}" if cache_opts else "/cache",
            "-e", "XDG_CACHE_HOME=/cache",
            "-e", "HOME=/cache",
            "-w", "/w", *extra, DOCKER_IMAGE, f"/w/{exe.name}"]
    t0 = time.monotonic()
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        rc, out, err, to = r.returncode, r.stdout, r.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, out, err, to = None, (e.stdout or b"").decode("utf8", "replace"), \
            (e.stderr or b"").decode("utf8", "replace"), True
    secs = round(time.monotonic() - t0, 1)

    # Docker's own failures are the harness's problem, not haru-pack's.
    if rc is not None and rc in (125, 126, 127) and "haru-pack" not in (out + err):
        return {"outcome": "CASE-ERROR", "rc": rc, "seconds": secs, "blame": "harness",
                "stdout": "", "stderr": f"docker could not start the run: "
                                        f"{(err or out).strip()[-300:]}"}
    outcome = classify(rc, out, err, to)
    return {"outcome": outcome, "rc": rc, "seconds": secs,
            "blame": blame(out, err) if outcome != "RAN" else "none",
            "stdout": (out or "").strip()[-400:], "stderr": (err or "").strip()[-400:],
            "docker": " ".join(argv[:12])}


def _thick_for_docker(work: Path) -> tuple:
    """A thick binary to take into a container. Built once per case; thick is the only tier
    that can run with --network none."""
    proj = work / "dproj"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "app.py").write_text(COMPOSED_APP)
    out = work / "dockerable"
    rc, so, se = _build(proj / "app.py", out, "--tier", "thick", timeout=2400)
    return (rc == 0 and out.exists()), out, (so + se).strip()[-300:]


def _quotamaster(work: Path, *, cache_opts: str, extra=(), needs_msg: str) -> dict:
    if why := _docker_available():
        return {"outcome": "REFUSED", "rc": None, "seconds": 0, "blame": "harness",
                "stdout": "", "stderr": f"SKIPPED: {why}"}
    ok, exe, note = _thick_for_docker(work)
    if not ok:
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"thick build failed: {note}"}
    r = _docker_run(exe, work, cache_opts=cache_opts, extra=extra)
    r["needs"] = needs_msg
    return r


@case("quotamaster", ("REFUSED", "RAN"),
      "The cache is on a noexec mount, as /tmp is on any hardened host. Staging writes an "
      "interpreter and then execs it, so this fails at exec with EACCES. A refusal is the "
      "right outcome — but the message has to name the mount, because 'permission denied' "
      "sends the operator to check file ownership and they will find nothing wrong with it.",
      inv="INV-STAGE-01",
      remedy="If this CRASHES or is SILENT, the exec failure is not being handled. If it "
             "REFUSES without saying 'noexec' or naming the directory, the diagnostic is "
             "the finding: suggest HARU_CACHE_DIR or an equivalent on an exec-capable path.",
      per_fixture=False, serial=True)
def cache_on_a_noexec_mount(exe: Path, work: Path) -> dict:
    return _quotamaster(work, cache_opts="noexec,size=2g",
                        needs_msg="docker, for a real noexec mount")


@case("quotamaster", ("REFUSED", "RAN"),
      "The cache filesystem is 24 MB — far smaller than a staged interpreter. Writes fail "
      "partway, which produces a PARTIAL stage rather than no stage: the case that most "
      "needs an integrity check, because the next run may find a plausible-looking "
      "directory and use it.",
      inv="INV-STAGE-01",
      remedy="A truncated stage must never be treated as complete. If a later run reuses "
             "it, the ready-marker is being written before the stage is verified.",
      per_fixture=False, serial=True)
def cache_filesystem_is_far_too_small(exe: Path, work: Path) -> dict:
    return _quotamaster(work, cache_opts="size=24m",
                        needs_msg="docker, for a real size-limited filesystem")


@case("quotamaster", ("REFUSED", "RAN"),
      "A read-only root filesystem with only the cache writable — a hardened container, and "
      "an increasingly normal way to ship software. Anything the launcher writes outside "
      "its cache fails here, and that is worth knowing before a customer finds it.",
      inv="INV-STAGE-01",
      remedy="Every write must go through the cache directory. A failure here names the "
             "path that was written outside it.",
      per_fixture=False, serial=True)
def read_only_root_filesystem(exe: Path, work: Path) -> dict:
    return _quotamaster(work, cache_opts="size=2g", extra=("--read-only",),
                        needs_msg="docker, for a real read-only rootfs")


@case("quotamaster", ("REFUSED", "RAN", "APP-CRASHED"),
      "512 MB of container memory, enforced by a cgroup rather than by RLIMIT_AS. A cgroup "
      "limit kills on the OOM path instead of failing an allocation, so the process gets "
      "SIGKILL with no traceback and no message — which is a different failure from the "
      "rlimit case and must not be reported as a silent success.",
      inv="INV-STAGE-01",
      remedy="An OOM kill has rc 137 and no output. If that is classified as SILENT rather "
             "than as a kill, the classifier needs to learn 137.",
      per_fixture=False, serial=True)
def cgroup_memory_limit(exe: Path, work: Path) -> dict:
    return _quotamaster(work, cache_opts="size=2g", extra=("-m", "512m"),
                        needs_msg="docker, for a real cgroup memory limit")


# ======================================================= composition: stacking the personas

# A persona that runs alone is an integration test in a costume. The question chaos
# engineering asks is which COMBINATION of individually-survivable conditions is not
# survivable — and no amount of running them one at a time will answer it.
#
# The pass condition for a composed run is deliberately weak, because nobody has reasoned
# about combination 7,431 of 10,000:
#
#     RAN / REFUSED / APP-CRASHED     acceptable
#     CRASHED / HUNG / SILENT         never acceptable
#
# That is the existing FATAL set. Composition needs no new vocabulary, only a weaker
# expectation. "haru-pack refuses intelligibly under any stack of hostile conditions" is a
# property worth having. "haru-pack always works" is not, and asserting it would be exactly
# the sort of overclaim INVARIANTS.md exists to catch.

COMPOSED_APP = f"""# /// script
# requires-python = "==3.12.*"
# ///
print("{MARKER}", "composed fixture ran")
"""


def _payload_members(exe: Path) -> list:
    """(name, first 4 bytes) for every payload member, without staging anything.

    Static inspection is what makes the cross-target checks possible at all: a Windows
    payload cannot be executed here, but it can be read.
    """
    from haru_pack import overlay
    info = overlay.verify(exe)
    data = exe.read_bytes()
    blob = data[info["payload_off"]:info["payload_off"] + info["payload_len"]]
    out = []
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for n in z.namelist():
            if n.endswith("/"):
                continue
            with z.open(n) as fh:
                out.append((n, fh.read(20)))
    return out


ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
# e_machine values from the ELF header, little-endian, at offset 18.
EM = {0x3E: "x86-64", 0xB7: "aarch64", 0x28: "arm", 0xF3: "riscv64", 0x03: "i386"}


def _elf_machine(head: bytes) -> str:
    if not head.startswith(ELF_MAGIC) or len(head) < 20:
        return ""
    return EM.get(head[18] | (head[19] << 8), f"unknown(0x{head[18]:02x})")


def _build_composed(ctx, work: Path) -> tuple:
    """Materialise a BuildCtx into a real project and build it. Returns (rc, out, err, exe)."""
    ctx.proj.mkdir(parents=True, exist_ok=True)
    (ctx.proj / "app.py").write_text(COMPOSED_APP)
    for rel, body in ctx.files.items():
        f = ctx.proj / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body)
    if ctx.decl:
        lines = []
        for k, v in ctx.decl.items():
            lines.append(f"{k} = {v!r}" if isinstance(v, str) else f"{k} = {v}")
        (ctx.proj / "haru_pack.toml").write_text("\n".join(lines) + "\n")
    for fn in [*ctx.post, *ctx.post_late]:
        fn(ctx.proj)

    out = work / ctx.out_name
    args = ["--tier", ctx.tier] if ctx.tier else []
    haru = shutil.which("haru-pack") or str(REPO / ".venv" / "bin" / "haru-pack")
    env = {**clean_env(work / "bc"), **ctx.env}
    entry = ctx.proj / ctx.entry
    r = subprocess.run([haru, "build", str(entry), "-o", str(out), *args, *ctx.cli],
                       capture_output=True, text=True, timeout=2400, env=env)
    return r.returncode, r.stdout or "", r.stderr or "", out


def _static_verdict(ctx, exe: Path) -> dict:
    """For a foreign target: read the payload instead of running it."""
    if not exe.exists():
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": "no artifact produced"}
    try:
        members = _payload_members(exe)
    except Exception as e:
        return {"outcome": "CRASHED", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"payload unreadable: {type(e).__name__}: {e}"}

    # Magic, not filenames. The first draft matched any path containing "manylinux", which
    # flagged pip's vendored `_manylinux.py` — the platform-DETECTION module, pure Python
    # source, not a wheel. Caught by the compose-1 baseline on 2026-09-10. A binary object is
    # identified by its bytes; a wheel only by an actual `.whl` name.
    def _is_wheel(n: str) -> bool:
        return n.endswith(".whl")

    problems = []
    if ctx.target == "windows":
        elves = [n for n, h in members if h.startswith(ELF_MAGIC)]
        if elves:
            problems.append(f"{len(elves)} ELF object(s) in a Windows payload, e.g. "
                            f"{elves[:3]}")
        linux_wheels = [n for n, _ in members if _is_wheel(n)
                        and ("manylinux" in n or "linux_x86_64" in n)]
        if linux_wheels:
            problems.append(f"linux wheel(s) in a Windows payload: {linux_wheels[:3]}")
    elif ctx.target == "linux-aarch64":
        wrong = [(n, m) for n, h in members if (m := _elf_machine(h))
                 and m not in ("aarch64", "arm")]
        if wrong:
            problems.append(f"{len(wrong)} non-ARM ELF object(s) in an aarch64 payload, "
                            f"e.g. {wrong[:3]}")
        x86_wheels = [n for n, _ in members if _is_wheel(n)
                      and ("x86_64" in n or "amd64" in n)]
        if x86_wheels:
            problems.append(f"x86 wheel(s) in an aarch64 payload: {x86_wheels[:3]}")

    if problems:
        # Built cleanly and shipped the wrong architecture. The binary would fail on the
        # target it was explicitly built for, which is the same shape as SILENT-WEDGE:
        # a quiet success that produces a broken artifact.
        return {"outcome": "SILENT-WEDGE", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": " | ".join(problems)[:400]}
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} payload matches target {ctx.target}, "
                      f"{len(members)} member(s) inspected", "stderr": ""}


def run_stack(fixture_exe: Path, work: Path, combo: tuple, seed: int,
              run_index: int, force: bool = False) -> dict:
    """Run one stack of traits. The single code path for every composed run."""
    fired = realize(combo, seed, run_index, force=force)
    skipped = [n for n in fired if TRAITS[n]["needs"] and not _have(TRAITS[n]["needs"])]
    fired = tuple(n for n in fired if n not in skipped)

    build_traits = [n for n in fired if TRAITS[n]["phase"] == "build"]
    run_traits = [n for n in fired if TRAITS[n]["phase"] == "run"]

    meta = {"selected": list(combo), "fired": list(fired), "skipped": skipped,
            "seed": seed, "run_index": run_index,
            "layers": sorted({TRAITS[n]["layer"] for n in fired})}

    exe, build_note = fixture_exe, ""
    bctx = None
    if build_traits:
        bctx = BuildCtx(proj=work / "proj")
        for n in build_traits:
            TRAITS[n]["fn"](bctx)
        rc, so, se, built = _build_composed(bctx, work)
        build_note = (so + se).strip()[-300:]
        if rc != 0 or not built.exists():
            # A refusal at build time is a fine outcome for a hostile stack, provided it is
            # a refusal and not a traceback.
            outcome = "CRASHED" if any(m in (so + se) for m in TRAITS_TRACEBACKS) \
                else "REFUSED"
            return {**meta, "outcome": outcome, "rc": rc, "seconds": 0,
                    "blame": "builder", "stdout": "", "stderr": build_note}
        exe = built
        if not bctx.runnable:
            return {**meta, **_static_verdict(bctx, exe), "build_note": build_note}

    rctx = RunCtx(env=clean_env(work / "c"), cwd=work)
    for n in run_traits:
        TRAITS[n]["fn"](rctx)
    for fn in [*rctx.pre, *rctx.pre_late]:
        fn(work, exe)

    degrades = any(TRAITS[n]["degrades"] for n in fired)
    r = run_exe(exe, rctx.cwd or work, env=rctx.env, timeout=rctx.timeout,
                args=rctx.args, rlimits=rctx.rlimits or None, argv0=rctx.argv0)
    if degrades and r["outcome"] == "CRASHED" and r.get("blame") == "app":
        # A trait that declared it can starve the application got what it asked for.
        r["outcome"] = "APP-CRASHED"
    return {**meta, **r, "build_note": build_note}


# Markers that mean the BUILD produced a traceback rather than a diagnostic. Separate from
# TRACEBACK_MARKERS because a build is Python and a launcher is Nim, and the Python ones
# would false-positive on a launcher's own error text.
TRAITS_TRACEBACKS = ("Traceback (most recent call last)", "Error: unhandled exception")


def _have(needs: tuple) -> bool:
    for n in needs:
        if n == "docker":
            if not shutil.which("docker"):
                return False
        elif n == "wine":
            if not shutil.which("wine"):
                return False
        elif n == "cross-built-artifact":
            return False        # supplied by the tourist cases, not by a plain stack
    return True


# ------------------------------------------------- archivist / auditor / crosseyed as cases
# These three personas assert a PROPERTY of an artifact rather than surviving a condition,
# so they are cases, not traits. "These two builds are identical" and "no ELF in a Windows
# payload" are not things to endure; they are things to check. The parts of them that DO
# compose — the foreign target, the planted secret, the shifted mtimes — live in
# busybody_traits.py and take part in stacks like everything else.


@case("archivist", ("RAN", "REFUSED"),
      "The same input built twice must produce the same payload bytes. An EV-signed binary "
      "nobody can reproduce is one nobody can audit: there is no way to show that the "
      "signed artifact corresponds to the source it claims to. payload.py writes zip "
      "entries with z.write(), which takes mtime and mode from disk, and nothing honours "
      "SOURCE_DATE_EPOCH — so this is expected to fail until it is fixed.",
      inv="INV-BUILD-03",
      remedy="Normalise the zip: a fixed date_time from SOURCE_DATE_EPOCH (or a constant), "
             "a fixed external_attr, and the already-sorted member order. The payload is "
             "the part that must be stable; the launcher stub is compiled and can differ.",
      per_fixture=False, serial=True)
def two_builds_of_one_input_are_identical(exe: Path, work: Path) -> dict:
    from haru_pack import overlay

    proj = work / "repro"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "app.py").write_text(COMPOSED_APP)

    digests, sizes, notes = [], [], []
    for i in (1, 2):
        out = work / f"repro-{i}"
        rc, so, se = _build(proj / "app.py", out, "--tier", "thin", timeout=1800)
        if rc != 0 or not out.exists():
            return {"outcome": "REFUSED", "rc": rc, "seconds": 0, "blame": "builder",
                    "stdout": "", "stderr": f"build {i} failed: {(so + se).strip()[-300:]}"}
        info = overlay.verify(out)
        blob = out.read_bytes()[info["payload_off"]:
                                info["payload_off"] + info["payload_len"]]
        digests.append(hashlib.sha256(blob).hexdigest())
        sizes.append(len(blob))
        # Touch nothing between builds: the point is that an unchanged tree is enough.
        notes.append(f"build{i}: {len(blob)}B sha={digests[-1][:16]}")

    if digests[0] == digests[1]:
        return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
                "stdout": f"{MARKER} payload reproducible: {digests[0][:16]}", "stderr": ""}

    diff = _first_zip_difference(work / "repro-1", work / "repro-2")
    return {"outcome": "SILENT-WEDGE", "rc": 0, "seconds": 0, "blame": "builder",
            "stdout": "", "stderr": (
                f"two builds of an unchanged tree differ. {' | '.join(notes)}. "
                f"first difference: {diff}")}


def _first_zip_difference(a: Path, b: Path) -> str:
    """Name the first differing member and WHY, so the fix is obvious from the report."""
    from haru_pack import overlay
    mem = []
    for exe in (a, b):
        info = overlay.verify(exe)
        blob = exe.read_bytes()[info["payload_off"]:
                                info["payload_off"] + info["payload_len"]]
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            mem.append({i.filename: i for i in z.infolist()})
    only_a = sorted(set(mem[0]) - set(mem[1]))
    only_b = sorted(set(mem[1]) - set(mem[0]))
    if only_a or only_b:
        return f"member sets differ (only in first: {only_a[:3]}, only in second: {only_b[:3]})"
    for name in sorted(mem[0]):
        x, y = mem[0][name], mem[1][name]
        if x.date_time != y.date_time:
            return (f"{name}: date_time {x.date_time} vs {y.date_time} "
                    f"(mtime is being embedded; honour SOURCE_DATE_EPOCH)")
        if x.external_attr != y.external_attr:
            return (f"{name}: external_attr {x.external_attr:#o} vs {y.external_attr:#o} "
                    f"(permission bits are being embedded; normalise them)")
        if x.CRC != y.CRC:
            return f"{name}: content differs (CRC {x.CRC:#x} vs {y.CRC:#x})"
    return "member metadata identical but the compressed bytes differ (compressor state?)"


@case("auditor", ("RAN", "REFUSED"),
      "Every credential shape the ignore list claims to cover is planted in the project, "
      "then the FINISHED BINARY is grepped for each planted value. The existing hygiene "
      "test reads decompressed zip members, which cannot see a secret that leaked by "
      "another route — through the manifest, a Nim string, or a warmed uv cache.",
      inv="INV-PAYLOAD-01",
      remedy="Any hit names the exact planted string; find where that path is copied. A "
             "leak here is published the moment the binary is distributed, and signing it "
             "makes the leak authentic.",
      per_fixture=False, serial=True)
def no_planted_secret_survives_into_the_binary(exe: Path, work: Path) -> dict:
    from busybody_traits import AUDITOR_SECRETS

    ctx = BuildCtx(proj=work / "leaky", tier="thick", out_name="leaky-bin")
    for name in ("auditor_plants_credentials", "auditor_plants_a_git_history",
                 "auditor_plants_a_venv_with_a_token",
                 "auditor_plants_a_secret_in_pycache"):
        TRAITS[name]["fn"](ctx)
    rc, so, se, out = _build_composed(ctx, work)
    if rc != 0 or not out.exists():
        return {"outcome": "REFUSED", "rc": rc, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"build failed: {(so + se).strip()[-300:]}"}

    planted = {}
    for body in ctx.files.values():
        for tok in re.findall(r"busybody_secret_[a-z]+_[0-9a-f]+", body):
            planted[tok] = True
    for body in AUDITOR_SECRETS.values():
        for tok in re.findall(r"busybody_secret_[a-z]+_[0-9a-f]+", body):
            planted[tok] = True

    blob = out.read_bytes()
    leaked = sorted(t for t in planted if t.encode() in blob)
    if leaked:
        return {"outcome": "SILENT-WEDGE", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": (
                    f"{len(leaked)} of {len(planted)} planted secret(s) are present in the "
                    f"finished binary: {leaked}")}
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} none of {len(planted)} planted secret(s) reached the "
                      f"binary ({len(blob) / 1e6:.0f}MB scanned)", "stderr": ""}


def _crosseyed(work: Path, trait_name: str, target: str) -> dict:
    ctx = BuildCtx(proj=work / f"cross-{target}", tier="thick",
                   out_name=f"cross-{target}")
    TRAITS[trait_name]["fn"](ctx)
    rc, so, se, out = _build_composed(ctx, work)
    if rc != 0 or not out.exists():
        return {"outcome": "REFUSED", "rc": rc, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"cross build failed: {(so + se).strip()[-400:]}"}
    return _static_verdict(ctx, out)


@case("crosseyed", ("RAN", "REFUSED"),
      "A --target windows --thick payload must contain no ELF objects from this host and no "
      "linux wheels. uv's --python-platform cross-download resolves wheels for the target "
      "without executing them, which is the right mechanism and a subtle one: a host .so "
      "reaching the payload produces a Windows binary that fails on first run, after the "
      "build reported success.",
      inv="INV-TIER-03",
      remedy="Inspect the payload members named in the finding. A host object in a foreign "
             "payload means something was staged with the host interpreter instead of "
             "resolved for the target.",
      per_fixture=False, serial=True)
def a_windows_payload_carries_no_linux_objects(exe: Path, work: Path) -> dict:
    return _crosseyed(work, "crosseyed_target_windows", "windows")


@case("crosseyed", ("RAN", "REFUSED"),
      "A --target linux-aarch64 --thick payload must contain only ARM ELF objects. An "
      "x86-64 interpreter in an aarch64 payload is a binary that dies on a Raspberry Pi "
      "with an exec format error — and the Pi is a stated target for this project, so the "
      "failure would land on a real user rather than in CI.",
      inv="INV-TIER-03",
      remedy="Check e_machine on the payload members named in the finding. 0x3E is x86-64; "
             "0xB7 is aarch64.",
      per_fixture=False, serial=True)
def an_aarch64_payload_carries_no_x86_objects(exe: Path, work: Path) -> dict:
    return _crosseyed(work, "crosseyed_target_aarch64", "linux-aarch64")



# ---------------------------------------------------------------- parallel execution

def run_one(fixture_name: str, exe_str: str, case_name: str, run_dir_str: str,
            work_root_str: str, keep: bool) -> dict:
    """Run one (case, fixture) pair and return its record. Safe to call in a worker process.

    Everything this needs arrives as arguments rather than through module state, and nothing
    it touches is shared: its own work directory, its own subprocesses, its own rlimits. The
    two things that ARE shared — the journal and the findings ledger — are deliberately not
    written here. The parent does that as records come back, which keeps the append order
    deterministic and the fsync-per-line contract intact with one writer.

    Args are strings because a work item crosses a process boundary; Path survives pickling
    but strings make it obvious that this is a message, not a reference.
    """
    c = next(x for x in CASES if x["name"] == case_name)
    exe, run_dir = Path(exe_str), Path(run_dir_str)
    work = Path(tempfile.mkdtemp(prefix=f"bb-{case_name}-",
                                 dir=work_root_str or None))
    try:
        try:
            r = c["fn"](exe, work)
        except Exception as e:
            r = {"outcome": "CASE-ERROR", "rc": None, "seconds": 0, "blame": "harness",
                 "stdout": "", "stderr": f"{type(e).__name__}: {e}"}
        r.setdefault("blame", blame(r.get("stdout", ""), r.get("stderr", "")))
        r["scratch_bytes"] = dir_bytes(work)

        ok = r["outcome"] in c["expect"] and r["outcome"] not in FATAL
        msg = (r.get("stderr") or r.get("stdout") or "").strip()
        rec = {**{k: c[k] for k in ("name", "persona", "why", "inv", "remedy")},
               **r, "ok": ok, "expect": list(c["expect"]), "fixture": fixture_name,
               "severity": severity_for(c, r, ok),
               "fingerprint": fingerprint(c["persona"], c["name"], r["outcome"], msg)}
        if not ok:
            rec["artifacts"] = preserve(run_dir, f"{fixture_name}--{case_name}", work)
        if keep:
            rec.setdefault("artifacts", str(work))
        return rec
    finally:
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



def compose_sweep(a, fixtures, jr, run_dir: Path, run_id: str, reaper, results: list) -> int:
    """Stack traits and run them. Returns an exit code.

    Kept separate from the case sweep because the two answer different questions and share
    only the journal: a case has an expectation, a stack has only the FATAL floor.
    """
    seed = a.compose_seed if a.compose_seed is not None else int(run_id[2:].replace("-", ""))
    exe = fixtures[0][1] if fixtures else None

    # Fallibility off for the baseline and for an explicitly-named stack; see realize().
    force = bool(a.compose_only) or a.compose == 1

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
        combos = [names] * max(1, a.compose_runs)
    elif a.compose == 1:
        combos = singleton_cases()
    else:
        combos = sample_combos(list(TRAITS), a.compose, a.compose_runs, seed)

    if not combos:
        print(f"no conflict-free stacks of {a.compose} trait(s) to run", file=sys.stderr)
        return 2

    jr.write("started", planned=[",".join(c) for c in combos], tier=a.tier,
             fixtures=[n for n, _ in fixtures], cases=len(combos), total=len(combos),
             mode="compose", compose_k=a.compose, compose_seed=seed, forced=force)
    jr.beat()
    print(f"\nbusybody compose: {len(combos)} stack(s) of "
          f"{a.compose if a.compose else len(combos[0])} trait(s)   run {run_id}")
    print(f"seed: {seed}   (reproduce a stack with --compose-only a,b,c)")
    print("fallibility: " + ("OFF — every selected trait fires, because this pass is the "
                             "attribution baseline" if force else
                             "ON — a trait may decline to act; the FIRED set is what counts"))
    for ln in work_root_report(WORK_ROOT or Path(tempfile.gettempdir())):
        print(ln)
    print(f"\n  acceptable: RAN / REFUSED / APP-CRASHED.  never: {', '.join(FATAL)}\n")

    peak = 0
    for i, combo in enumerate(combos):
        work = Path(tempfile.mkdtemp(prefix="bb-stack-", dir=WORK_ROOT or None))
        try:
            r = run_stack(exe, work, combo, seed, i, force=force)
            peak = max(peak, dir_bytes(work))
            fired = r.get("fired") or []
            ok = r["outcome"] not in FATAL
            rec = {**r, "name": "+".join(fired) or "(nothing fired)",
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
            if not ok:
                rec["artifacts"] = preserve(run_dir, f"stack-{i:04d}", work)
            results.append(rec)
            jr.write("case", **{k: v for k, v in rec.items() if k != "why"})
            jr.beat()
            n_sel, n_fired = len(combo), len(fired)
            drop = f" ({n_sel - n_fired} did not fire)" if n_fired < n_sel else ""
            print(f"  {'ok ' if ok else 'BAD'} [{i + 1:>4}/{len(combos)}] "
                  f"{r['outcome']:12} {'+'.join(fired) or '(control run)'}{drop}")
            if not ok:
                print(f"       {(r.get('stderr') or '').strip()[:160]}")
        finally:
            if not a.keep:
                free_dir(work)

    bad = [r for r in results if not r["ok"]]
    if bad:
        ledger_append([{k: v for k, v in r.items()
                        if k in ("name", "persona", "outcome", "severity", "fingerprint",
                                 "inv", "remedy", "artifacts", "fixture", "selected",
                                 "fired", "seed", "run_index")}
                       | {"run": run_id, "at": time.time(),
                          "message": (r.get("stderr") or r.get("stdout") or "")[:500]}
                       for r in bad])
    (run_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    write_report(results, "(stacks)", run_dir / "report.txt", run_id=run_id)
    jr.write("finished", cases=len(results), findings=len(bad),
             peak_scratch_bytes=peak)
    jr.close()
    reaper.reap()
    prune_runs(RUNS, keep=a.keep_runs, log=lambda m: print(f"  {m}"))

    print(f"\n{len(results) - len(bad)}/{len(results)} stack(s) stayed out of "
          f"{'/'.join(FATAL)}")
    print(f"peak scratch per stack: {human_bytes(peak)}")
    print(f"report : {(run_dir / 'report.txt').relative_to(REPO)}")
    if bad:
        print(f"\n{len(bad)} finding(s) — each with a --compose-only line to reproduce it:")
        for r in bad:
            print(f"  [{r['severity']}] {r['outcome']:12} {r['name']}")
            print(f"      {r['remedy']}")
        return 1
    return 0


def main() -> int:
    global WORK_ROOT, SCRATCH_CAP_GB
    ap = argparse.ArgumentParser(description=__doc__,
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
    ap.add_argument("--timeout", type=int, default=180)
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
                    help="seed for stack selection and for trait fallibility "
                         "(default: derived from the run id, and always recorded)")
    ap.add_argument("--compose-only", metavar="A,B,C", default="",
                    help="run exactly this stack, repeatedly if --compose-runs > 1; "
                         "the way to reproduce a finding")
    ap.add_argument("-j", "--jobs", type=int, default=JOBS_DEFAULT, metavar="N",
                    help=f"run cases in N worker processes (default {JOBS_DEFAULT}, max "
                         f"{JOBS_MAX}). Timing-sensitive cases always run serially.")
    ap.add_argument("--scratch-cap-gb", type=float, default=SCRATCH_CAP_GB,
                    metavar="N", help=f"abort if the scratch root exceeds N GiB "
                                      f"(default {SCRATCH_CAP_GB}; guards against a leak)")
    ap.add_argument("--calibrate", action="store_true",
                    help="measure the resource band between fixtures and stop")
    a = ap.parse_args()

    SCRATCH_CAP_GB = a.scratch_cap_gb

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

    if a.work_root:
        WORK_ROOT = Path(a.work_root).expanduser().resolve()
        # INV-LAUNCH-07: a work dir inside the repository lets uv discover haru-pack's own
        # pyproject.toml from it, and a staged run then adopts this project instead of the
        # one it packed. That bug clobbered the repo's .venv twice before the work dirs were
        # moved out. --work-root must not be a way to walk back into it.
        if WORK_ROOT == REPO or REPO in WORK_ROOT.parents:
            raise SystemExit(
                f"--work-root must be outside the repository (got {WORK_ROOT}).\n"
                f"A work dir under {REPO} lets uv discover haru-pack's own project from it, "
                f"so a\nstaged run adopts this checkout instead of the payload it was "
                f"built with. See INV-LAUNCH-07.")
        WORK_ROOT.mkdir(parents=True, exist_ok=True)

    if a.list_traits:
        print(describe_traits())
        return 0

    if a.history:
        return print_history()
    if a.triage:
        return print_triage()
    if a.analyze is not None:
        runs = sorted(d for d in (RUNS.iterdir() if RUNS.is_dir() else []) if d.is_dir())
        if not runs:
            print("no runs to analyse", file=sys.stderr)
            return 1
        target = runs[-1] if a.analyze == "latest" else RUNS / a.analyze
        if not (target / "journal.jsonl").exists():
            print(f"no journal in {target}", file=sys.stderr)
            return 1
        print(format_analysis(analyze_run(target)))
        return 0

    picked = CASES
    if a.persona:
        want = {s.strip() for s in a.persona.split(",")}
        picked = [c for c in picked if c["persona"] in want]
    if a.case:
        want = {s.strip() for s in a.case.split(",")}
        picked = [c for c in picked if c["name"] in want]
    if not picked:
        print("nothing selected", file=sys.stderr)
        return 1

    if a.list:
        cur = None
        for c in picked:
            if c["persona"] != cur:
                cur = c["persona"]
                print(f"\n== {cur} ==")
            print(f"  {c['name']:42} expect={'/'.join(c['expect'])}")
            print(f"      {' '.join(c['why'].split())}")
        print(f"\n{len(picked)} case(s); nothing was run.")
        return 0

    # A run id from the wall clock, so run directories sort chronologically and a human
    # can say "the 14:05 run" without consulting anything.
    run_id = "bb" + time.strftime("%Y%m%d-%H%M%S")
    run_dir = RUNS / run_id
    jr = Journal(run_dir, run_id)
    reaper = Reaper(log=lambda m: print(f"  {m}"))

    # EVERYTHING below is inside try/finally. Reaping is not conditional on success: a
    # chaos harness is the program most likely to be interrupted, and at the thick tier
    # each work directory holds a staged interpreter — tens of megabytes per case. The
    # previous version removed a work dir only on the success path, so a raising case or a
    # Ctrl-C leaked it.
    results, interrupted, aborted, rc = [], False, False, 0
    peak_scratch = 0
    try:
        reap_orphans(RUNS, log=lambda m: print(f"  {m}"))

        try:
            if a.fixtures == "synthetic":
                fixtures = [("synthetic", build_fixture(a.tier))]
            elif a.fixtures == "top25":
                fixtures = build_top25_fixtures(a.tier, reaper)
            else:
                exe = Path(a.fixtures).expanduser().resolve()
                if not exe.exists():
                    raise SystemExit(f"no such binary: {exe}")
                fixtures = [(exe.name, exe)]
        except SystemExit as e:
            # lotek calls this a SETUP FAILURE: the harness never reached the starting
            # line, so there are no results. Reporting zero findings would be a lie.
            jr.write("setup_failure", detail=str(e)[:400])
            print(f"SETUP FAILURE: {e}", file=sys.stderr)
            print(f"no cases ran; journal at {run_dir.relative_to(REPO)}", file=sys.stderr)
            return 2

        if a.calibrate:
            return calibrate(fixtures)

        # fixture-free cases run once; everything else once per fixture
        _ff = len([c for c in picked if not c.get("per_fixture", True)])
        total = len(fixtures) * (len(picked) - _ff) + _ff
        jr.write("started", planned=[c["name"] for c in picked], tier=a.tier,
                 fixtures=[n for n, _ in fixtures], cases=len(picked), total=total)
        jr.beat()
        print(f"\nbusybody: {len(picked)} case(s) x {len(fixtures)} fixture(s) "
              f"= {total} run(s)   run {run_id}")
        for ln in work_root_report(WORK_ROOT or Path(tempfile.gettempdir())):
            print(ln)
        print()

        # One code path for a case run: run_one(). The parallel pass hands work items to
        # a pool, the serial pass calls the same function inline. Records come back and the
        # parent — the only writer — journals them, which keeps the append order
        # deterministic and the one-fsync-per-line contract honest.
        def record(rec: dict) -> None:
            nonlocal peak_scratch
            peak_scratch = max(peak_scratch, rec.get("scratch_bytes") or 0)
            if reason := infra_failure_reason(rec):
                raise InfraFailure(
                    f"{rec['persona']}/{rec['name']} on {rec['fixture']}: {reason}")
            results.append(rec)
            jr.write("case", **{k: v for k, v in rec.items() if k != "why"})
            if len(results) % 25 == 0:
                live = dir_bytes(WORK_ROOT or Path(tempfile.gettempdir()))
                if live > SCRATCH_CAP_GB * 1024**3:
                    raise InfraFailure(
                        f"scratch root holds {human_bytes(live)} after {len(results)} "
                        f"case(s), over the {SCRATCH_CAP_GB} GiB cap. Reaping is "
                        f"per-case, so this is a leak, not normal growth.")
            jr.beat()
            ok = rec["ok"]
            print(f"  {'ok ' if ok else 'BAD'} {rec['persona']:14} {rec['name']:42} "
                  f"{rec['outcome']:9}{'  ' if ok else '<-'}"
                  + (f" [{rec['fixture']}]" if len(fixtures) > 1 else ""))

        # A case that says nothing about the packed package runs once, not once per
        # fixture. Running it 25 times would repeat one answer 25 times and inflate the
        # census, which is precisely what --analyze exists to expose.
        fixture_free = [c for c in picked if not c.get("per_fixture", True)]
        picked = [c for c in picked if c.get("per_fixture", True)]
        if a.compose is not None or a.compose_only:
            return compose_sweep(a, fixtures, jr, run_dir, run_id, reaper, results)

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
            items = [(fname, str(exe), c["name"], str(run_dir), str(WORK_ROOT or ""), a.keep)
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
                               str(WORK_ROOT or ""), a.keep))

        if serial_cases:
            if parallel_cases:
                print(f"\n-- serial pass: {len(serial_cases)} case(s) that measure time")
            for fname, exe in fixtures:
                if len(fixtures) > 1 and not parallel_cases:
                    print(f"-- {fname} ({exe.stat().st_size / 1e6:.0f}MB)")
                for c in serial_cases:
                    record(run_one(fname, str(exe), c["name"], str(run_dir),
                                   str(WORK_ROOT or ""), a.keep))

    except InfraFailure as e:
        aborted = True
        jr.write("infra_failure", detail=str(e)[:400], completed=len(results))
        print(f"\n*** ABORTED — the environment failed, not haru-pack.\n"
              f"    {e}\n\n"
              f"    {len(results)} case(s) had already run. They are journalled but NOT\n"
              f"    written to the findings ledger: once scratch space is exhausted every\n"
              f"    later result is the same failure wearing a different persona's costume,\n"
              f"    and a ledger full of those is worse than an empty one.\n",
              file=sys.stderr)
        for ln in work_root_report(WORK_ROOT or Path(tempfile.gettempdir())):
            print(f"    {ln}", file=sys.stderr)
        print("\n    Re-run with --work-root DIR pointing at a filesystem with room.",
              file=sys.stderr)
    except KeyboardInterrupt:
        interrupted = True
        jr.write("interrupted", completed=len(results),
                 planned=len(picked) * max(1, len(locals().get("fixtures", [1]))))
        print("\n^C — interrupted. Everything completed so far is in the journal.",
              file=sys.stderr)
    finally:
        bad = [r for r in results if not r["ok"]]
        if bad and not aborted:
            ledger_append([{k: v for k, v in r.items()
                            if k in ("name", "persona", "outcome", "severity",
                                     "fingerprint", "inv", "remedy", "artifacts",
                                     "fixture")}
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
        prune_runs(RUNS, keep=a.keep_runs, log=lambda m: print(f"  {m}"))

    bad = [r for r in results if not r["ok"]]
    if aborted:
        print(f"\n{len(results)} case(s) ran before the environment failed. This run is NOT"
              f"\na verdict on haru-pack — see the message above.")
        return 2
    print(f"\n{len(results) - len(bad)}/{len(results)} behaved as expected"
          + ("  (RUN INTERRUPTED — this is not the whole suite)" if interrupted else ""))
    if peak_scratch:
        print(f"peak scratch per case: {human_bytes(peak_scratch)}  "
              f"(cap {SCRATCH_CAP_GB} GiB on the root)")
    if results:
        print(f"report : {(run_dir / 'report.txt').relative_to(REPO)}   "
              f"<- read this; it explains every finding")
        print(f"journal: {(run_dir / 'journal.jsonl').relative_to(REPO)}")
    if bad:
        print(f"ledger : {ledger_path()}   (--triage to group by fingerprint)")
        print(f"\n{len(bad)} finding(s):")
        for r in bad:
            print(f"  [{r['severity']}] {r['outcome']:9} {r.get('fixture', '?')} "
                  f"{r['persona']}/{r['name']}" + (f"  {r['inv']}" if r.get("inv") else ""))

    # lotek's exit-code contract. An interrupt wins over findings: a run the operator
    # killed did not finish, and reporting its partial findings as a completed verdict is
    # the same lie facing the other way.
    if interrupted:
        return 130
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())

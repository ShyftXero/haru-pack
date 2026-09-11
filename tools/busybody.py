#!/usr/bin/env python3
"""busybody — chaos testing for haru-pack binaries. Does it fail WELL?

    python tools/busybody.py                      # every persona
    python tools/busybody.py --persona forger     # one persona
    python tools/busybody.py --list               # what would run, and why
    python tools/busybody.py --keep               # leave the wreckage for inspection
    python tools/busybody.py --triage             # past findings, grouped by fingerprint
    python tools/busybody.py --history            # every run, including interrupted ones

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
    SILENT    exit 0 but the app never ran                    (FINDING, the worst kind;
              for a build-time case, exit 0 and the directive was ignored)
    WEDGED    no process was making progress                 (FINDING; the watchdog says
              so, and no single child can)

A case passes when the outcome is in its `expect` set. CRASHED, HUNG, SILENT and WEDGED are
never acceptable, whatever the case — that is the whole standard.

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
    herd           Sixteen of them, at once, on one stage key, with a watchdog outside
                   every child. Tests the stall no single process can observe.
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

  A BUILD-TIME persona. The twelve above attack a finished binary, so they need one; this
  one attacks the BUILD that produces it, and runs once per run rather than once per
  fixture:

    tinkerer       Lives in configuration. Misspells a directive key by one character,
                   contradicts [tool.haru-pack] with haru_pack.toml and both with a CLI
                   flag, points an entrypoint out of the tree, passes --thin --thick.
                   Tests whether a directive haru-pack does not read is refused or
                   silently ignored (INV-BUILD-07).

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
import json
import os
import pty
import random
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from haru_pack import overlay  # noqa: E402

from busybody_ledger import (  # noqa: E402
    Journal, Reaper, fingerprint, ledger_append, ledger_path, ledger_rollup,
    prune_runs, reap_orphans, scan_runs)

OUT = REPO / "busybody" / "out"
RUNS = OUT / "runs"
MARKER = "BUSYBODY_OK"

# Never acceptable, in any case, whatever it declared.
#   CRASHED  the LAUNCHER dumped a traceback on the user
#   HUNG     nothing exited
#   SILENT   exit 0 and the app never ran
#   WEDGED   no child was progressing; a watchdog declared it, no single child did
# APP-CRASHED is deliberately NOT here: an application that raises under a limit a persona
# imposed on purpose is behaving correctly, and a case must opt into accepting it.
#
# Read from here, never re-listed. severity_for and write_report used to spell the same
# three names out again, so a fourth outcome would have been fatal in one copy and not in
# the other two.
FATAL = ("CRASHED", "HUNG", "SILENT", "WEDGED")

# The default wait for a case that does not name its own. --timeout was parsed and never
# read until now — run_exe hardcoded 120 while the flag advertised 180 — so main() sets
# this from a.timeout and run_exe reads it.
DEFAULT_TIMEOUT_S = 180

CASES = []


def case(persona: str, expect, why: str, inv: str = "", remedy: str = "",
         kind: str = "exe", light: bool = False):
    """Register a chaos case.

    `expect`  outcomes that are acceptable.
    `why`     what this case simulates and why it matters. Printed in the report.
    `inv`     the INVARIANTS.md entry that governs it, if any.
    `remedy`  what to do when it fails. Written into the report so the reader does not
              have to work it out, or ask anyone.
    `kind`    "exe"   -> fn(exe, work), once per fixture: attacks a built binary.
              "build" -> fn(haru, work), ONCE per run: attacks the build, whose answer
              does not vary by fixture. The driver dispatches on this field and never on
              the function's arity — a wrong signature raises TypeError, which the driver's
              bare `except` would swallow into a CASE-ERROR instead of naming the mistake.
    `light`   the work directory holds many near-identical subtrees (one shared stage plus
              N transient staging dirs), so preserve() keeps top-level files only.
    """
    def deco(fn):
        CASES.append({"name": fn.__name__, "persona": persona,
                      "expect": tuple(expect) if isinstance(expect, (list, tuple)) else (expect,),
                      "why": why, "inv": inv, "remedy": remedy, "kind": kind,
                      "light": light, "fn": fn})
        return fn
    return deco


class Ctx:
    """What a case can reach back to: the journal, its seed, the heartbeat.

    Module-level rather than a parameter because 37 existing cases take (exe, work) and
    widening all of them to reach the journal would be churn for no signal.

    Every method is a no-op when no run is in progress. The unit tests exec this module
    with importlib and there is no journal then; a context that raised outside a run would
    make a case that journals untestable.
    """

    journal = None          # set by the driver for the duration of one case; else None
    seed = 0
    case = ""
    fixture = ""

    @classmethod
    def enter(cls, journal, seed: int, case: str, fixture: str) -> None:
        cls.journal, cls.seed, cls.case, cls.fixture = journal, seed, case, fixture

    @classmethod
    def clear(cls) -> None:
        cls.journal, cls.case, cls.fixture = None, "", ""

    @classmethod
    def rng(cls, salt: str = "") -> random.Random:
        """A stream determined by (run seed, case, fixture, salt) and nothing else.

        hashlib, not the hash() builtin: hash() is salted per process, so the same --seed
        would draw a different stream every run and the one thing a seed is for — landing
        a fault at the same moment twice — would silently not work.
        """
        basis = "|".join((str(cls.seed), cls.case, cls.fixture, salt))
        digest = hashlib.sha256(basis.encode("utf-8")).digest()[:8]
        return random.Random(int.from_bytes(digest, "big"))

    @classmethod
    def perturb(cls, action: str, **fields) -> None:
        """Journal a fault BEFORE performing it, never after: a fault whose moment was
        chosen from a seed is unattributable if it is recorded after the fact, and the
        harness's own timing jitter then reads as a product defect.
        """
        if cls.journal is None:
            return
        cls.journal.write("perturb", case=cls.case, fixture=cls.fixture, seed=cls.seed,
                          action=action, **fields)          # write() flushes and fsyncs

    @classmethod
    def beat(cls) -> None:
        # A case that can outlast busybody_ledger.HEARTBEAT_STALE_S (120s) must beat from
        # inside itself. The driver beats only BETWEEN cases, so a herd case that runs
        # longer goes stale while it is still working — and a stale heartbeat is exactly
        # how reap_orphans and prune_runs decide a run is dead and delete its work dirs.
        if cls.journal is None:
            return
        cls.journal.beat()


# ---------------------------------------------------------------- outcome classification

TRACEBACK_MARKERS = (
    "Traceback (most recent call last)",      # Python
    "Error: unhandled exception",             # Nim
    "[IndexDefect]", "[RangeDefect]", "[ValueError]", "[OSError]",
    "sysFatal", "signal SIGSEGV", "core dumped",
)


def blame(out: str, err: str) -> str:
    """Who failed: the launcher, the packaged app, or the OS?

    An app-level case makes this distinction load-bearing. "haru-pack refused to run" and
    "the application started and then died" are different facts, and a run under a tiny
    memory limit is SUPPOSED to produce the second. Without the split, a persona that
    stresses the application reads as a launcher defect.

    The launcher prefixes every diagnostic with "haru-pack:", which is what makes this
    cheap. An app traceback has no such prefix.
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

    WEDGED is not decidable here and nothing about it belongs in this function. HUNG is
    ONE process failing to exit inside its timeout, which is all this sees. WEDGED is NO
    process making progress, which only a watchdog watching several of them can say.
    Deciding it from a single process's timeout would turn every slow case into a wedge.
    """
    blob = (out or "") + (err or "")
    if timed_out:
        return "HUNG"
    if any(m in blob for m in TRACEBACK_MARKERS):
        return "CRASHED" if blame(out, err) == "launcher" else "APP-CRASHED"
    if rc == 0:
        return "RAN" if MARKER in out else "SILENT"
    return "REFUSED"


def run_exe(exe: Path, cwd: Path, env=None, timeout: int | None = None, args=(),
            rlimits=None, argv0=None) -> dict:
    """Run a packed binary and classify what happened.

    `rlimits` applies resource limits in the child ({resource.RLIMIT_AS: (soft, hard)}),
    which is how the app-level personas starve an application without touching the host.
    `argv0` overrides argv[0] without renaming the file.
    `timeout` defaults to DEFAULT_TIMEOUT_S, which --timeout sets; pass one to override.
    """
    timeout = DEFAULT_TIMEOUT_S if timeout is None else timeout
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
                "stdout": "", "stderr": f"{type(e).__name__}: {e}"}
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
             "rebuilt, not reused and not treated as fatal. Check stageZip's reuse path.")
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
             "reads a partially written tree.")
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
# cascades of the wedge is evidence inside that record, not sixteen more records.
#
# Cost, stated so it is not a surprise: staging takes no lock, so each child extracts
# its own .tmp- copy and then races an atomic move. Peak disk under one work directory
# is therefore N times the staged tree — at the thick tier roughly 200 MB each, ~3 GB at
# N=16. That is half of why --herd-n exists; the other half is reproducing on a box with
# fewer cores.

HERD_N = 16          # --herd-n sets this, the way --timeout sets DEFAULT_TIMEOUT_S

# How long all three wedge conditions must hold CONTINUOUSLY before the watchdog says
# WEDGED.
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
# of a healthy cold start does the same thing pointing the other way — it cries wedge on
# a working run, and a case that always fires is a case nobody reads.
#
# The limit of the method, measured while validating it: an application that deliberately
# idles is indistinguishable from a stall by these three signals. A fixture that only
# slept produced 6s of continuous quiet on a 4-way healthy herd. So the herd cases
# hold for fixtures that stage, print and exit — which is every busybody fixture — and a
# packaged app that waits on a network or a prompt for longer than this does not belong
# in this persona at any threshold.
WEDGE_QUIET_S = 40.0


def _cpu_ticks(pid: int) -> int | None:
    """utime+stime for one pid in clock ticks, or None if the pid is gone.

    /proc, not resource.getrusage: rusage reports only children that have already been
    waited on, which is exactly the set a stall does not contain. The comm field is
    parenthesised and may itself contain spaces and parens, so the fields are taken after
    the LAST ')' — splitting the whole line on whitespace misreads a process named `a b)`.
    """
    try:
        blob = Path(f"/proc/{pid}/stat").read_text()
        f = blob[blob.rindex(")") + 2:].split()
        return int(f[11]) + int(f[12])            # stat fields 14 and 15, 1-indexed
    except (OSError, ValueError, IndexError):
        return None


def _staged_bytes(base: Path) -> int:
    """Total bytes under the launcher's staging area: the .tmp-* dirs and the stage root.

    Errors are swallowed on purpose. moveDir and removeDir run underneath this walk, so a
    file that vanishes between readdir and lstat is normal operation rather than a fault,
    and raising here would make the watchdog the least reliable thing in the run.
    """
    total = 0
    for root, _dirs, names in os.walk(base, onerror=lambda e: None, followlinks=False):
        for n in names:
            try:
                total += os.lstat(os.path.join(root, n)).st_size
            except OSError:
                continue
    return total


def _tmp_dirs(base: Path) -> list:
    """In-flight staging directories. stage.nim names them <key>.tmp-<pid>."""
    try:
        return [d for d in base.iterdir() if ".tmp-" in d.name and d.is_dir()]
    except OSError:
        return []


def _tmp_owner(d: Path) -> int | None:
    """The pid a staging directory names as its author, if the name still parses."""
    try:
        return int(d.name.rsplit(".tmp-", 1)[1])
    except (IndexError, ValueError):
        return None


class StallWatch:
    """Says WEDGED when nothing is progressing. A THREAD in the harness process.

    A thread, not a subprocess, for three reasons:

      * The harness parent is not computing while a herd runs — it sits in a poll/sleep
        loop here and in communicate() everywhere else, and both release the GIL, so a
        1s sampling thread is scheduled on time. If the parent were CPU-bound this would
        have to be a process.
      * It is already OUTSIDE every child, which is the only property that matters. The
        observer must not be one of the processes it is judging.
      * A subprocess would observe the same three things through the same /proc and
        lstat() calls and would then need IPC to hand the verdict back. It buys isolation
        from a harness crash, and a harness crash is not the failure this looks for.

    Three conditions, AND-ed, held continuously for `quiet_s`:

      * every child is still alive          (an exit IS progress, and the collector
                                             classifies it)
      * no child's CPU time advanced        (all of them, not one)
      * the staged byte total did not grow  (the tree is not being built)

    The conjunction is what makes three individually unreliable signals safe together.
    The byte walk can miss growth under churn and /proc is a clock tick coarse, but
    neither can declare a wedge alone: sixteen processes burning CPU are never quiet,
    whatever the walk says.
    """

    def __init__(self, base: Path, procs, quiet_s: float | None = None,
                 tick_s: float = 1.0):
        self.base = Path(base)
        self.quiet_s = WEDGE_QUIET_S if quiet_s is None else quiet_s
        self.tick_s = tick_s
        self.wedged_at = None      # time.monotonic() of the declaration; None until then
        self.wedge_id = ""
        self.wedge_blame = ""
        self.evidence = ""
        self.quiet_max = 0.0       # longest quiet stretch seen, wedge or not: THE number
        self.ticks = 0             # WEDGE_QUIET_S has to be calibrated against
        self.late = 0              # ticks that arrived far later than they were asked to
        self._scan_s = 0.0
        self._procs = list(procs)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def drop(self, proc) -> None:
        """Stop watching one child. For a child the CASE killed on purpose.

        Without this, a deliberate kill silently disarms the watchdog for the rest of the
        case: "every child alive" can never hold again once one is intentionally dead, so
        the case that most needs an observer would quietly not have one.
        """
        with self._lock:
            self._procs = [p for p in self._procs if p is not proc]

    def _roster(self) -> list:
        with self._lock:
            return list(self._procs)

    def start(self):
        self._thread = threading.Thread(target=self._run, name="stallwatch", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.tick_s * 5)

    def _run(self) -> None:
        prev_cpu, prev_bytes, quiet_since = None, None, None
        last = time.monotonic()
        while not self._stop.is_set():
            now = time.monotonic()
            # Our own scan time is not lateness. Anything past 3x the interval we asked
            # for is the scheduler, and that resets the quiet stretch — see _attribute.
            if self.ticks and now - last > (self.tick_s + self._scan_s) * 3:
                self.late += 1
                quiet_since = None
            last = now
            self.ticks += 1
            # HEARTBEAT_STALE_S is 120 and these cases outlive it. A stale heartbeat is
            # how reap_orphans and prune_runs decide a run is dead and delete its work
            # directories — out from under the case that is still using them.
            Ctx.beat()

            roster = self._roster()
            alive = [p for p in roster if p.poll() is None]
            t_scan = time.monotonic()
            cpu = {p.pid: _cpu_ticks(p.pid) for p in alive}
            nbytes = _staged_bytes(self.base)
            self._scan_s = time.monotonic() - t_scan

            quiet = (bool(roster) and len(alive) == len(roster)
                     and prev_cpu is not None and cpu == prev_cpu
                     and all(v is not None for v in cpu.values())
                     and prev_bytes is not None and nbytes <= prev_bytes)
            if quiet:
                quiet_since = now if quiet_since is None else quiet_since
                held = now - quiet_since
                self.quiet_max = max(self.quiet_max, held)
                if held >= self.quiet_s and self.wedged_at is None:
                    self._declare(now, held, nbytes, len(alive))
            else:
                quiet_since = None
            prev_cpu, prev_bytes = cpu, nbytes
            self._stop.wait(self.tick_s)

    def _declare(self, now: float, held: float, nbytes: int, alive: int) -> None:
        self.wedged_at = now
        # Shared by every sub-result that resolves after this instant, so a reader can
        # tie sixteen cascades back to the one stall that caused them.
        self.wedge_id = hashlib.sha256(
            f"{self.base}|{Ctx.case}|{Ctx.fixture}|{now}".encode()).hexdigest()[:12]
        self.wedge_blame, self.evidence = self._attribute(held, nbytes, alive)
        # NOT Ctx.perturb: perturb records a fault the harness INJECTED, and a wedge is
        # one it observed. Filing an observation as an injection would make the seeded
        # kill record — the one thing a seed exists to make reproducible — untrustworthy.
        if Ctx.journal is not None:
            Ctx.journal.write("wedge", case=Ctx.case, fixture=Ctx.fixture,
                              wedge_id=self.wedge_id, quiet_s=round(held, 1),
                              staged_bytes=nbytes, alive=alive,
                              blame=self.wedge_blame, evidence=self.evidence)

    def _attribute(self, held: float, nbytes: int, alive: int) -> tuple:
        """"launcher" only on launcher-side evidence. Otherwise "unknown".

        The one thing that counts as evidence: a staging directory whose byte count is
        static and whose OWNER IS DEAD. stage.nim names it <key>.tmp-<pid>, so an orphan
        names its own author, and "the survivors are waiting on a tree nobody is
        building" is then a claim about launcher-side state rather than about the box.
        Static comes for free from the wedge condition — the orphan sits inside the byte
        total that did not grow for the whole quiet stretch — so only the death of its
        owner has to be checked here.

        Everything else is "unknown", including — checked first, before anything else —
        this sampler not being scheduled. A watchdog that reports its own starvation on a
        loaded machine as a product wedge is tight_address_space again: it fires, it
        looks thorough, and it discriminates nothing.
        """
        seen = (f"{alive} child(ren) alive, no CPU and no new bytes for {held:.0f}s, "
                f"{nbytes} byte(s) staged")
        if self.late:
            return "unknown", (f"{seen}; this sampler was itself late on {self.late} "
                               f"tick(s) of {self.ticks}, so this may be our own "
                               f"scheduling rather than the launcher")
        orphans = []
        watched = {p.pid for p in self._roster()}
        for d in _tmp_dirs(self.base):
            pid = _tmp_owner(d)
            if pid is None or pid in watched:
                continue
            if not Path(f"/proc/{pid}").exists():
                orphans.append(f"{d.name} ({_staged_bytes(d)}B, owner pid {pid} gone)")
        if orphans:
            return "launcher", f"{seen}; orphaned staging dir(s): {', '.join(orphans)}"
        return "unknown", (f"{seen}; no orphaned staging directory, so nothing here says "
                           f"the launcher rather than the box")


def herd_deadline() -> int:
    """One deadline for the whole herd, not one per child.

    N sequential waits of DEFAULT_TIMEOUT_S would let a single 16-way case run for 48
    minutes. Sixteen cold starts do genuinely take longer than one — they serialise on
    the disk — so this scales with N and never drops below the default wait.
    """
    return max(DEFAULT_TIMEOUT_S, 20 * HERD_N)


def stage_key(exe: Path) -> str:
    """The stage key this binary will use, computed without running it.

    main.nim calls stageZip(payload, hexOf(ft.payloadSha)[0..15]) and stage.nim names the
    in-flight directory <key>.tmp-<pid> under baseDir(). The key comes from the FOOTER
    digest, so this holds for an encrypted payload too — the final directory name does
    not, since that carries the digest of the decrypted bytes.

    Recomputed here rather than learned by running the binary once, because a case that
    warms the cache to find out where the cache is is no longer a cold start.
    """
    info = overlay.verify(exe)
    at, ln = info["payload_off"], info["payload_len"]
    return hashlib.sha256(exe.read_bytes()[at:at + ln]).hexdigest()[:16]


def herd_start(exe: Path, work: Path, cache: Path, n: int) -> list:
    """n children, started as close together as this can manage, on ONE cache key.

    Output goes to a FILE per child, not a pipe. With N=16 a child that fills its 64 KB
    stdout pipe blocks in write() until the parent drains it, and the parent drains one
    child at a time — so a perfectly healthy herd would present this watchdog with all
    three of its wedge conditions (alive, no CPU, no new bytes) and busybody would report
    its own collection strategy as a haru-pack wedge. A file cannot fill.

    Returns (proc, logfile, handle) triples; herd_collect closes the handles.
    """
    cache.mkdir(parents=True, exist_ok=True)
    env = clean_env(cache)
    kids = []
    for i in range(n):
        log = work / f"child-{i:02d}.out"
        fh = log.open("wb")
        kids.append((subprocess.Popen([str(exe)], cwd=work, env=env,
                                      stdin=subprocess.DEVNULL, stdout=fh,
                                      stderr=subprocess.STDOUT), log, fh))
    return kids


def herd_collect(kids: list, watch: StallWatch, deadline_s: int | None = None) -> list:
    """Wait for every child, then classify each one on its own output.

    Records WHEN each child resolved, which is the whole post_wedge contract: once the
    watchdog has declared a wedge at T, a child that resolves after T did so in a system
    that was already stuck, and reading its failure as a fresh fault is how one stall
    becomes sixteen bugs.
    """
    deadline = time.monotonic() + (herd_deadline() if deadline_s is None else deadline_s)
    done = {}
    while len(done) < len(kids) and time.monotonic() < deadline:
        for i, (p, _log, _fh) in enumerate(kids):
            if i not in done and p.poll() is not None:
                done[i] = time.monotonic()
        if len(done) < len(kids):
            time.sleep(0.25)

    subs = []
    for i, (p, log, fh) in enumerate(kids):
        timed_out = i not in done
        if timed_out:
            p.kill()
            p.wait(timeout=30)
            done[i] = time.monotonic()
        fh.close()
        blob = log.read_text("utf8", "replace") if log.exists() else ""
        outcome = classify(p.returncode, blob, "", timed_out)
        cascade = watch.wedged_at is not None and done[i] >= watch.wedged_at
        subs.append({"i": i, "rc": p.returncode, "outcome": outcome,
                     "blame": blame(blob, "") if outcome != "RAN" else "none",
                     "post_wedge": cascade,
                     "wedge_id": watch.wedge_id if cascade else "",
                     "at": done[i], "tail": blob.strip()[-200:]})
    return subs


# Worst-of, the reduction twin uses, with the order spelled out because a herd has more
# outcomes to rank than twin did. WEDGED dominates: it is a statement about the whole
# system, and every child outcome recorded after it is downstream of it.
_HERD_ORDER = ("RAN", "REFUSED", "APP-CRASHED", "CRASHED", "SILENT", "HUNG", "WEDGED")


def _worse(a: str, b: str) -> str:
    rank = {name: i for i, name in enumerate(_HERD_ORDER)}
    return a if rank.get(a, len(rank)) >= rank.get(b, len(rank)) else b


def herd_verdict(subs: list, watch: StallWatch, t0: float, ignore=()) -> dict:
    """Reduce N children and one watchdog to one record.

    `ignore` holds the index of a child the case killed itself: its outcome is the case's
    own doing, and the SURVIVORS are the claim being made.
    """
    killed = set(ignore)
    judged = [s for s in subs if s["i"] not in killed]
    worst = "RAN"
    for s in judged:
        worst = _worse(worst, s["outcome"])
    if watch.wedged_at is not None:
        worst = "WEDGED"
    tally = {}
    for s in judged:
        tally[s["outcome"]] = tally.get(s["outcome"], 0) + 1
    detail = [f"{len(judged)} judged: "
              + ", ".join(f"{k}x{v}" for k, v in sorted(tally.items()))]
    if killed:
        detail.append("killed by this case: "
                      + ", ".join(f"#{s['i']} {s['outcome']}" for s in subs
                                  if s["i"] in killed))
    detail.append(f"longest quiet stretch {watch.quiet_max:.0f}s of the "
                  f"{watch.quiet_s:.0f}s a wedge needs, over {watch.ticks} tick(s)")
    if watch.wedged_at is not None:
        detail.append(f"WEDGE {watch.wedge_id} blamed on {watch.wedge_blame}: "
                      f"{watch.evidence}")
    cascades = [s for s in judged if s["post_wedge"]]
    if cascades:
        detail.append(f"{len(cascades)} child(ren) resolved after the wedge and are "
                      f"cascades of it, not separate faults")
    bad = next((s for s in judged if s["outcome"] != "RAN"), None)
    return {"outcome": worst,
            "rc": bad["rc"] if bad else (judged[0]["rc"] if judged else None),
            "seconds": round(time.monotonic() - t0, 1),
            "blame": watch.wedge_blame if worst == "WEDGED"
                     else (bad["blame"] if bad else "none"),
            # post_wedge marks a record as a CONSEQUENCE of a wedge, which sinks it below
            # the fresh findings at --triage. A declared wedge makes WEDGED the verdict
            # here and that record IS the fresh finding, so this is False by construction
            # today. The per-child flags above are where the cascade evidence lives; this
            # field keeps the distinction if a later case ever tolerates a wedge in its
            # expect set.
            "post_wedge": watch.wedged_at is not None and worst != "WEDGED",
            "wedge_id": watch.wedge_id,
            "stdout": " | ".join(detail),
            "stderr": (bad or {}).get("tail", "")}


@case("herd", ("RAN",),
      "Sixteen first runs at the same instant on one cold cache, watched from outside by "
      "a thread that samples liveness, per-child CPU time and the staged byte total once "
      "a second. twin proves two processes can share a stage; this asks whether sixteen "
      "can, which is the shape a CI job that starts one binary per worker actually has. "
      "The failure it exists for is the one no child can report: everybody alive, nobody "
      "burning CPU, nothing being written.",
      inv="INV-STAGE-01",
      remedy="RAN from all sixteen is the pass. WEDGED is the serious one, and the record "
             "carries what the watchdog saw, including whether an orphaned .tmp- "
             "directory made it a launcher-side claim. Note what INV-STAGE-01 does and "
             "does not cover: its Statement governs what a stage must satisfy before it "
             "is executed, which is exactly what the survivors' verdict asserts here, "
             "but NO current invariant Statement mentions concurrency or atomicity — "
             "that claim lives only in twin's remedy prose. If this wedges, the thing to "
             "write is the missing invariant about N stagers on one key, not a footnote "
             "under INV-STAGE-01.",
      light=True)
def sixteen_cold_starts_at_once(exe: Path, work: Path) -> dict:
    t0 = time.monotonic()
    cache = work / "herdcache"
    kids = herd_start(exe, work, cache, HERD_N)
    watch = StallWatch(cache / "haru-pack", [p for p, _, _ in kids]).start()
    try:
        subs = herd_collect(kids, watch)
    finally:
        watch.stop()
    return herd_verdict(subs, watch, t0)


@case("herd", ("RAN",),
      "Sixteen cold starts, one of them SIGKILLed mid-stage at a moment drawn from the "
      "run seed — butterfingers composed with twin, which no single-fault case can be. "
      "killed_mid_stage proves one process recovers from its own interrupted staging; "
      "this asks whether fifteen bystanders survive somebody else's, and the seed is "
      "here so a wedge found once can be landed again deliberately.",
      inv="INV-STAGE-01",
      remedy="The survivors must each end up with a complete, verified stage: RAN is the "
             "pass, and the victim's own outcome is excluded from the verdict because "
             "this case killed it. A REFUSED survivor means a dead stager's leftovers "
             "became reachable by another process, which is INV-STAGE-01's territory — a "
             "tree that cannot be accounted for is discarded and rebuilt, never "
             "inherited. WEDGED means the survivors waited on the dead child; reproduce "
             "it with the seed and delay the journal's perturb record carries.",
      light=True)
def sixteen_cold_starts_one_killed_mid_stage(exe: Path, work: Path) -> dict:
    t0 = time.monotonic()
    cache = work / "herdcache"
    rng = Ctx.rng("kill")
    # 0.8s is past exec and into staging; 6s is still inside it for a thick payload
    # (killed_mid_stage has used a fixed 1.5s since it was written). The victim is drawn
    # too — killing child 0 every time would only ever test the one that started first.
    delay = round(rng.uniform(0.8, 6.0), 2)
    kids = herd_start(exe, work, cache, HERD_N)
    victim = rng.randrange(len(kids))
    watch = StallWatch(cache / "haru-pack", [p for p, _, _ in kids]).start()
    try:
        time.sleep(delay)
        # BEFORE the kill, never after: a fault whose moment came from a seed is
        # unattributable if it is recorded afterwards.
        Ctx.perturb("kill_mid_stage", delay_s=delay, victim=victim, n=len(kids),
                    signal="SIGKILL")
        target = kids[victim][0]
        target.send_signal(signal.SIGKILL)
        watch.drop(target)          # or "every child alive" never holds again
        subs = herd_collect(kids, watch)
    finally:
        watch.stop()
    return herd_verdict(subs, watch, t0, ignore=(victim,))


@case("herd", ("RAN", "REFUSED"),
      "Sixteen starts against a staging directory whose owner died before it ever wrote "
      ".ready: the name stage.nim would have chosen, a half-extracted root/, mode 0700, "
      "and a pid that is genuinely gone. Today's staging takes no lock — every process "
      "builds in its own .tmp-<pid> and races an atomic move — so the orphan should be "
      "ignored outright. The case exists to keep it that way: the moment a lock or a "
      "wait-for-the-winner appears, waiting forever on a dead owner's claim is the bug "
      "that arrives with it, and no single process can see it happen.",
      inv="INV-STAGE-01",
      remedy="RAN (the orphan ignored) and REFUSED with one line naming the directory to "
             "remove are both acceptable — INV-STAGE-01 already requires a tree with no "
             ".ready to be refused rather than executed, which is the half of this case "
             "that a current invariant covers; the no-waiting half is not covered by any "
             "Statement today. WEDGED means something waits on a dead owner and must "
             "instead take the claim over or refuse. SILENT means the orphan's "
             "half-extracted tree ran, which is trust-on-first-use back in a new place.",
      light=True)
def sixteen_starts_against_an_orphaned_stage(exe: Path, work: Path) -> dict:
    t0 = time.monotonic()
    cache = work / "herdcache"
    base = cache / "haru-pack"
    base.mkdir(parents=True, exist_ok=True)
    base.chmod(0o700)                  # hardenDir's mode; 0777 is world_writable_cache
    # A pid that has already been waited on, rather than a number we hope is unused. It
    # can in principle be recycled before the children start, which would make the case
    # weaker but never falsely positive: a live owner is the ordinary race twin tests.
    corpse = subprocess.Popen(["/bin/true"])
    corpse.wait()
    tmp = base / f"{stage_key(exe)}.tmp-{corpse.pid}"
    (tmp / "root" / "app").mkdir(parents=True)
    (tmp / "root" / "app" / "half.py").write_text("# extraction stopped here\n")
    (tmp / "root" / "manifest.toml").write_text('entrypoint = "app/half.py"\n')
    for d in (tmp, tmp / "root"):
        d.chmod(0o700)                 # no .ready and no .stage-files, deliberately
    kids = herd_start(exe, work, cache, HERD_N)
    watch = StallWatch(base, [p for p, _, _ in kids]).start()
    try:
        subs = herd_collect(kids, watch)
    finally:
        watch.stop()
    r = herd_verdict(subs, watch, t0)
    r["stdout"] = f"orphan {tmp.name} (owner pid {corpse.pid} dead) | " + r["stdout"]
    return r


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
    "SILENT": "exit 0, but the app never ran — or a build ignored a directive",
    "WEDGED": "no child was progressing; declared by the watchdog, not by any child",
    "APP-CRASHED": "the packaged application raised; the launcher was not at fault",
    "CASE-ERROR": "the chaos case itself failed; this is a bug in busybody, not in haru-pack",
}


def write_report(results: list, exe_name: str, path: Path, run_id: str = "",
                 interrupted: bool = False) -> None:
    """A report a human reads on its own. No JSON, no cross-referencing, no AI.

    Every finding carries: what was done, what happened, what should have happened, why the
    case exists at all, the invariant that governs it, and the next step. If you are holding
    this file and nothing else, that has to be enough.
    """
    bad = [r for r in results if not r["ok"]]
    # A cascade is a case that failed BECAUSE a wedge had already been declared. It stays
    # in the report — the shape of a cascade is the primary evidence for the wedge — but
    # counting N of them among the findings reads as N distinct bugs, which is wrong.
    cascades = [r for r in bad if r.get("post_wedge")]
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
    if cascades:
        L.append(f"  cascades   : {len(cascades)} of those followed a declared wedge — "
                 f"consequences, not")
        L.append("               that many separate bugs")
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
    L.append(f"  Always a finding, whatever the case expected: {', '.join(FATAL)}.")
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
            if r.get("post_wedge"):
                L.append("    CASCADE   ran after a wedge was declared"
                         + (f" ({r['wedge_id']})" if r.get("wedge_id") else "")
                         + " — a consequence of that")
                L.append("              wedge, not an independent finding")
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
    if r["outcome"] in FATAL:
        return "critical"      # a traceback at the user, the wrong code running, or a wedge
    if r["outcome"] == "APP-CRASHED":
        return "note"          # the app declined the box it was given; not haru-pack's doing
    if r["outcome"] == "CASE-ERROR":
        return "note"          # busybody's own bug, not haru-pack's — say so, do not inflate
    return "warning"           # refused where it should have run, or the reverse


def preserve(run_dir: Path, case_name: str, work: Path, light: bool = False) -> str:
    """Copy a failing case's wreckage somewhere it will still exist tomorrow.

    Unconditional for findings: `--keep` is a flag people remember only after the
    interesting run, and you cannot triage a crash you threw away.

    `light` keeps top-level files only. A herd case's work dir holds one shared stage tree
    plus N transient staging dirs, and the branch below copytrees a directory whole — so
    the default would write the same staged interpreter N times for no extra evidence.
    """
    dest = run_dir / "findings" / case_name
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    kept, skipped = [], []
    for child in sorted(work.iterdir()):
        try:
            if child.is_file() and child.stat().st_size < 300 * 1024 * 1024:
                shutil.copy2(child, dest / child.name)
                kept.append(child.name)
            elif child.is_dir() and light:
                skipped.append(child.name + "/")
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
        + (f"Not copied (light case — top-level files only): {', '.join(skipped)}\n\n"
           if skipped else "")
        + "Re-run just this case:\n"
        + f"    python tools/busybody.py --case {case_name} --keep\n")
    return str(dest.relative_to(REPO))


# ---------------------------------------------------------------- history and triage

def print_history() -> int:
    runs = scan_runs(RUNS)
    if not runs:
        print("no runs yet")
        return 0
    print(f"{'run':22} {'state':12} {'cases':>5} {'findings':>8} {'cascades':>8}  planned")
    print(f"{'-' * 22} {'-' * 12} {'-' * 5:>5} {'-' * 8:>8} {'-' * 8:>8}  -------")
    for r in runs:
        planned = len(r["planned"] or []) if r["planned"] else "?"
        print(f"{r['run']:22} {r['state']:12} {r['cases']:>5} {r['findings']:>8} "
              f"{r.get('cascades', 0):>8}  {planned}")
    # The two columns are separate because they are separate claims. `findings` counts
    # cases that failed on their own; `cascades` counts cases that failed after a wedge
    # had been declared. Adding them would report one wedged herd as seventeen bugs, and
    # then --history and --triage would give different answers about the same run.
    if any(r.get("cascades") for r in runs):
        print()
        print("cascades ran after a wedge was already declared, so they are consequences")
        print("of a finding rather than findings of their own; they are counted apart from")
        print("the findings column, never inside it. `--triage` lists them last.")
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
    """An epoch second as the date a human triages by, or 'unknown'.

    Not 1970: a record that reached the ledger without a timestamp is a record with no
    date, and printing the epoch would read as a real and very old finding.
    """
    if not at:
        return "unknown"
    return time.strftime("%Y-%m-%d", time.localtime(at))


def _triage_group(i: int, g: dict) -> None:
    """One group, rendered. Shared so the findings and the cascades sections cannot drift
    apart in shape — the difference between them belongs in the heading, not the fields."""
    print("-" * 78)
    print(f"[{i}] {g['count']} occurrence(s)   severity: {g['severity']}   "
          f"outcome: {g['outcome']}")
    print(f"    fingerprint : {g['fingerprint']}")
    print(f"    cases       : {', '.join(g['cases'])}")
    print(f"    personas    : {', '.join(g['personas'])}")
    shown = g["runs"][:6]
    print(f"    seen in runs: {', '.join(shown)}"
          + (f"  (+{len(g['runs']) - 6} more)" if len(g["runs"]) > 6 else ""))
    # This file's docstring, busybody_ledger's, and docs/BUSYBODY.md all promise "a count
    # and a first-seen date"; the rollup computed the date all along and this printer
    # dropped it. It is the field that answers "old and known, or did it start today?".
    print(f"    first seen  : {_seen_date(g.get('first_seen'))}"
          + (f"   last: {_seen_date(g.get('last_seen'))}"
             if _seen_date(g.get("last_seen")) != _seen_date(g.get("first_seen")) else ""))
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
    # ledger_rollup already sorts every cascade group below every fresh one; split on the
    # field rather than trusting that order, so the two headings cannot interleave if the
    # sort key ever changes again.
    fresh = [g for g in groups if not g.get("post_wedge")]
    cascades = [g for g in groups if g.get("post_wedge")]
    print("=" * 78)
    print(f"busybody triage — {sum(g['count'] for g in fresh)} finding(s), "
          f"{len(fresh)} distinct")
    if cascades:
        print(f"                  plus {sum(g['count'] for g in cascades)} cascade(s), "
              f"{len(cascades)} distinct — listed last, and not counted above")
    print(f"ledger: {path}")
    print("=" * 78)
    print()
    print("Grouped by fingerprint: paths, timestamps, hex and bare numbers are normalised")
    print("out, so repeats of one root cause appear as ONE group with a count and a")
    print("first-seen date. Fix the group, not the occurrences. Biggest group first.")
    print()
    for i, g in enumerate(fresh, 1):
        _triage_group(i, g)
    if cascades:
        print("=" * 78)
        print("CASCADES — consequences of a wedge, NOT independent findings")
        print("=" * 78)
        print()
        print("Every occurrence below ran after a wedge had already been declared, so it")
        print("failed because of that wedge. One stall that takes sixteen children down is")
        print("one bug; counted by occurrences it outranked the fault that caused it, which")
        print("is why these are ranked below every group above no matter how large they get.")
        print("Fix the findings above and expect these to go with them. Anything still here")
        print("afterwards was never a cascade, and will then appear in the section above.")
        print()
        # Numbering continues rather than restarting: [17] has to mean one group, so that
        # a number written on a whiteboard still picks out the same row tomorrow.
        for i, g in enumerate(cascades, len(fresh) + 1):
            _triage_group(i, g)
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


# Enough of the escape vocabulary to see what a human sees, not a terminal emulator: a
# case that needed one would be asserting something about the terminal rather than about
# haru-pack.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]"           # CSI: colour, cursor, erase
                   r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC: window title
                   r"|\x1b[()][A-Za-z0-9]|\x1b[=>]")      # charset and keypad modes


def _plain(text: str) -> str:
    """What is actually readable: escapes removed, a pty's CR-LF normalised."""
    return _ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "")


def _run_on_a_pty(exe: Path, cwd: Path, env: dict, timeout: int) -> tuple:
    """Run with stdout AND stderr on a real terminal. Returns (rc, raw text, timed_out).

    A pty, not an environment variable: isatty() is the thing under test and nothing but
    a real terminal makes it true. stdin stays on /dev/null — no claim here needs a tty
    stdin, stdin_is_closed next door covers closed stdin, and a tty stdin that nobody
    ever writes to is a hang waiting to be misread as a finding.
    """
    master, slave = pty.openpty()
    p = subprocess.Popen([str(exe)], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                         stdout=slave, stderr=slave)
    os.close(slave)          # the child now holds the only slave fd, so the read below
    chunks = []              # sees a real end-of-file the moment it exits
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if not select.select([master], [], [], 0.5)[0]:
                continue
            try:
                data = os.read(master, 65536)
            except OSError:
                break        # EIO on a pty master IS end-of-file; it is not an error
            if not data:
                break
            chunks.append(data)
    finally:
        os.close(master)
    try:
        rc, to = p.wait(timeout=max(1, int(deadline - time.monotonic()))), False
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(timeout=30)
        rc, to = None, True
    return rc, b"".join(chunks).decode("utf8", "replace"), to


@case("mute", ("RAN",),
      "The same binary twice on one cache: once with stdout on a real pty (pty.openpty, "
      "so isatty is genuinely true) and once on a pipe. The app's marker has to survive "
      "both. This is the shape INV-UI-01 was written about — rich reads `[...]` as a "
      "style tag and drops an unrecognised one SILENTLY, so a message is eaten rather "
      "than mangled, and the piped path is the one nobody is watching. `| head -1` is "
      "stdout_closed_early's job; this is `> file`, and the one thing that must not "
      "differ between them is the text.",
      inv="INV-UI-01",
      remedy="SILENT is the finding: exit 0 with no marker on one of the two paths means "
             "the message was lost on that path, and INV-UI-01's red path is exactly "
             "that — markup on by default renders [project.scripts] as nothing at all. "
             "Formatting may legitimately differ (rich honours NO_COLOR and a non-tty "
             "stdout, and a tty gets width-dependent wrapping); TEXT may not. The record "
             "reports whether the two agree once escape sequences are stripped, so a "
             "divergence is visible without failing the case on a terminal width.")
def the_message_survives_a_tty_and_a_pipe(exe: Path, work: Path) -> dict:
    t0 = time.monotonic()
    env = clean_env(work / "c")
    # The pipe run goes first so the pty run reuses its stage: this case is about the
    # shape of stdout, not about staging, and staging twice doubles a slow case. Popen
    # rather than run(), and stdin on /dev/null on BOTH sides, so that the only thing
    # differing between the two runs is whether stdout is a terminal.
    p = subprocess.Popen([str(exe)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, cwd=work, env=env, text=True)
    try:
        pipe_out, pipe_err = p.communicate(timeout=DEFAULT_TIMEOUT_S)
        pipe_rc, pipe_to = p.returncode, False
    except subprocess.TimeoutExpired:
        p.kill()
        pipe_out, pipe_err = p.communicate()
        pipe_rc, pipe_to = None, True
    tty_rc, tty_raw, tty_to = _run_on_a_pty(exe, work, env, DEFAULT_TIMEOUT_S)
    # Stripped BEFORE classifying, and on BOTH sides: a marker wearing a colour code
    # would otherwise read as SILENT and this case would report ANSI as a launcher
    # defect. Comparing a stripped tty against an unstripped pipe would also call every
    # run a divergence, which is the same mistake one step later.
    tty_out, pipe_plain = _plain(tty_raw), _plain(pipe_out or "")
    pipe, tty = (classify(pipe_rc, pipe_plain, pipe_err, pipe_to),
                 classify(tty_rc, tty_out, "", tty_to))
    same = tty_out.strip() == pipe_plain.strip()
    outcome = _worse(pipe, tty)
    detail = (f"pipe={pipe} rc={pipe_rc} | tty={tty} rc={tty_rc} | same text after "
              f"stripping escapes: {same} | tty {len(tty_raw)} raw / {len(tty_out)} "
              f"plain chars vs pipe {len(pipe_plain)}")
    return {"outcome": outcome, "rc": pipe_rc,
            "seconds": round(time.monotonic() - t0, 1),
            "blame": blame(pipe_plain + tty_out, pipe_err) if outcome != "RAN" else "none",
            "stdout": detail, "stderr": (pipe_err or "").strip()[-300:]}


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
             "launcher traceback means the parent took the signal instead of the child.")
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
             "how a later run finds a directory being written to.")
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


# ================================================================ tinkerer

# Twelve personas above attack a finished binary. This one attacks the BUILD, because the
# config surface is where haru-pack grew fastest and nothing was hitting it. Directives
# live in three places — discovery < [tool.haru-pack] in pyproject.toml < haru_pack.toml
# < CLI flags — build._declarations merges the middle two with dict.update (per top-level
# key, not deep), and _resolve then consumes the merged dict with plain decl.get(). There
# is no unknown-key validation anywhere in that ladder.
#
# INV-BUILD-07 states the oracle itself, in its Assets paragraph: "A config table read by
# nobody is worse than a missing one, because the operator believes it took effect."
# That is SILENT, which this harness already calls the worst kind: a build that exits 0
# having ignored a directive is the packaging form of a Save that returns 200 and never
# persists. So the two cases below that expect a refusal and get exit 0 are findings, not
# miscalibrated cases.
#
# WHAT "THE DIRECTIVE TOOK EFFECT" IS READ FROM. Not the build log — the receipt prints
# out/tier/target/payload length/sha and says nothing about any directive. Not the
# binary's behaviour either, for these seven: a thin binary fetches uv and a Python on
# first run, so running one needs the network and measures the LAUNCHER, which the other
# twelve personas already do to death. The oracle is manifest.toml at the payload zip
# root — the same bytes the launcher parses at stage time — read back out of the artifact
# by payload_manifest(). RAN in this persona therefore means "exit 0 AND the shipped
# artifact records the directive as honoured", and every case names the field it read.
#
# COST, stated up front because there is no launcher-compile cache: every build
# recompiles the Nim launcher from scratch. Measured 2026-09-11 on this box: a --thin
# build of the APP script is 15 s wall (83 s CPU — nim parallelises), a refusal that
# lands in _declarations is 0.3 s because nothing is compiled or downloaded yet, and
# --thin is the only tier that bundles no uv, so five of these seven cases download
# nothing at all. The persona is five thin builds plus one tier case.

# Only the contradictory-tier case can reach the thick path, and a thick build downloads
# a uv and a CPython and XZ-compresses the uv — ~100 s at preset 9 on a cold cache, by
# bundle.compress_uv's own measurement. At the per-case default (180 s) that case would
# report HUNG for the harness timing out its own download, which is a fabricated finding.
THICK_BUILD_TIMEOUT_S = 900

# Enough of a pyproject.toml to be a real one; the [tool.haru-pack] table is what each
# case appends. A script target does not need [project] at all — it is here so the
# fixture looks like the project an operator would actually be editing.
PYPROJECT = '[project]\nname = "tinker"\nversion = "0.0.1"\n\n'

_TOOLCHAIN_NOTE = None          # the preflight answer, computed once per run


def toolchain_note() -> str:
    """Why this box cannot build at all, or "" — asked once, cached for the whole run.

    build() calls find_nim() and detect_c_toolchain() BEFORE _resolve reads a single
    directive, so on a box with no Nim every case in this persona fails identically with
    "Nim not found": seven records that look like seven guards firing and say nothing
    about the config surface. Worse, the four cases that EXPECT a refusal would PASS —
    the harness would report a clean persona on a box that cannot build.
    """
    global _TOOLCHAIN_NOTE
    if _TOOLCHAIN_NOTE is None:
        try:
            from haru_pack.bootstrap import detect_c_toolchain, find_nim
            nim, tc = find_nim(), detect_c_toolchain("host")
            _TOOLCHAIN_NOTE = "" if nim and tc.get("ok") else (
                f"this box cannot build: nim={nim or 'not found'}, c-toolchain="
                f"{'ok' if tc.get('ok') else (tc.get('advice') or 'missing')[:120]}")
        except (ImportError, OSError, RuntimeError) as e:
            # ToolchainError is a RuntimeError; ImportError is the box not having the
            # package at all. Anything else reaches the driver's own handler and becomes
            # a CASE-ERROR carrying the message, which is the same outcome by a longer
            # road — a preflight that raises must not take the persona down with it.
            _TOOLCHAIN_NOTE = f"toolchain preflight failed: {type(e).__name__}: {e}"
    return _TOOLCHAIN_NOTE


def build_env(work: Path) -> dict:
    """The build's environment: the caller's Python contamination stripped, the
    operator's download cache KEPT.

    Every other user of clean_env points XDG_CACHE_HOME at a scratch directory, because a
    launcher case that reuses a warm stage proves nothing. A build case is the opposite.
    That cache holds pinned, digest-verified downloads and the XZ-compressed uv, and
    isolating it would add ~100 s of recompression plus a 55 MB download to the one case
    that reaches the thick path, while testing nothing this persona is about.

    NO_COLOR because a record and its fingerprint should be text, not escape sequences
    (INV-UI-01 says it is honoured). The log is run through _plain() anyway: whether
    NO_COLOR is honoured is the herd's pty case's question, not a dependency of this one.
    """
    cache = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
    return clean_env(cache, NO_COLOR="1")


def tinker_project(work: Path, *, pyproject: str = "", sidecar: str = "",
                   extra=(), name: str = "proj") -> Path:
    """Write a throwaway project under the case's work dir; return the BUILD TARGET.

    The target is the script, not the directory, and that is the cheapest shape this
    persona can use: _resolve takes decl_dir = project.parent for a file target, so a
    sibling pyproject.toml's [tool.haru-pack] is read in full while discovery still
    treats the thing as a PEP 723 script — no [project.scripts] and no __main__ to
    satisfy, and no dependency to resolve.

    The app body is the module's APP constant, so the marker assertion every other
    persona relies on keeps holding for whichever candidate an artifact ends up naming.
    """
    proj = work / name
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "app.py").write_text(APP)
    for rel, body in extra:
        p = proj / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    if pyproject:
        (proj / "pyproject.toml").write_text(pyproject)
    if sidecar:
        (proj / "haru_pack.toml").write_text(sidecar)
    return proj / "app.py"


def run_build(haru: Path, project: Path, work: Path, *args, out_name: str = "out",
              timeout: int | None = None) -> dict:
    """Run one `haru-pack build` and return the facts without judging them.

    Keys: rc, log, timed_out, exe (the artifact, or None), seconds, argv, preflight.

    The two streams are merged into one log on purpose. haru-pack's ui prints diagnostics
    and progress through the same rich Console, so the operator sees one ordered
    transcript and that is what the classifier should read; and a log FILE cannot fill the
    way a 64 KB pipe can while this loop is sleeping (the herd learned that the hard way).

    Ctx.beat() every 5 s while waiting: busybody_ledger.HEARTBEAT_STALE_S is 120 and a
    thick build runs longer than that, and a stale heartbeat is how reap_orphans decides a
    LIVE run is dead and deletes its work dirs.
    """
    note = toolchain_note()
    if note:
        return {"rc": None, "log": "", "timed_out": False, "exe": None,
                "seconds": 0.0, "argv": [], "preflight": note}
    timeout = DEFAULT_TIMEOUT_S if timeout is None else timeout
    exe = work / out_name
    argv = [str(haru), "build", str(project), "-o", str(exe), *args]
    logfile = work / f"{out_name}.build.log"
    t0 = time.monotonic()
    timed_out = False
    with logfile.open("wb") as fh:
        p = subprocess.Popen(argv, cwd=work, env=build_env(work),
                             stdin=subprocess.DEVNULL, stdout=fh,
                             stderr=subprocess.STDOUT)
        while True:
            try:
                p.wait(timeout=5)
                break
            except subprocess.TimeoutExpired:
                Ctx.beat()
                if time.monotonic() - t0 > timeout:
                    p.kill()
                    p.wait()
                    timed_out = True
                    break
    return {"rc": p.returncode, "log": _plain(logfile.read_text(errors="replace")),
            "timed_out": timed_out, "exe": exe if exe.is_file() else None,
            "seconds": round(time.monotonic() - t0, 1), "argv": argv, "preflight": ""}


def payload_manifest(exe: Path) -> dict:
    """The manifest.toml out of an artifact's payload, without running the artifact.

    This is the record that decides what the launcher does — the same bytes it parses at
    stage time — so reading it asserts something about the SHIPPED artifact rather than
    about the build's own log, which mentions no directive at all. Only valid for an
    unencrypted payload, which is every case in this persona.
    """
    import io
    import zipfile

    import tomllib  # own group: requires-python >= 3.9, not stdlib there

    info = overlay.verify(exe)
    at, ln = info["payload_off"], info["payload_len"]
    with zipfile.ZipFile(io.BytesIO(exe.read_bytes()[at:at + ln])) as z:
        return tomllib.loads(z.read("manifest.toml").decode("utf-8"))


def manifest_entrypoint(exe) -> list:
    """The entrypoint argv the artifact records, or [] if there is no artifact."""
    return list(payload_manifest(exe).get("entrypoint") or []) if exe else []


def classify_build(b: dict, honoured: bool | None = None) -> str:
    """Map a build onto the existing closed vocabulary — no new outcome words.

        REFUSED  non-zero with a haru-pack diagnostic (a guard fired: good)
        CRASHED  non-zero with a language-level traceback
        SILENT   exit 0 and the directive did not take effect (the worst kind)
        RAN      exit 0 and the artifact records the directive as honoured

    `honoured` is what the case established from manifest.toml. None means the case is a
    refusal case with nothing to read: exit 0 is then SILENT by definition, because the
    build accepted what it was supposed to refuse.

    TRACEBACK_MARKERS is shared with the launcher path deliberately. A build-time
    traceback is the same defect wearing different clothes — cli.py catches BuildError,
    EntryPointError, AmbiguousProject and TargetError, and anything else reaches the
    operator as a rich traceback full of build-machine paths.
    """
    if b["preflight"]:
        return "CASE-ERROR"
    if b["timed_out"]:
        return "HUNG"
    if any(m in b["log"] for m in TRACEBACK_MARKERS):
        return "CRASHED"
    if b["rc"] != 0:
        return "REFUSED"
    return "RAN" if honoured else "SILENT"


def build_verdict(b: dict, outcome: str, *evidence) -> dict:
    """One record in the shape the driver expects, carrying what the case established.

    The evidence strings are load-bearing: "SILENT" cannot by itself say WHICH directive
    was ignored or what the artifact recorded instead, and the report prints this field.
    """
    detail = [e for e in evidence if e]
    if b["preflight"]:
        detail.append(b["preflight"])
    return {"outcome": outcome, "rc": b["rc"], "seconds": b["seconds"],
            # blame's vocabulary — launcher/app/unknown — is about a RUNNING binary, and
            # neither half fits a build. blame() would answer "app" for every diagnostic
            # here, because a build message carries no "haru-pack:" prefix, filing "the
            # builder ignored a directive" next to "the packaged app declined a resource
            # limit". "build" is a fourth value; no test pins the set (the three tests on
            # blame() assert its answers for given inputs, which are unchanged).
            "blame": {"RAN": "none", "CASE-ERROR": "unknown"}.get(outcome, "build"),
            "stdout": " | ".join(detail),
            "stderr": (b["log"] or "").strip()[-400:]}


@case("tinkerer", ("REFUSED",),
      "A [tool.haru_pack] table with an UNDERSCORE in pyproject.toml — one character "
      "away from the name haru-pack reads, and the spelling a developer who thinks in "
      "Python identifiers writes first. haru-pack must refuse rather than build a binary "
      "whose entire configuration was addressed to nobody. This is the persona's "
      "calibration case: INV-BUILD-07 guards it explicitly, so it should pass, and if it "
      "does not then nothing else this persona reports can be trusted either.",
      inv="INV-BUILD-07",
      remedy="The guard is the `if \"haru-pack\" not in tool and \"haru_pack\" in tool` "
             "branch in build._declarations, and INV-BUILD-07's Red-path names deleting "
             "it. SILENT here means it is gone: restore it, and check "
             "test_an_underscored_tool_table_is_refused_not_ignored is still red without "
             "it. REFUSED for the wrong reason — a missing toolchain, an unrelated "
             "BuildError — shows up as CASE-ERROR instead, which is why the toolchain is "
             "preflighted once per run.",
      kind="build")
def tool_table_with_an_underscore(haru: Path, work: Path) -> dict:
    proj = tinker_project(
        work, pyproject=PYPROJECT + '[tool.haru_pack]\nentrypoint = "app.py"\n')
    b = run_build(haru, proj, work, "--thin")
    # Nothing to read from an artifact: the refusal IS the answer, and it lands in
    # _declarations before the launcher is compiled or anything is downloaded. honoured
    # stays None, so exit 0 classifies as SILENT — the build accepted a table it cannot
    # read, which is the failure INV-BUILD-07 exists to prevent.
    return build_verdict(b, classify_build(b),
                         "[tool.haru_pack] (underscore) present, no hyphenated table")


@case("tinkerer", ("REFUSED",),
      "A directive key misspelled the way this one actually gets misspelled: "
      "`entry-point` for `entrypoint`, in a correctly-named [tool.haru-pack] table, "
      "naming a second script that exists. Nothing in the ladder validates keys — "
      "_declarations merges the table wholesale and _resolve reads the handful of names "
      "it knows with decl.get() — so the operator's directive is carried all the way "
      "into a merged dict that nobody ever asks about, and the build exits 0. The "
      "artifact runs the discovered entrypoint instead, which is the developer three "
      "months later wondering why a directive did nothing.",
      inv="INV-BUILD-07",
      remedy="Refuse, the way the underscored table is refused, and for the same reason: "
             "validate the merged dict's top-level keys in build._declarations against "
             "the set that is actually read — entrypoint, name, kind, app_subdir, "
             "cwd_policy, verbose_uv, python, encryption, shake, bundle, pre_install, "
             "post_install and uv_run_args in _resolve, plus `sources` in "
             "Sources.resolve — and name the nearest match in the message: 'unknown "
             "directive \"entry-point\"; did you mean \"entrypoint\"?'. "
             "INV-BUILD-07's Statement covers the underscored TABLE but says nothing "
             "about an unknown KEY inside a correctly-named one; the "
             "Statement needs widening to 'a directive haru-pack does not read is never "
             "silently ignored' with a claiming test per spelling.",
      kind="build")
def directive_key_with_a_plausible_typo(haru: Path, work: Path) -> dict:
    proj = tinker_project(
        work, pyproject=PYPROJECT + '[tool.haru-pack]\nentry-point = "cli.py"\n',
        extra=(("cli.py", APP),))
    b = run_build(haru, proj, work, "--thin")
    # The effect is read from the artifact's manifest, which is what the launcher obeys:
    # cli.py means the key was read (wrong too — two spellings for one directive — but a
    # different failure), app.py means the directive was dropped on the floor.
    ep = manifest_entrypoint(b["exe"])
    return build_verdict(b, classify_build(b, honoured=ep == ["cli.py"]),
                         f"directive named cli.py under the key 'entry-point'; "
                         f"artifact entrypoint {ep or 'none (no artifact)'}")


@case("tinkerer", ("RAN",),
      "The two directive homes disagree: [tool.haru-pack] in pyproject.toml says one "
      "entrypoint, a haru_pack.toml sidecar beside it says another, and both files exist "
      "in a tree a developer is editing. The documented ladder puts the sidecar above "
      "pyproject.toml — it is the local override — so the artifact must name the "
      "sidecar's script. This pins the precedence rather than hunting a bug: a ladder "
      "nobody tests is a ladder that gets reordered by a refactor, and the symptom is a "
      "binary that runs the wrong program on a customer's machine.",
      inv="INV-BUILD-07",
      remedy="The order is stated in both INV-BUILD-07's Statement and "
             "build._declarations' docstring: discovery < [tool.haru-pack] < "
             "haru_pack.toml < CLI flags. If the artifact names pyproject's script, the "
             "two merged.update() calls in _declarations have been swapped and every "
             "project carrying both files silently changed meaning; the fix is the order, "
             "not a note in the docs.",
      kind="build")
def two_directive_homes_disagree(haru: Path, work: Path) -> dict:
    proj = tinker_project(
        work, pyproject=PYPROJECT + '[tool.haru-pack]\nentrypoint = "app.py"\n',
        sidecar='entrypoint = "cli.py"\n', extra=(("cli.py", APP),))
    b = run_build(haru, proj, work, "--thin")
    ep = manifest_entrypoint(b["exe"])
    return build_verdict(b, classify_build(b, honoured=ep == ["cli.py"]),
                         f"pyproject says app.py, haru_pack.toml says cli.py; artifact "
                         f"entrypoint {ep or 'none (no artifact)'} (sidecar must win)")


@case("tinkerer", ("RAN",),
      "A directive contradicted by the equivalent CLI flag: haru_pack.toml names one "
      "entrypoint, `--entry-point` on the same command line names another. The flag is "
      "the top of the ladder and must win — anything else means the operator cannot "
      "override a checked-in directive from the command line, which is the one thing a "
      "flag is for.",
      inv="INV-BUILD-07",
      remedy="_resolve already prefers `entry_point or decl.get(\"entrypoint\")` in two "
             "places (the ambiguity rescue and the resolution proper). If the artifact "
             "names the sidecar's script, one of those two reads lost its `entry_point "
             "or` prefix — the ordering was backwards once before, and the symptom then "
             "was a project with an explicit entrypoint being told to set an entrypoint.",
      kind="build")
def a_directive_contradicted_by_its_cli_flag(haru: Path, work: Path) -> dict:
    proj = tinker_project(work, sidecar='entrypoint = "cli.py"\n',
                          extra=(("cli.py", APP),))
    b = run_build(haru, proj, work, "--thin", "--entry-point", "app.py")
    ep = manifest_entrypoint(b["exe"])
    return build_verdict(b, classify_build(b, honoured=ep == ["app.py"]),
                         f"haru_pack.toml says cli.py, --entry-point says app.py; "
                         f"artifact entrypoint {ep or 'none (no artifact)'} "
                         f"(the flag must win)")


@case("tinkerer", ("REFUSED",),
      "`--thin --thick` on one command line: the two tiers are mutually exclusive by "
      "construction — thin bundles nothing and needs the network, thick bundles "
      "everything and forbids it — and cli._run_build resolves them with two unguarded "
      "ifs, so whatever the operator typed, thick wins and nothing says so. The operator "
      "asked for the smallest possible binary and gets an 82 MB one, or asks for a "
      "hermetic binary and gets one that downloads on first run; either way the receipt "
      "reports the tier they did not ask for as if it were the one they did.",
      inv="",
      remedy="Refuse in cli._run_build, before any work: a tier is one choice, so two "
             "flags naming different ones is a typo or a stale script, and picking the "
             "later flag silently is the form of the bug --shake was written to avoid "
             "('asked for small, silently got fat'). Hand over the fix — name both flags "
             "and the tier each one means. NO invariant covers this today; the refusal "
             "should arrive with one, because the thing that must never happen is a "
             "receipt that names a tier the operator did not choose.",
      kind="build")
def contradictory_tier_flags(haru: Path, work: Path) -> dict:
    proj = tinker_project(work)
    b = run_build(haru, proj, work, "--thin", "--thick",
                  timeout=THICK_BUILD_TIMEOUT_S)
    # honoured=False because exit 0 cannot be a pass here whichever tier won: the
    # contradiction was resolved without a word either way. The tier is read from the
    # artifact's manifest (tiers.apply_tier writes it) so the record says WHICH one.
    tier = payload_manifest(b["exe"]).get("tier") if b["exe"] else ""
    if not tier and "bundle_python" in b["log"]:
        # No artifact to read a tier out of, but bundle_python is called from exactly one
        # place — the `if tier == "thick"` branch of assemble_payload — so its name in
        # the log is still proof of which flag won.
        tier = "thick (the log reaches bundle_python)"
    outcome = classify_build(b, honoured=False)
    # Gated on REFUSED, not tested against the whole log, and that is not fussiness: rich
    # prints the failing frame's SOURCE in a traceback, and one of cli.py's own lines is
    # the help text "Tiers: --thin ... --thick/--chonky". A substring test over a
    # traceback therefore claims the contradiction was reported when it was not.
    named = outcome == "REFUSED" and "--thin" in b["log"] and "--thick" in b["log"]
    if outcome == "REFUSED" and not named:
        # It refused, but not about this. A thick build has a whole second economy to
        # fail in — an unpinned interpreter, no network, a full disk — and counting that
        # as the guard firing would mark this case as passing for a reason it never
        # tested. Measured 2026-09-11 on this box: the thick path dies in 2.6 s at an
        # unpinned python-build-standalone URL, and does it by way of an UNCAUGHT
        # UnpinnedArtifact (archives.py raises a RuntimeError; cli.py catches BuildError,
        # EntryPointError, AmbiguousProject and TargetError), which classify_build sees
        # as CRASHED before it ever gets here.
        outcome = "CASE-ERROR"
    return build_verdict(b, outcome,
                         f"--thin --thick both given; artifact tier {tier or 'unknown'}",
                         "a one-line diagnostic named both flags" if named else
                         "no refusal named the contradiction")


@case("tinkerer", ("REFUSED",),
      "A directive naming a file OUTSIDE the project tree, in the two spellings an "
      "operator reaches for: `../shared/cli.py` (the app lives one level up, beside its "
      "siblings) and `sub/../../shared/cli.py` (the same file, arrived at through a "
      "directory that does exist). Only the project's own tree is copied into the "
      "payload, so either one names a file that will not be there — a guaranteed "
      "first-run failure on the customer's machine, decidable at build time, which is "
      "exactly the class INV-BUILD-04's entrypoint verification exists for.",
      inv="INV-BUILD-04, INV-BUILD-07",
      remedy="_PLAIN_NAME in entrypoints.resolve_entrypoint rejects a leading '..' or "
             "'/', which is what refuses the first spelling. The second is not a "
             "spelling problem and cannot be fixed in that regex: verify_script_file "
             "resolves `Path(project) / spec` and asks is_file(), so an interior '..' "
             "that lands on a real file outside the tree passes. Resolve the candidate "
             "and require it to stay under decl_dir — the same containment check "
             "archives._is_within already applies to archive members (INV-SUPPLY-03) — "
             "and refuse with the resolved path in the message.",
      kind="build")
def a_directive_pointing_outside_the_project(haru: Path, work: Path) -> dict:
    shared = work / "shared"
    shared.mkdir(parents=True, exist_ok=True)
    (shared / "cli.py").write_text(APP)

    plain = tinker_project(work, sidecar='entrypoint = "../shared/cli.py"\n')
    b = run_build(haru, plain, work, "--thin")
    first = classify_build(b)
    if first != "REFUSED":
        # The obvious spelling got through (or the box cannot build, which build_verdict
        # reports on its own); there is nothing subtler to add.
        return build_verdict(b, first, "" if b["preflight"] else
                             "entrypoint '../shared/cli.py' was not refused")

    # Same file, spelled through a directory that exists. `sub` has to be real: is_file()
    # asks the OS to resolve the path, and the OS will not walk '..' out of a component
    # that is not there.
    escaped = tinker_project(work, sidecar='entrypoint = "sub/../../shared/cli.py"\n',
                             extra=(("sub/keep.py", APP),), name="proj2")
    b2 = run_build(haru, escaped, work, "--thin", out_name="out2")
    ep = manifest_entrypoint(b2["exe"])
    # honoured=False: this spelling being HONOURED is the finding, not the pass. Exit 0
    # therefore classifies as SILENT, and the evidence says what was silent about it —
    # the containment check had no effect, and the artifact carries an entrypoint that
    # resolves outside its own payload.
    return build_verdict(b2, classify_build(b2, honoured=False),
                         f"'../shared/cli.py' refused (rc={b['rc']})",
                         f"'sub/../../shared/cli.py' names the same file; artifact "
                         f"entrypoint {ep or 'none (no artifact)'}")


@case("tinkerer", ("RAN",),
      "A [[bundle]] list in BOTH homes, with different steps. INV-BUILD-07's Note says "
      "the merge is per top-level key and not deep: the sidecar's list REPLACES "
      "pyproject's rather than extending it. Worth pinning precisely because the "
      "tempting implementation is the wrong one — concatenating reads as the friendly "
      "choice and would mean an operator can add a build step but never remove an "
      "inherited one, and 'why is this build still running a step I deleted' is a bad "
      "afternoon. Runs at --thin, where the steps are recorded in the manifest and never "
      "executed, so the case costs one launcher compile and no network.",
      inv="INV-BUILD-07",
      remedy="The behaviour comes from _declarations' two merged.update() calls being "
             "dict.update and nothing deeper. If the artifact records both steps, "
             "something grew a deep merge: INV-BUILD-07's Note is the statement to honour "
             "or to change deliberately, with a claiming test either way — not something "
             "to leave differing between the invariant and the code.",
      kind="build")
def a_bundle_list_in_both_homes(haru: Path, work: Path) -> dict:
    proj = tinker_project(
        work,
        pyproject=PYPROJECT + '[tool.haru-pack]\n\n[[tool.haru-pack.bundle]]\n'
                              'run = ["echo", "from-pyproject"]\n',
        sidecar='[[bundle]]\nrun = ["echo", "from-sidecar"]\n')
    b = run_build(haru, proj, work, "--thin")
    steps = (payload_manifest(b["exe"]).get("bundle") or []) if b["exe"] else []
    runs = [" ".join(s.get("run", [])) if isinstance(s, dict) else str(s) for s in steps]
    return build_verdict(b, classify_build(b, honoured=runs == ["echo from-sidecar"]),
                         f"artifact bundle steps {runs or 'none'}; replacement is "
                         f"['echo from-sidecar'], extension would be both")


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
        work = reaper.track(Path(tempfile.mkdtemp(prefix="bb-fixture-")))
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


def main() -> int:
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
    ap.add_argument("--timeout", type=int, default=180,
                    help="default wait per case, in seconds; a case may override it")
    ap.add_argument("--herd-n", type=int, default=16,
                    help="children per herd case; N is the whole point of that persona, "
                         "and 16 cold starts need ~N copies of the staged tree on disk "
                         "at once")
    ap.add_argument("--seed", type=int, default=0,
                    help="seed for cases that choose a moment or a victim at random; the "
                         "same seed and case reproduce the same sequence")
    ap.add_argument("--keep", action="store_true", help="keep each case's wreckage")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--triage", action="store_true",
                    help="group past findings by fingerprint and stop")
    ap.add_argument("--history", action="store_true",
                    help="list runs, marking any that were interrupted")
    a = ap.parse_args()

    # The line that makes --timeout honest: it was parsed and never read, while run_exe
    # hardcoded 120 and the flag advertised 180. A case that names its own wait still wins.
    global DEFAULT_TIMEOUT_S, HERD_N
    DEFAULT_TIMEOUT_S = a.timeout
    # A herd of one is twin with extra steps, and nothing below N=2 can race at all.
    HERD_N = max(2, a.herd_n)

    if a.history:
        return print_history()
    if a.triage:
        return print_triage()

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
    results, interrupted, rc = [], False, 0
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

        # Two kinds, counted differently. An exe-kind case runs once per fixture. A
        # build-kind case attacks the BUILD, whose answer does not vary by fixture, so it
        # runs once per RUN: looping it over --fixtures top25 would buy 25 identical
        # answers, which is what the 2026-09-10 sweep did to the launcher cases — 575 runs
        # for 23 distinct fingerprints.
        exe_cases = [c for c in picked if c["kind"] != "build"]
        build_cases = [c for c in picked if c["kind"] == "build"]
        total = len(fixtures) * len(exe_cases) + len(build_cases)
        jr.write("started", planned=[c["name"] for c in picked], tier=a.tier,
                 fixtures=[n for n, _ in fixtures], cases=len(picked), total=total,
                 seed=a.seed, timeout=a.timeout, build_cases=len(build_cases),
                 herd_n=HERD_N)
        jr.beat()
        print(f"\nbusybody: {len(exe_cases)} case(s) x {len(fixtures)} fixture(s)"
              + (f" + {len(build_cases)} build-time case(s)" if build_cases else "")
              + f" = {total} run(s)   run {run_id}\n")

        def run_one(c: dict, fname: str, target: Path) -> None:
            """One case: its own work dir, its own record, appended and flushed at once.

            `target` is the built binary for an exe-kind case and the haru-pack CLI for a
            build-kind one. The two call sites below choose it, on c["kind"].
            """
            work = reaper.track(Path(tempfile.mkdtemp(prefix=f"bb-{c['name']}-")))
            Ctx.enter(jr, a.seed, c["name"], fname)
            try:
                r = c["fn"](target, work)
            except Exception as e:
                r = {"outcome": "CASE-ERROR", "rc": None, "seconds": 0,
                     "stdout": "", "stderr": f"{type(e).__name__}: {e}"}
            finally:
                Ctx.clear()
            ok = r["outcome"] in c["expect"] and r["outcome"] not in FATAL
            msg = (r.get("stderr") or r.get("stdout") or "").strip()
            rec = {**{k: c[k] for k in ("name", "persona", "why", "inv", "remedy")},
                   **r, "ok": ok, "expect": list(c["expect"]), "fixture": fname,
                   "kind": c["kind"], "seed": a.seed,
                   # Normalised to a bool and always present: a key that exists only on
                   # cascades makes every reader of results.json test for its absence.
                   # A cascade is NOT marked ok — that would erase it from the findings
                   # section and from the exit code. De-emphasised at triage, not hidden.
                   "post_wedge": bool(r.get("post_wedge")),
                   "wedge_id": r.get("wedge_id", ""),
                   "severity": severity_for(c, r, ok),
                   # The seed is NOT in the fingerprint basis. normalize() collapses bare
                   # numbers to <n> anyway, so seeded variants of one fault must group
                   # together: the seed is a field you read, not an identity.
                   "fingerprint": fingerprint(c["persona"], c["name"], r["outcome"], msg)}

            if not ok:
                rec["artifacts"] = preserve(run_dir, f"{fname}--{c['name']}", work,
                                            light=c["light"])
            if a.keep:
                reaper.hold(work)
                rec.setdefault("artifacts", str(work))

            results.append(rec)
            # `kind` is renamed on the way into the journal. Journal.write(kind, **fields)
            # names its first parameter `kind`, and the journal's own kind field is the
            # RECORD type ("case", "perturb") — a different thing from exe-vs-build.
            # Passing the case's kind straight through is a TypeError, not an overwrite.
            jr.write("case", case_kind=rec["kind"],
                     **{k: v for k, v in rec.items() if k not in ("why", "kind")})
            jr.beat()
            prefix = f"  {'ok ' if ok else 'BAD'} "
            label = f"{c['persona']:14} {c['name']:42}"
            print(f"{prefix}{label} {r['outcome']:9}{'  ' if ok else '<-'}")

        for fname, exe in fixtures:
            if len(fixtures) > 1:
                print(f"-- {fname} ({exe.stat().st_size / 1e6:.0f}MB)")
            for c in exe_cases:
                run_one(c, fname, exe)

        if build_cases:
            # Resolved exactly as build_fixture resolves it.
            haru = Path(shutil.which("haru-pack") or REPO / ".venv" / "bin" / "haru-pack")
            print("-- build-time cases, once each (not once per fixture)")
            for c in build_cases:
                run_one(c, "none (build-time case)", haru)

    except KeyboardInterrupt:
        interrupted = True
        jr.write("interrupted", completed=len(results),
                 planned=len(picked) * max(1, len(locals().get("fixtures", [1]))))
        print("\n^C — interrupted. Everything completed so far is in the journal.",
              file=sys.stderr)
    finally:
        bad = [r for r in results if not r["ok"]]
        if bad:
            # A whitelist: a key not named here reaches results.json and the journal but
            # never the ledger, and so never --triage. post_wedge and wedge_id are in it
            # deliberately — cascades DO reach the ledger, because the shape of a cascade
            # is the primary evidence for the wedge that caused it. Suppressing them is
            # triage's job, not append's.
            ledger_append([{k: v for k, v in r.items()
                            if k in ("name", "persona", "outcome", "severity",
                                     "fingerprint", "inv", "remedy", "artifacts",
                                     "fixture", "kind", "seed", "post_wedge",
                                     "wedge_id")}
                           | {"run": run_id, "at": time.time(),
                              "message": (r.get("stderr") or r.get("stdout") or "")[:500]}
                           for r in bad])
        if results:
            (run_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
            write_report(results, ", ".join(sorted({r["fixture"] for r in results})),
                         run_dir / "report.txt", run_id=run_id, interrupted=interrupted)
        if not interrupted and results:
            jr.write("finished", cases=len(results), findings=len(bad))
        jr.close()

        # Unconditional. This is the line the whole finally block exists for.
        print()
        reaper.reap()
        prune_runs(RUNS, keep=a.keep_runs, log=lambda m: print(f"  {m}"))

    bad = [r for r in results if not r["ok"]]
    print(f"\n{len(results) - len(bad)}/{len(results)} behaved as expected"
          + ("  (RUN INTERRUPTED — this is not the whole suite)" if interrupted else ""))
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

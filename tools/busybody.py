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
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
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

# Outcomes that are never acceptable, in any case.
FATAL = ("CRASHED", "HUNG", "SILENT")

CASES = []


def case(persona: str, expect, why: str, inv: str = "", remedy: str = ""):
    """Register a chaos case.

    `expect`  outcomes that are acceptable.
    `why`     what this case simulates and why it matters. Printed in the report.
    `inv`     the INVARIANTS.md entry that governs it, if any.
    `remedy`  what to do when it fails. Written into the report so the reader does not
              have to work it out, or ask anyone.
    """
    def deco(fn):
        CASES.append({"name": fn.__name__, "persona": persona,
                      "expect": tuple(expect) if isinstance(expect, (list, tuple)) else (expect,),
                      "why": why, "inv": inv, "remedy": remedy, "fn": fn})
        return fn
    return deco


# ---------------------------------------------------------------- outcome classification

TRACEBACK_MARKERS = (
    "Traceback (most recent call last)",      # Python
    "Error: unhandled exception",             # Nim
    "[IndexDefect]", "[RangeDefect]", "[ValueError]", "[OSError]",
    "sysFatal", "signal SIGSEGV", "core dumped",
)


def classify(rc, out: str, err: str, timed_out: bool) -> str:
    blob = (out or "") + (err or "")
    if timed_out:
        return "HUNG"
    if any(m in blob for m in TRACEBACK_MARKERS):
        return "CRASHED"
    if rc == 0:
        return "RAN" if MARKER in out else "SILENT"
    return "REFUSED"


def run_exe(exe: Path, cwd: Path, env=None, timeout: int = 120, args=()) -> dict:
    t0 = time.monotonic()
    try:
        r = subprocess.run([str(exe), *args], capture_output=True, text=True,
                           timeout=timeout, cwd=cwd, env=env)
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
    if r["outcome"] in ("CRASHED", "SILENT", "HUNG"):
        return "critical"      # a traceback at the user, the wrong code running, or a wedge
    if r["outcome"] == "CASE-ERROR":
        return "note"          # busybody's own bug, not haru-pack's — say so, do not inflate
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
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--keep", action="store_true", help="keep each case's wreckage")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--triage", action="store_true",
                    help="group past findings by fingerprint and stop")
    ap.add_argument("--history", action="store_true",
                    help="list runs, marking any that were interrupted")
    a = ap.parse_args()

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

        total = len(fixtures) * len(picked)
        jr.write("started", planned=[c["name"] for c in picked], tier=a.tier,
                 fixtures=[n for n, _ in fixtures], cases=len(picked), total=total)
        jr.beat()
        print(f"\nbusybody: {len(picked)} case(s) x {len(fixtures)} fixture(s) "
              f"= {total} run(s)   run {run_id}\n")

        for fname, exe in fixtures:
            if len(fixtures) > 1:
                print(f"-- {fname} ({exe.stat().st_size / 1e6:.0f}MB)")
            for c in picked:
                work = reaper.track(Path(tempfile.mkdtemp(prefix=f"bb-{c['name']}-")))
                try:
                    r = c["fn"](exe, work)
                except Exception as e:
                    r = {"outcome": "CASE-ERROR", "rc": None, "seconds": 0,
                         "stdout": "", "stderr": f"{type(e).__name__}: {e}"}
                ok = r["outcome"] in c["expect"] and r["outcome"] not in FATAL
                msg = (r.get("stderr") or r.get("stdout") or "").strip()
                rec = {**{k: c[k] for k in ("name", "persona", "why", "inv", "remedy")},
                       **r, "ok": ok, "expect": list(c["expect"]), "fixture": fname,
                       "severity": severity_for(c, r, ok),
                       "fingerprint": fingerprint(c["persona"], c["name"], r["outcome"], msg)}

                if not ok:
                    rec["artifacts"] = preserve(run_dir, f"{fname}--{c['name']}", work)
                    reaper.hold(work) if a.keep else None
                if a.keep:
                    reaper.hold(work)
                    rec.setdefault("artifacts", str(work))

                results.append(rec)
                jr.write("case", **{k: v for k, v in rec.items() if k != "why"})
                jr.beat()
                prefix = f"  {'ok ' if ok else 'BAD'} "
                label = f"{c['persona']:14} {c['name']:42}"
                print(f"{prefix}{label} {r['outcome']:9}{'  ' if ok else '<-'}")

    except KeyboardInterrupt:
        interrupted = True
        jr.write("interrupted", completed=len(results),
                 planned=len(picked) * max(1, len(locals().get("fixtures", [1]))))
        print("\n^C — interrupted. Everything completed so far is in the journal.",
              file=sys.stderr)
    finally:
        bad = [r for r in results if not r["ok"]]
        if bad:
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

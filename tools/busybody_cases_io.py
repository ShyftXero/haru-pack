"""Cases about the SHAPE of the app's I/O, its signals, and what it is starved of.

    mute       stdin/stdout — closed, a pipe, a pty
    impatient  SIGINT and SIGTERM mid-run
    hoarder    few descriptors, a tight address space, a read-only /tmp

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from busybody_runner import TRACEBACK_MARKERS  # noqa: E402
from busybody_herd import _worse  # noqa: E402

import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "src") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "src"))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from haru_pack import overlay  # noqa: E402,F401

import busybody_config as cfg  # noqa: E402
from busybody_config import (ADDRESS_SPACE_MB, FATAL, MARKER, case)  # noqa: E402,F401
from busybody_runner import (Ctx, InfraFailure, blame, classify, clean_env,  # noqa: E402,F401
                             dir_bytes, infra_failure_reason, run_exe, stage_root,
                             warm, work_root_report)
import fcntl  # noqa: E402,F401
import pty  # noqa: E402
import resource  # noqa: E402
import select  # noqa: E402
import termios  # noqa: E402,F401

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
    finally:
        # stderr is read but never closed otherwise, on either path. One leaked pipe per
        # run is harmless; under --jobs the GC notices it inside a worker and reports it
        # against whichever case that worker was running, which is a ResourceWarning
        # pointing at innocent code.
        if p1.stderr is not None:
            p1.stderr.close()
    # No marker is reachable — stdout is gone — so judge on rc and stderr alone.
    outcome = ("HUNG" if to else
               classify(rc, "", err, False) if any(m in err for m in TRACEBACK_MARKERS)
               else "RAN" if rc == 0 else "REFUSED")
    return {"outcome": outcome, "rc": rc, "seconds": round(time.monotonic() - t0, 1),
            "blame": blame("", err), "stdout": "(closed by the test)",
            "stderr": (err or "").strip()[-400:]}


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
             "fixture-divergence is visible without failing the case on a terminal width.")
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
        pipe_out, pipe_err = p.communicate(timeout=cfg.DEFAULT_TIMEOUT_S)
        pipe_rc, pipe_to = p.returncode, False
    except subprocess.TimeoutExpired:
        p.kill()
        pipe_out, pipe_err = p.communicate()
        pipe_rc, pipe_to = None, True
    tty_rc, tty_raw, tty_to = _run_on_a_pty(exe, work, env, cfg.DEFAULT_TIMEOUT_S)
    # Stripped BEFORE classifying, and on BOTH sides: a marker wearing a colour code
    # would otherwise read as SILENT and this case would report ANSI as a launcher
    # defect. Comparing a stripped tty against an unstripped pipe would also call every
    # run a fixture-divergence, which is the same mistake one step later.
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
      "(slow import) REFUSED, iniconfig (finishes first) RAN. That fixture-divergence is a fact "
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
    return run_exe(exe, work, env=clean_env(work / "c"),
                   rlimits={resource.RLIMIT_NOFILE: (64, 64)})


#: Calibrated, not guessed. A resource ceiling only discriminates between packages if it
#: sits BETWEEN their requirements. Measured 2026-09-10 on this box, after a warm stage:
#:   iniconfig  ok at 512 MB
#:   numpy      FAILS at 512 and 768 MB, ok at 1024 MB
#: 768 MB therefore separates them. The first version used 256 MB, which was below BOTH —
#: every package failed identically and the case discriminated nothing. If this stops
#: diverging, re-run tools/busybody.py --calibrate rather than nudging the number.


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



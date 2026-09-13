"""The stall watchdog: several processes alive, and none of them making progress.

Only an observer OUTSIDE every one of them can say this, which is why STALLED is not a
value `classify()` can return. The three signals are alive + CPU stable + no I/O, and they
must ALL hold continuously for `cfg.STALL_QUIET_S`.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import hashlib  # noqa: E402
from busybody_runner import Ctx  # noqa: E402

import os
import threading
import time
from pathlib import Path

import busybody_config as cfg



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
    """Says STALLED when nothing is progressing. A THREAD in the harness process.

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
    neither can declare a stall alone: sixteen processes burning CPU are never quiet,
    whatever the walk says.
    """

    def __init__(self, base: Path, procs, quiet_s: float | None = None,
                 tick_s: float = 1.0):
        self.base = Path(base)
        self.quiet_s = cfg.STALL_QUIET_S if quiet_s is None else quiet_s
        self.tick_s = tick_s
        self.stalled_at = None      # time.monotonic() of the declaration; None until then
        self.stall_id = ""
        self.stall_blame = ""
        self.evidence = ""
        self.quiet_max = 0.0       # longest quiet stretch seen, stall or not: THE number
        self.ticks = 0             # cfg.STALL_QUIET_S has to be calibrated against
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
                if held >= self.quiet_s and self.stalled_at is None:
                    self._declare(now, held, nbytes, len(alive))
            else:
                quiet_since = None
            prev_cpu, prev_bytes = cpu, nbytes
            self._stop.wait(self.tick_s)

    def _declare(self, now: float, held: float, nbytes: int, alive: int) -> None:
        self.stalled_at = now
        # Shared by every sub-result that resolves after this instant, so a reader can
        # tie sixteen cascades back to the one stall that caused them.
        self.stall_id = hashlib.sha256(
            f"{self.base}|{Ctx.case}|{Ctx.fixture}|{now}".encode()).hexdigest()[:12]
        self.stall_blame, self.evidence = self._attribute(held, nbytes, alive)
        # NOT Ctx.perturb: perturb records a fault the harness INJECTED, and a stall is
        # something it merely watched happen. Ctx.observe writes to the same fsynced file
        # so the record survives this process being killed, and the parent journals it
        # under its own record type.
        Ctx.observe("stall", stall_id=self.stall_id, quiet_s=round(held, 1),
                    staged_bytes=nbytes, alive=alive, blame=self.stall_blame,
                    evidence=self.evidence)

    def _attribute(self, held: float, nbytes: int, alive: int) -> tuple:
        """"launcher" only on launcher-side evidence. Otherwise "unknown".

        The one thing that counts as evidence: a staging directory whose byte count is
        static and whose OWNER IS DEAD. stage.nim names it <key>.tmp-<pid>, so an orphan
        names its own author, and "the survivors are waiting on a tree nobody is
        building" is then a claim about launcher-side state rather than about the box.
        Static comes for free from the stall condition — the orphan sits inside the byte
        total that did not grow for the whole quiet stretch — so only the death of its
        owner has to be checked here.

        Everything else is "unknown", including — checked first, before anything else —
        this sampler not being scheduled. A watchdog that reports its own starvation on a
        loaded machine as a product stall is tight_address_space again: it fires, it
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


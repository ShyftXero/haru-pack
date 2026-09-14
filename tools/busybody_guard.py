"""INV-CHAOS-13 — one sweep at a time, and a dead sweep's marker gets reaped.

Two concurrent sweeps share a scratch root, a findings ledger and a stage-key namespace,
so the second one measures the first. Refusing is cheap; a run that silently interleaves
produces findings nobody can reproduce.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import sys  # noqa: E402

import json
import os
import time
from pathlib import Path

import busybody_config as cfg



def _bb_live(entry: dict) -> bool:
    """True only if the entry names a process still genuinely working: its pid is alive AND its
    heartbeat (or, before its first beat, its birth time) is fresh. A recycled pid with a stale
    or absent heartbeat is NOT live — so a dead run's marker never blocks a new one."""
    pid = entry.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)                  # signal 0: exists + signalable; ProcessLookupError if gone
    except ProcessLookupError:
        return False
    except PermissionError:
        pass                             # alive but owned by another user — still alive
    beat = None
    hb = entry.get("heartbeat")
    if hb:
        try:
            beat = float(Path(hb).read_text().strip())
        except (OSError, ValueError):
            beat = None
    if beat is None:                     # not yet beating -> fall back to birth so a just-started
        beat = entry.get("born")         # run is not mistaken for a corpse
    if not isinstance(beat, (int, float)):
        return False
    return (time.time() - beat) < cfg.BB_STALE_S


def guard_single_instance(run_id: str, heartbeat: Path, log=print) -> Path:
    """Refuse to start while another sweep is LIVE (exit 3); reap a DEAD one's registry and carry
    on. Returns this run's registry-file path — remove it on exit. `HARUPACK_BUSYBODY_FORCE=1`
    overrides the refusal (a logged, deliberate override beats a guard someone deletes)."""
    cfg.BB_REGISTRY.mkdir(parents=True, exist_ok=True)
    forced = os.environ.get(cfg.BB_FORCE_ENV) == "1"
    for f in sorted(cfg.BB_REGISTRY.glob("*.json")):
        try:
            entry = json.loads(f.read_text())
        except (OSError, ValueError):
            f.unlink(missing_ok=True)    # unreadable marker is junk, not a live run
            continue
        if entry.get("pid") == os.getpid():
            continue                     # never match our own pid
        if _bb_live(entry):
            if forced:
                log(f"another busybody sweep is live (pid {entry.get('pid')}, run "
                    f"{entry.get('run_id')}); {cfg.BB_FORCE_ENV}=1 set — starting anyway")
                continue
            print(f"busybody: another sweep is already running (pid {entry.get('pid')}, run "
                  f"{entry.get('run_id')}).\nTwo sweeps each stage a real interpreter and thrash "
                  f"this box into the OOM killer.\nWait for it to finish, or set "
                  f"{cfg.BB_FORCE_ENV}=1 to run anyway.", file=sys.stderr)
            raise SystemExit(3)
        log(f"reaping a stale busybody registry: {f.name} (pid {entry.get('pid')} dead or "
            f"idle > {int(cfg.BB_STALE_S)}s)")
        f.unlink(missing_ok=True)
    mine = cfg.BB_REGISTRY / f"{run_id}.json"
    mine.write_text(json.dumps({"pid": os.getpid(), "run_id": run_id,
                                "heartbeat": str(heartbeat), "born": time.time()}))
    return mine


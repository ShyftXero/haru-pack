"""The herd: N processes racing one stage key, reduced to ONE record.

THREE CASES, not 3*N. `--triage` ranks fingerprint groups by count, so sixteen children
failing on one stall would outrank a genuine unique finding sixteen to one. Each case here
reduces over its own children and returns exactly one record; which children cascaded is
evidence inside that record, not sixteen more records.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import hashlib
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
from busybody_config import (FATAL, MARKER, case)  # noqa: E402,F401
from busybody_runner import (Ctx, InfraFailure, blame, classify, clean_env,  # noqa: E402,F401
                             dir_bytes, infra_failure_reason, run_exe, stage_root,
                             warm, work_root_report)
from busybody_stall import StallWatch  # noqa: E402


def herd_deadline() -> int:
    """One deadline for the whole herd, not one per child.

    N sequential waits of cfg.DEFAULT_TIMEOUT_S would let a single 16-way case run for 48
    minutes. Sixteen cold starts do genuinely take longer than one — they serialise on
    the disk — so this scales with N and never drops below the default wait.
    """
    return max(cfg.DEFAULT_TIMEOUT_S, 20 * cfg.HERD_N)


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
    three of its stall conditions (alive, no CPU, no new bytes) and busybody would report
    its own collection strategy as a haru-pack stall. A file cannot fill.

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

    Records WHEN each child resolved, which is the whole post_stall contract: once the
    watchdog has declared a stall at T, a child that resolves after T did so in a system
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
        # `unresolved=timed_out`: this deadline is SHARED by all N children, so a child
        # still working when it passed may have been seconds from done. HUNG would be a
        # claim we cannot support here — the observer that CAN say the system stopped
        # progressing is the watchdog, and it makes that claim separately as STALLED.
        outcome = classify(p.returncode, blob, "", timed_out, unresolved=timed_out)
        cascade = watch.stalled_at is not None and done[i] >= watch.stalled_at
        subs.append({"i": i, "rc": p.returncode, "outcome": outcome,
                     "blame": blame(blob, "") if outcome != "RAN" else "none",
                     "post_stall": cascade,
                     "stall_id": watch.stall_id if cascade else "",
                     "at": done[i], "tail": blob.strip()[-200:]})
    return subs


# Worst-of, the reduction twin uses, with the order spelled out because a herd has more
# outcomes to rank than twin did. STALLED dominates: it is a statement about the whole
# system, and every child outcome recorded after it is downstream of it.
_HERD_ORDER = ("RAN", "REFUSED", "APP-CRASHED", "CRASHED", "SILENT", "HUNG", "STALLED")


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
    # An INDETERMINATE child contributes no verdict, so it cannot be the worst of anything.
    # But a herd where NOTHING resolved has not shown that the system is fine — it has shown
    # that we stopped watching — so the reduction of an all-indeterminate herd is
    # INDETERMINATE and not RAN.
    settled = [s for s in judged if s["outcome"] != "INDETERMINATE"]
    unresolved = [s for s in judged if s["outcome"] == "INDETERMINATE"]
    worst = "RAN"
    for s in settled:
        worst = _worse(worst, s["outcome"])
    if judged and not settled:
        worst = "INDETERMINATE"
    if watch.stalled_at is not None:
        worst = "STALLED"
    tally = {}
    for s in judged:
        tally[s["outcome"]] = tally.get(s["outcome"], 0) + 1
    detail = [f"{len(judged)} judged: "
              + ", ".join(f"{k}x{v}" for k, v in sorted(tally.items()))]
    if killed:
        detail.append("killed by this case: "
                      + ", ".join(f"#{s['i']} {s['outcome']}" for s in subs
                                  if s["i"] in killed))
    if unresolved:
        detail.append(f"{len(unresolved)} child(ren) had not resolved when the shared "
                      f"deadline passed and were killed: INDETERMINATE, counted as neither "
                      f"a pass nor a finding")
    detail.append(f"longest quiet stretch {watch.quiet_max:.0f}s of the "
                  f"{watch.quiet_s:.0f}s a stall needs, over {watch.ticks} tick(s)")
    if watch.stalled_at is not None:
        detail.append(f"STALL {watch.stall_id} blamed on {watch.stall_blame}: "
                      f"{watch.evidence}")
    cascades = [s for s in judged if s["post_stall"]]
    if cascades:
        detail.append(f"{len(cascades)} child(ren) resolved after the stall and are "
                      f"cascades of it, not separate faults")
    bad = next((s for s in settled if s["outcome"] != "RAN"), None)
    return {"outcome": worst,
            "indeterminate": worst == "INDETERMINATE",
            "rc": bad["rc"] if bad else (settled[0]["rc"] if settled else None),
            "seconds": round(time.monotonic() - t0, 1),
            "blame": watch.stall_blame if worst == "STALLED"
                     else (bad["blame"] if bad else "none"),
            # post_stall marks a record as a CONSEQUENCE of a stall, which sinks it below
            # the fresh findings at --triage. A declared stall makes STALLED the verdict
            # here and that record IS the fresh finding, so this is False by construction
            # today. The per-child flags above are where the cascade evidence lives; this
            # field keeps the distinction if a later case ever tolerates a stall in its
            # expect set.
            "post_stall": watch.stalled_at is not None and worst != "STALLED",
            "stall_id": watch.stall_id,
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
      remedy="RAN from all sixteen is the pass. STALLED is the serious one, and the record "
             "carries what the watchdog saw, including whether an orphaned .tmp- "
             "directory made it a launcher-side claim. Note what INV-STAGE-01 does and "
             "does not cover: its Statement governs what a stage must satisfy before it "
             "is executed, which is exactly what the survivors' verdict asserts here, "
             "but NO current invariant Statement mentions concurrency or atomicity — "
             "that claim lives only in twin's remedy prose. If this stalls, the thing to "
             "write is the missing invariant about N stagers on one key, not a footnote "
             "under INV-STAGE-01.",
      light=True)
def sixteen_cold_starts_at_once(exe: Path, work: Path) -> dict:
    t0 = time.monotonic()
    cache = work / "herdcache"
    kids = herd_start(exe, work, cache, cfg.HERD_N)
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
      "here so a stall found once can be landed again deliberately.",
      inv="INV-STAGE-01",
      remedy="The survivors must each end up with a complete, verified stage: RAN is the "
             "pass, and the victim's own outcome is excluded from the verdict because "
             "this case killed it. A REFUSED survivor means a dead stager's leftovers "
             "became reachable by another process, which is INV-STAGE-01's territory — a "
             "tree that cannot be accounted for is discarded and rebuilt, never "
             "inherited. STALLED means the survivors waited on the dead child; reproduce "
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
    kids = herd_start(exe, work, cache, cfg.HERD_N)
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
             "Statement today. STALLED means something waits on a dead owner and must "
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
    kids = herd_start(exe, work, cache, cfg.HERD_N)
    watch = StallWatch(base, [p for p, _, _ in kids]).start()
    try:
        subs = herd_collect(kids, watch)
    finally:
        watch.stop()
    r = herd_verdict(subs, watch, t0)
    r["stdout"] = f"orphan {tmp.name} (owner pid {corpse.pid} dead) | " + r["stdout"]
    return r



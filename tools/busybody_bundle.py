"""A forensic bundle: the state that EXPLAINS a finding, not only the record of it.

Adopted from lotek's `tests/busybody/bundle.py` (T-016). Its collectors are py-spy stacks,
`pg_stat_activity` and screenshots, because its target is a live stateful web application.
haru-pack's target is a process tree that stages an interpreter and execs it, so the
analogues are the process tree, the open file descriptors, the staged directory and what the
scratch filesystem was doing.

## Why this is not the same as preserving artifacts

`busybody_report.preserve()` already copies a failing case's work directory somewhere it will
still exist tomorrow. That is the RECORD: what the case produced. It answers "what came out".

It cannot answer "what was going on". By the time a case returns, the processes are gone, the
file descriptors are closed, and the thing you want to know — which of the sixteen children
was holding the stage, what the launcher had open when it stopped, how much room was actually
left — is unrecoverable. A HUNG or STALLED finding is exactly the case where the record is
least useful and the live state is most.

So a bundle is collected at the moment of the finding, from the living system, and the record
is collected afterwards from what it left behind. Both, or neither is enough.

## The rules every collector here follows

**Never raise.** A collector runs while something has already gone wrong. One that throws
turns a finding into a CASE-ERROR and loses the finding as well as the evidence. Every one of
these returns a string, and the string may say it failed.

**Never block.** Each is bounded by a short timeout, and the total is bounded too. A forensic
collector that hangs while investigating a hang is a comedy this repo cannot afford — the
harness already has a watchdog watching for exactly the condition the collector would be
adding to.

**Never touch the subject.** Read `/proc`, run `ps`, stat the filesystem. No signals, no
`lsof` on a path that might block on a dead NFS mount, nothing that changes what is being
measured. A finding investigated by perturbing it further is not the finding you had.

**Degrade, loudly.** On a box without `ps`, the process-tree section says so rather than
being absent. An empty section and a missing section look identical, and only one of them
means "there was nothing to see".
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

__all__ = ["collect", "write_bundle", "BUNDLE_NAME"]

BUNDLE_NAME = "forensics.json"

# Every collector gets this long, and the whole bundle gets the sum. Short on purpose: this
# runs on the failure path, and evidence that arrives after the operator has given up reading
# is evidence nobody has.
_PER_COLLECTOR_S = 5.0


def _run(argv: list, timeout: float = _PER_COLLECTOR_S) -> str:
    """A command's output, or a string explaining why there isn't any. Never raises."""
    if not shutil.which(argv[0]):
        return f"(not collected: {argv[0]} is not on PATH)"
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        return out.strip()[:20000] or "(no output)"
    except subprocess.TimeoutExpired:
        return f"(not collected: {argv[0]} did not return within {timeout}s)"
    except (OSError, subprocess.SubprocessError) as e:
        return f"(not collected: {type(e).__name__}: {e})"


def process_tree(root_pid: int | None = None) -> str:
    """Who was alive, what they were doing, and who started them.

    The single most useful thing to have when a case reports HUNG or STALLED, and the single
    thing that is gone by the time anyone looks. `ps` rather than /proc-walking because the
    STAT column — D for uninterruptible sleep, Z for a zombie, the `+` for foreground — is
    the answer to "stuck on what?" and reproducing that formatting by hand is how a collector
    acquires its own bugs.
    """
    pid = root_pid or os.getpid()
    return _run(["ps", "-o", "pid,ppid,stat,etimes,rss,pcpu,args", "--forest",
                 "-g", str(os.getpgid(pid))])


def open_files(pid: int | None = None) -> str:
    """What this process had open. Read from /proc, never with lsof.

    `lsof` without arguments walks every mount, and on a box with a dead NFS mount it blocks
    — which is the one thing a collector on the failure path must not do. /proc/<pid>/fd is a
    directory of symlinks and reading it cannot block on anything but the kernel.
    """
    pid = pid or os.getpid()
    fd_dir = Path(f"/proc/{pid}/fd")
    if not fd_dir.is_dir():
        return "(not collected: no /proc/<pid>/fd on this platform)"
    rows = []
    try:
        for fd in sorted(fd_dir.iterdir(), key=lambda p: int(p.name) if p.name.isdigit()
                         else 1 << 30):
            try:
                rows.append(f"{fd.name} -> {os.readlink(fd)}")
            except OSError as e:
                rows.append(f"{fd.name} -> (unreadable: {type(e).__name__})")
    except OSError as e:
        return f"(not collected: {type(e).__name__}: {e})"
    return "\n".join(rows[:500]) or "(none open)"


def staged_tree(cache: Path | None) -> str:
    """What the launcher had actually staged, and how far it had got.

    A listing rather than a copy. The point is the SHAPE — is there a half-extracted
    `.tmp-<pid>` directory beside a committed one, did the atomic rename happen, is the
    `.ready` token there — and a directory listing answers that in 200 bytes where a copytree
    answers it in 145 MB of an interpreter nobody will read.
    """
    if cache is None:
        return "(not collected: the case did not name a cache directory)"
    base = Path(cache) / "haru-pack"
    if not base.is_dir():
        return f"(nothing staged under {base})"
    rows = []
    try:
        for child in sorted(base.iterdir()):
            try:
                st = child.stat()
                kind = "dir " if child.is_dir() else "file"
                n = len(list(child.iterdir())) if child.is_dir() else ""
                rows.append(f"{kind} {child.name}  {st.st_size}B  mode={oct(st.st_mode)[-4:]}"
                            + (f"  {n} entries" if n != "" else ""))
            except OSError as e:
                rows.append(f"?    {child.name}  (unreadable: {type(e).__name__})")
    except OSError as e:
        return f"(not collected: {type(e).__name__}: {e})"
    tmp = [r for r in rows if ".tmp-" in r]
    if tmp:
        rows.append("")
        rows.append(f"NOTE: {len(tmp)} half-staged .tmp- director(ies) present. A stage that "
                    f"died between extract and the atomic rename leaves exactly this.")
    return "\n".join(rows)


def scratch(root: Path | None) -> str:
    """How much room there actually was — including the ceiling `df` cannot see.

    A user quota is invisible to `statvfs`, so a box can report 31 GB free and refuse the
    next write at 24 GB. This harness has already lost one 925-case sweep to exactly that and
    then reported the quota failure as 470 chaos findings, so the quota line is the point of
    this collector and the free-space line is context.
    """
    root = Path(root or "/tmp")
    lines = []
    try:
        st = os.statvfs(root)
        lines.append(f"{root}: {st.f_bavail * st.f_frsize / 1024**3:.2f} GiB free per "
                     f"statvfs ({st.f_favail} inodes)")
    except OSError as e:
        return f"(not collected: {type(e).__name__}: {e})"
    try:
        best, opts = "", ""
        for ln in Path("/proc/mounts").read_text().splitlines():
            parts = ln.split()
            if len(parts) >= 4 and str(root).startswith(parts[1]) and len(parts[1]) > len(best):
                best, opts = parts[1], parts[3]
        if best:
            lines.append(f"mount {best}  opts={opts}")
            if any(q in opts for q in ("usrquota", "grpquota", "prjquota", "quota")):
                lines.append("QUOTA PRESENT: the free-space figure above is NOT the ceiling. "
                             "A per-user quota is invisible to statvfs.")
    except OSError:
        lines.append("(/proc/mounts unreadable; no quota information)")
    return "\n".join(lines)


def loadavg() -> str:
    """Was the box itself the problem?

    A timing-sensitive case that reports the machine's load rather than the product is the
    documented failure mode of this harness at high `--jobs`. One line, so the question is
    answerable rather than arguable.
    """
    try:
        one, five, fifteen = os.getloadavg()
        return f"load {one:.2f} {five:.2f} {fifteen:.2f} over {os.cpu_count()} cpu(s)"
    except OSError as e:
        return f"(not collected: {type(e).__name__}: {e})"


def collect(*, work: Path | None = None, cache: Path | None = None,
            pid: int | None = None, reason: str = "") -> dict:
    """Everything, in one bounded pass. Never raises.

    Called at the MOMENT of a finding, from the living system. Ordered cheapest-first so a
    collector that does hit its timeout costs the ones after it as little as possible.
    """
    t0 = time.monotonic()
    bundle = {
        "collected_at": round(time.time(), 3),
        "reason": reason,
        "pid": pid or os.getpid(),
        "loadavg": loadavg(),
        "scratch": scratch(work),
        "open_files": open_files(pid),
        "staged_tree": staged_tree(cache),
        "process_tree": process_tree(pid),
    }
    bundle["collection_seconds"] = round(time.monotonic() - t0, 2)
    return bundle


def write_bundle(dest: Path, bundle: dict) -> str:
    """Write it beside the preserved artifacts. Returns the path, or "" if it could not.

    Failing to write the bundle must never fail the case: the finding is the valuable thing
    and the bundle is an aid to reading it.
    """
    try:
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        p = dest / BUNDLE_NAME
        p.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return str(p)
    except OSError:
        return ""

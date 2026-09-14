"""busybody's memory: run journals, interrupted-run detection, and finding rollup.

Adopted from lotek's `tests/busybody/journal.py` + `ledger.py`. The shapes and the names
are deliberately the same so the two projects read alike; the reasoning below is lotek's,
restated because it is the part that matters.

## Why a journal instead of writing results at the end

A run that is interrupted — Ctrl-C, a timeout, the machine going away — used to lose
everything, because results were only serialised after the last case. Every record is now
appended and flushed as it happens, so a `kill -9` costs at most the case in flight.

## Why a heartbeat

"Did this run finish?" cannot be answered by the presence of a results file, because a
killed run never writes one. A heartbeat rewritten during the run answers it directly: a
fresh heartbeat means live, a stale one means it died, and no `finished` record means it
never got to the end. An interrupted run then shows up AS interrupted rather than simply
being absent — which is the difference between "nothing to see" and "we don't know".

## Why the ledger lives outside the repository

lotek keeps its findings ledger at `~/Dropbox/code/lotek-busybody-findings.jsonl`,
deliberately untracked and outside the working tree, because a file inside the repo gets
caught by `git stash`, by worktree switches, and by branch changes — losing history exactly
when you are moving between branches to investigate something. haru-pack is developed in
git worktrees, so this applies with force.

## Why fingerprints — bucketing by signature

Three cases failing for one reason should read as one problem. **Bucketing by signature** is
the universal fuzzing term for this, and `fingerprint` is the field that carries it: the
volatile parts of a message — paths, timestamps, hex, ports, numbers — are replaced with
placeholders (**signature normalization**) and what is left is hashed, so repeats collapse
into a group with a count and a first-seen date. Without it every run looks like a fresh set
of unrelated failures.

The field name stays `fingerprint`, because it is written into every row on disk and into
lotek's; only the description adopts the standard vocabulary.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

__all__ = ["SEVERITIES", "SCHEMA_VERSION", "normalize", "fingerprint", "Journal",
           "ledger_path", "ledger_append", "ledger_rollup", "scan_runs", "heartbeat_state",
           "Reaper", "reap_orphans", "prune_runs", "human_bytes"]

# The on-disk contract's version, stamped into every record busybody writes.
# `docs/BUSYBODY-SCHEMA.md` IS the contract; this constant is the code agreeing with it.
#
# It lives here rather than in busybody_config because this module owns the record shapes —
# the journal, the ledger and the roll-up are all defined in this file — and because this is
# the module with no first-party imports at all, which is the property that makes it the
# cheapest thing in the harness to lift out. `busybody_runner` imports it for the perturb and
# observe records, which travel through the journal.
#
# It goes up when a field CHANGES MEANING or disappears, not when one is added: a reader that
# ignores unknown keys is unaffected by an addition, and bumping for those would train
# everyone to ignore the number. A record with no `schema_version` at all predates the
# document and is version 1 by definition, which is why nothing on disk needs migrating.
SCHEMA_VERSION = 1

# A closed vocabulary, as in lotek. Not "error", not "info" — three levels, chosen once.
#   critical  the product did something it must never do
#   warning   the product coped, but worse than it should have
#   note      recorded for context; not a defect on its own
SEVERITIES = ("critical", "warning", "note")

HEARTBEAT_STALE_S = 120          # older than this and the run is not live

# SIGNATURE NORMALIZATION: the volatile substrings replaced before hashing. Straight from
# lotek's ledger.py — without these, one root cause splits into as many groups as there are
# runs, because a path or a pid makes every occurrence look unique.
_VOLATILE = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b[0-9a-f]{16,}\b", re.I), "<hex>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*"), "<ts>"),
    (re.compile(r"0x[0-9a-f]+", re.I), "<addr>"),
    (re.compile(r"(/[^\s:,)\"']+)+"), "<path>"),
    (re.compile(r":\d{2,5}\b"), ":<port>"),
    (re.compile(r"\bbb[0-9a-f]{12,}\b"), "<runid>"),
    (re.compile(r"\b\d+(?:[a-z%]{1,3})?(?!\w)"), "<n>"),
]


def normalize(text: str) -> str:
    out = text or ""
    for pattern, repl in _VOLATILE:
        out = pattern.sub(repl, out)
    return " ".join(out.split())


def fingerprint(persona: str, case: str, outcome: str, message: str) -> str:
    """A stable 16-hex identity for one failure mode: the bucketing signature.

    "Bucketing by signature" is the standard fuzzing term for what this does — collapsing
    many crashes into the distinct faults behind them. The identifier stays `fingerprint`
    because it is a field name on every row ever written, here and in lotek.

    Keyed on the case as well as the message: the same underlying fault reached through a
    different persona is worth seeing separately, because the route matters when you are
    deciding what to fix.
    """
    basis = f"{persona}|{case}|{outcome}|{normalize(message)}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------- per-run journal

class Journal:
    """Append-only JSONL for one run, plus a heartbeat.

    Line-buffered and fsynced per record on purpose: a wedged or SIGKILLed process must
    leave a journal readable up to the last thing it did.
    """

    def __init__(self, run_dir: Path, run_id: str):
        self.run_dir = run_dir
        self.run_id = run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        self.path = run_dir / "journal.jsonl"
        self._fh = open(self.path, "a", encoding="utf-8", buffering=1)

    def write(self, kind: str, **fields) -> None:
        rec = {"schema_version": SCHEMA_VERSION, "run": self.run_id,
               "at": round(time.time(), 3), "kind": kind, **fields}
        self._fh.write(json.dumps(rec, sort_keys=True) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def beat(self) -> None:
        (self.run_dir / "heartbeat").write_text(str(time.time()))

    def close(self) -> None:
        try:
            self._fh.close()
        except OSError:
            pass

    def records(self) -> list:
        return read_jsonl(self.path)


def read_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            # A torn final line is exactly what kill -9 mid-write looks like. Keep the
            # rest; refusing to read the file would throw away the evidence.
            continue
    return rows


# ---------------------------------------------------------------- interrupted runs

def heartbeat_state(run_dir: Path) -> str:
    """'live' | 'stale' | 'absent' — is anything still running in this run directory?"""
    hb = run_dir / "heartbeat"
    if not hb.exists():
        return "absent"
    try:
        age = time.time() - float(hb.read_text().strip())
    except (ValueError, OSError):
        return "absent"
    return "live" if age < HEARTBEAT_STALE_S else "stale"


def scan_runs(out_dir: Path) -> list:
    """Every run directory, with whether it completed.

    A run is INTERRUPTED when it started, is not live, and never wrote a `finished`
    record. That is the state that used to be invisible.
    """
    runs = []
    if not out_dir.is_dir():
        return runs
    for d in sorted(out_dir.iterdir()):
        if not d.is_dir() or not (d / "journal.jsonl").exists():
            continue
        recs = read_jsonl(d / "journal.jsonl")
        cases = [r for r in recs if r.get("kind") == "case"]
        finished = any(r.get("kind") == "finished" for r in recs)
        hb = heartbeat_state(d)
        state = "complete" if finished else ("live" if hb == "live" else "INTERRUPTED")
        started = next((r for r in recs if r.get("kind") == "started"), {})
        runs.append({
            "run": d.name, "dir": d, "state": state,
            "cases": len(cases),
            # Counted the same way --triage groups them, or the two views disagree
            # sixteen-to-one about one stall and neither number can be trusted.
            "findings": len([r for r in cases
                             if not r.get("ok") and not r.get("post_stall")]),
            "cascades": len([r for r in cases
                             if not r.get("ok") and r.get("post_stall")]),
            "planned": started.get("planned"),
            "at": started.get("at"),
        })
    return runs


# ---------------------------------------------------------------- cross-run ledger

def ledger_path() -> Path:
    """Beside the MAIN checkout, outside every worktree, and overridable.

    Inside a repo the file is caught by `git stash`, by worktree switches and by branch
    changes — losing history exactly when you are hopping branches to investigate. lotek
    puts its ledger beside the checkout for this reason; so do we.

    "Beside the checkout" has to mean the main one. Resolving it relative to __file__ put
    the ledger in `.claude/worktrees/<name>-busybody-findings.jsonl` when run from a
    worktree — inside the very directory that gets deleted when the worktree is removed,
    which defeats the entire reason for keeping it out of the repo. Findings accumulated
    across a week of branches would vanish with the branch that happened to be last.

    `git rev-parse --git-common-dir` is the authoritative answer: it reports the MAIN
    repository's .git for a worktree and its own for a normal checkout, so one call covers
    both. The path fallback exists only for a source tree that is not a git checkout at all.
    """
    env = os.environ.get("HARUPACK_BUSYBODY_LEDGER")
    if env:
        return Path(env).expanduser()
    root = main_checkout(Path(__file__).resolve().parent.parent)
    return root.parent / f"{root.name}-busybody-findings.jsonl"


def main_checkout(start: Path) -> Path:
    """The main working tree for `start`, even when `start` is a linked worktree."""
    try:
        common = subprocess.run(
            ["git", "rev-parse", "--git-common-dir"], cwd=start,
            capture_output=True, text=True, timeout=15)
        if common.returncode == 0:
            d = Path(common.stdout.strip())
            if not d.is_absolute():
                d = (start / d).resolve()
            # <main>/.git -> <main>. A bare repo has no working tree to sit beside, so it
            # falls through to the path rule below.
            if d.name == ".git" and d.parent.is_dir():
                return d.parent
    except (OSError, subprocess.SubprocessError):
        pass
    # No git, or a bare repo: worktrees created by this project live in
    # <main>/.claude/worktrees/<name>, so the main checkout is the parent of `.claude`.
    # Scanned from the RIGHT, and matching the two components as a PAIR: a checkout can
    # itself live under some other `.claude` (a test tmpdir under ~/.claude, for one), and
    # taking the first match there resolves to the wrong tree entirely.
    parts = start.parts
    for i in range(len(parts) - 2, -1, -1):
        if parts[i] == ".claude" and parts[i + 1] == "worktrees":
            return Path(*parts[:i])
    return start


def ledger_append(records: list, path: Path | None = None) -> Path:
    p = path or ledger_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8", buffering=1) as fh:
        for rec in records:
            # Stamped HERE rather than at each call site that builds ledger rows, because
            # there are two of them (`_finalize` and `_finish_compose`) and a version that
            # only some rows carry is worse than none — a reader could not distinguish an
            # old row from a new one written by the path that forgot.
            fh.write(json.dumps({"schema_version": SCHEMA_VERSION, **rec},
                                sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return p


def ledger_rollup(path: Path | None = None) -> list:
    """One row per (fingerprint, cascade?): count, first_seen, last_seen, runs, cases.

    WHY THE CASCADE FLAG IS PART OF THE GROUPING KEY AND NOT OF THE FINGERPRINT

    This is cascade suppression, and its stated intent is FIRST-FAILURE ATTRIBUTION — the
    SRE term for reporting the fault that started it rather than the N faults it caused.

    When the herd persona declares a stall, every child that resolves afterwards fails too,
    and it fails for the stall rather than for itself. Sixteen of those share a persona, a
    case and an outcome, so they land in one group — and this function used to rank groups
    by count alone, which put that sixteen-count group above a genuine one-off finding.
    One bug, ranked sixteen times, at the top of --triage.

    So `post_stall` joins the grouping key (a fault seen both cleanly and as a cascade must
    not merge, or the group's remedy and sample come from whichever row was read first) and
    the ordering key sinks every cascade group below every fresh one, whatever the counts.

    It stays OUT of the fingerprint basis for two reasons. A cascade of a real fault would
    fingerprint differently from the same fault seen cleanly, so the history of that fault
    would split in two; and the basis is written into every row already on disk, so
    changing it would orphan every fingerprint ever recorded. Rows written before this
    field existed have no `post_stall` key at all — bool(None) is False, so they group and
    rank exactly as they did before.
    """
    rows = read_jsonl(path or ledger_path())
    groups: dict = {}
    for r in rows:
        fp = r.get("fingerprint")
        if not fp:
            continue
        cascade = bool(r.get("post_stall"))
        g = groups.setdefault((fp, cascade), {
            "schema_version": SCHEMA_VERSION,
            "fingerprint": fp, "count": 0, "runs": set(), "cases": set(),
            "personas": set(), "outcome": r.get("outcome"), "severity": r.get("severity"),
            "inv": r.get("inv", ""), "remedy": r.get("remedy", ""),
            "first_seen": r.get("at"), "last_seen": r.get("at"),
            "sample": r.get("message", ""), "post_stall": cascade,
        })
        g["count"] += 1
        g["runs"].add(r.get("run"))
        g["cases"].add(r.get("name"))
        g["personas"].add(r.get("persona"))
        # A row written by hand rather than through the driver's whitelist can have no
        # `at` at all, and min(None, None) raises instead of degrading. Skip the unknowns
        # rather than let one malformed row take out the whole roll-up.
        seen = [x for x in (g["first_seen"], g["last_seen"], r.get("at")) if x is not None]
        if seen:
            g["first_seen"] = min(seen)
            g["last_seen"] = max(seen)
    out = []
    for g in groups.values():
        g["runs"] = sorted(x for x in g["runs"] if x)
        g["cases"] = sorted(x for x in g["cases"] if x)
        g["personas"] = sorted(x for x in g["personas"] if x)
        out.append(g)
    # Cascades last, whatever their count: that ordering IS the claim. A stall that took
    # sixteen children with it must not outrank the fault that caused it.
    return sorted(out, key=lambda g: (bool(g.get("post_stall")), -g["count"],
                                      g["fingerprint"]))


# ---------------------------------------------------------------- reaping

WORK_PREFIX = "bb-"


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n / 1:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}GB"


def _tree_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file() and not p.is_symlink():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def free_dir(path: Path) -> int:
    """Remove one directory tree now and return the bytes it held. Never raises.

    The single implementation of "this scratch is finished with". Two callers need it and
    they cannot share a Reaper: the serial path has one, and a parallel worker runs in
    another process. Two copies of this would drift, and the drift would be a leak that only
    appears at one --jobs setting.
    """
    d = Path(path)
    try:
        if not d.exists():
            return 0
        size = _tree_size(d)
        shutil.rmtree(d, ignore_errors=True)
        return 0 if d.exists() else size
    except OSError:
        return 0


class Reaper:
    """Tracks every working directory a run creates and guarantees all of them are removed.

    Two mechanisms, and both are needed:

      * `release()` frees one directory the moment its case is done. This is what keeps a
        long sweep's live footprint at one case's worth.
      * `reap()` in a `finally` removes whatever is left, unconditionally. This is what
        survives a raise or a Ctrl-C.

    Having only the second is a leak with a delayed fuse, and it bit us. Each tracked
    directory holds a staged interpreter at the thick tier — around 145 MB — and a
    37-case x 25-fixture sweep tracks 925 of them. Holding them all until the end needs
    roughly 100 GB. The 2026-09-10 sweep died at case 168 on a 24 GiB user quota, which is
    168 x 145 MB almost exactly, and then reported the quota failure as 470 chaos findings.

    Having only the first is the older bug: a case that raised leaked its directory.

    `hold()` marks a directory to survive: findings whose artifacts are being preserved, or
    everything when --keep is passed. Those are reported rather than silently retained, so
    the disk they occupy is never a surprise.
    """

    def __init__(self, log=print):
        self._dirs: list = []
        self._held: set = set()
        self._log = log
        self.reaped = 0
        self.freed = 0

    def track(self, path: Path) -> Path:
        self._dirs.append(Path(path))
        return Path(path)

    def hold(self, path: Path) -> None:
        self._held.add(str(Path(path)))

    def release(self, path: Path) -> int:
        """Free one directory now, and stop tracking it. Returns bytes freed.

        Silent by design: a per-case line for 925 cases is noise, and the totals are
        reported once by `reap()`. Held directories are left alone.
        """
        d = Path(path)
        if str(d) in self._held:
            return 0
        size = free_dir(d)
        if size:
            self.reaped += 1
            self.freed += size
        self._dirs = [x for x in self._dirs if x != d]
        return size

    def reap(self) -> tuple:
        """Remove every tracked directory that is not held. Never raises."""
        held_bytes = 0
        for d in self._dirs:
            try:
                if not d.exists():
                    continue
                if str(d) in self._held:
                    held_bytes += _tree_size(d)
                    continue
                size = _tree_size(d)
                shutil.rmtree(d, ignore_errors=True)
                if not d.exists():
                    self.reaped += 1
                    self.freed += size
            except OSError:
                continue
        if self.reaped:
            self._log(f"reaped {self.reaped} work dir(s), {human_bytes(self.freed)} freed")
        if self._held:
            self._log(f"kept {len(self._held)} work dir(s) holding "
                      f"{human_bytes(held_bytes)} (findings or --keep)")
        return self.reaped, self.freed


def reap_orphans(runs_dir: Path, log=print) -> tuple:
    """Remove work directories abandoned by earlier runs.

    Guarded by the heartbeat rule, from lotek's cleanup.py: if ANY run has a fresh
    heartbeat something may still be using its temporary directories, so nothing is
    touched. A missing or unreadable heartbeat means not live, and both are safe to reap —
    a live run always has a fresh one.
    """
    if any(heartbeat_state(d) == "live"
           for d in (runs_dir.iterdir() if runs_dir.is_dir() else [])
           if d.is_dir()):
        log("a run is live (fresh heartbeat) — not reaping orphans")
        return 0, 0
    n = freed = 0
    for d in Path(tempfile.gettempdir()).glob(f"{WORK_PREFIX}*"):
        if not d.is_dir():
            continue
        try:
            size = _tree_size(d)
            shutil.rmtree(d, ignore_errors=True)
            if not d.exists():
                n += 1
                freed += size
        except OSError:
            continue
    if n:
        log(f"reaped {n} orphaned work dir(s) from earlier runs, {human_bytes(freed)} freed")
    return n, freed


def prune_runs(runs_dir: Path, keep: int = 10, log=print) -> tuple:
    """Keep the most recent N run directories; drop the rest.

    Run directories hold preserved artifacts, which is the point, but they are also the
    thing that grows without bound. Never prunes a live run.
    """
    if not runs_dir.is_dir():
        return 0, 0
    dirs = sorted((d for d in runs_dir.iterdir() if d.is_dir()), key=lambda d: d.name)
    victims = [d for d in dirs[:-keep] if heartbeat_state(d) != "live"] if len(dirs) > keep else []
    n = freed = 0
    for d in victims:
        size = _tree_size(d)
        shutil.rmtree(d, ignore_errors=True)
        if not d.exists():
            n += 1
            freed += size
    if n:
        log(f"pruned {n} old run dir(s), {human_bytes(freed)} freed "
            f"(keeping the most recent {keep})")
    return n, freed

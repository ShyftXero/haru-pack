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

## Why fingerprints

Three cases failing for one reason should read as one problem. A fingerprint normalises the
volatile parts of a message — paths, timestamps, hex, ports, numbers — and hashes what is
left, so repeats collapse into a group with a count and a first-seen date. Without it every
run looks like a fresh set of unrelated failures.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

__all__ = ["SEVERITIES", "normalize", "fingerprint", "Journal", "ledger_path",
           "ledger_append", "ledger_rollup", "scan_runs", "heartbeat_state"]

# A closed vocabulary, as in lotek. Not "error", not "info" — three levels, chosen once.
#   critical  the product did something it must never do
#   warning   the product coped, but worse than it should have
#   note      recorded for context; not a defect on its own
SEVERITIES = ("critical", "warning", "note")

HEARTBEAT_STALE_S = 120          # older than this and the run is not live

# Volatile substrings, stripped before fingerprinting. Straight from lotek's ledger.py:
# without these, one root cause splits into as many groups as there are runs.
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
    """A stable 16-hex identity for one failure mode.

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
        rec = {"run": self.run_id, "at": round(time.time(), 3), "kind": kind, **fields}
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
            "findings": len([r for r in cases if not r.get("ok")]),
            "planned": started.get("planned"),
            "at": started.get("at"),
        })
    return runs


# ---------------------------------------------------------------- cross-run ledger

def ledger_path() -> Path:
    """Outside the repository, and overridable.

    Inside a repo the file is caught by `git stash`, by worktree switches and by branch
    changes — losing history exactly when you are hopping branches to investigate. lotek
    puts its ledger beside the checkout for this reason; so do we.
    """
    env = os.environ.get("HARUPACK_BUSYBODY_LEDGER")
    if env:
        return Path(env).expanduser()
    repo = Path(__file__).resolve().parent.parent
    return repo.parent / f"{repo.name}-busybody-findings.jsonl"


def ledger_append(records: list, path: Path | None = None) -> Path:
    p = path or ledger_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8", buffering=1) as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return p


def ledger_rollup(path: Path | None = None) -> list:
    """One row per fingerprint: count, first_seen, last_seen, which runs, which cases."""
    rows = read_jsonl(path or ledger_path())
    groups: dict = {}
    for r in rows:
        fp = r.get("fingerprint")
        if not fp:
            continue
        g = groups.setdefault(fp, {
            "fingerprint": fp, "count": 0, "runs": set(), "cases": set(),
            "personas": set(), "outcome": r.get("outcome"), "severity": r.get("severity"),
            "inv": r.get("inv", ""), "remedy": r.get("remedy", ""),
            "first_seen": r.get("at"), "last_seen": r.get("at"),
            "sample": r.get("message", ""),
        })
        g["count"] += 1
        g["runs"].add(r.get("run"))
        g["cases"].add(r.get("name"))
        g["personas"].add(r.get("persona"))
        g["first_seen"] = min(g["first_seen"] or r.get("at"), r.get("at"))
        g["last_seen"] = max(g["last_seen"] or r.get("at"), r.get("at"))
    out = []
    for g in groups.values():
        g["runs"] = sorted(x for x in g["runs"] if x)
        g["cases"] = sorted(x for x in g["cases"] if x)
        g["personas"] = sorted(x for x in g["personas"] if x)
        out.append(g)
    return sorted(out, key=lambda g: (-g["count"], g["fingerprint"]))

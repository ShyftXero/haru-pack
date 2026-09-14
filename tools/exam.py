#!/usr/bin/env python3
"""exam — the flex PROOF: every top-N package sits its OWN test suite, inside a thick binary,
offline, and the result is written to a git-tracked page.

    python tools/exam.py refresh            # pull rank/version/repo-url for the top-N (network)
    python tools/exam.py run                # sit the exam for every top-N package, update the ledger
    python tools/exam.py run --only six,idna
    python tools/exam.py emit               # render top_n_pypi_stats.md from the ledger (offline)

Why a package's OWN suite and not a hand-written smoke: `import numpy` succeeds long before
numpy is usable, and a bespoke one-liner per package is exactly the maintenance burden this
avoids. A package's tests are the closest thing to "use it for real", and they already exist.
The catch, and the reason this needs the SDIST: tests almost never ship in the wheel — they
ride in the source distribution (checked across the top-25: only numpy and certifi ship a
runnable suite in the wheel). So the tool fetches the sdist, finds the test tree wherever it
lives, ships it into a thick app whose entrypoint runs pytest over it, and runs that binary
with the network denied. A pass means the payload carried a WORKING library.

The page is generated, never hand-edited, and never written by an AI: `emit` is pure
formatting over `flex/exam-results.json`, which is itself produced by real build+run results.
`emit` touches no network, so the committed page reproduces byte-for-byte from the ledger.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

PACKAGES = REPO / "flex" / "packages.toml"
LEDGER = REPO / "flex" / "exam-results.json"
PAGE = REPO / "top_n_pypi_stats.md"
MARKER = "EXAM_OK"

from exam_fetch import (fetch_sdist, locate_suite, make_project, offline_env,  # noqa: E402,F401
                        pypi_meta, test_deps, top_n)
from exam_ledger import (apply_result, emit, load_ledger, save_ledger,  # noqa: E402,F401
                         today)



_ANSI = __import__("re").compile(r"\x1b\[[0-9;]*m")


def _passed_count(text: str) -> int:
    import re
    m = re.search(r"(\d+) passed", _ANSI.sub("", text))
    return int(m.group(1)) if m else 0


def _reason(text: str) -> str:
    """A human-readable one-line failure reason. pytest wraps everything in ANSI colour and
    ends with a bare "N errors" summary that says nothing; the useful line is the exception.
    Store that instead, so `flex/exam-results.json` — the committed proof — reads plainly."""
    lines = [ln.strip() for ln in _ANSI.sub("", text).splitlines() if ln.strip()]
    for pat in ("ModuleNotFoundError", "ImportError", "Error:", "error:",
                "requires", "not a file or directory"):
        hits = [ln for ln in lines if pat.lower() in ln.lower()]
        if hits:
            return hits[-1][:280]
    return (lines[-1] if lines else "")[:280]


def run_exam(pkg: str, imp: str, haru: str, work: Path,
             build_timeout: int, run_timeout: int) -> dict:
    """Sit the exam for one package. Returns a ledger-shaped result dict. Never raises for a
    package-level problem — a timeout or a broken suite is a recorded FAIL, not a crash."""
    r: dict = {"name": pkg, "passed": False, "tests": 0, "version": "", "error": ""}
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    meta = pypi_meta(pkg)
    r.update(version=meta["version"], repo_url=meta["repo_url"], pypi_url=meta["pypi_url"])
    if not meta["sdist_url"]:
        r["error"] = "no sdist on PyPI"
        return r
    root = fetch_sdist(meta["sdist_url"], work / "sd")
    kind, suite = locate_suite(root)
    if kind == "none":
        r["error"] = "no test suite in sdist"
        return r
    r["layout"] = kind + ":" + ",".join(p.name for p in suite)
    make_project(pkg, imp, meta["version"], kind, suite, test_deps(root), work / "proj")
    out = work / "exam.bin"
    try:
        b = subprocess.run([haru, "build", str(work / "proj"), "-o", str(out), "--thick"],
                           capture_output=True, text=True, timeout=build_timeout)
    except subprocess.TimeoutExpired:
        r["error"] = f"build timed out after {build_timeout}s"
        return r
    if not out.exists():
        r["error"] = "build: " + _reason(b.stderr or b.stdout)
        return r
    r["mb"] = round(out.stat().st_size / 1e6, 1)
    # Run the binary from a NEUTRAL directory OUTSIDE the repo, with its cache there too. If it
    # runs from inside flex/out/ (the repo worktree), pytest walks up from the staged suite and
    # discovers *haru-pack's own* pyproject.toml / conftest.py, applies their addopts (the
    # summary line vanishes → a passing suite reports 0 tests) and imports their fixtures
    # (spurious collection errors). That is the same "run-in-place adopts the surrounding
    # project" trap the launcher itself guards against; a real end user's cache is in ~/.cache,
    # not in a checkout, so this reproduces their conditions rather than the harness's.
    rundir = Path(tempfile.mkdtemp(prefix=f"haru-exam-{pkg}-"))
    # A separate, shorter cap for the RUN: a suite that shells out to subprocesses (click's
    # does) can hang or crawl inside a packed offline binary, and that is an honest FAIL, not
    # a reason to stall the whole sweep behind one package.
    try:
        x = subprocess.run([str(out)], capture_output=True, text=True, timeout=run_timeout,
                           cwd=rundir, env=offline_env(rundir / "cold"))
    except subprocess.TimeoutExpired:
        r["error"] = f"suite did not finish inside {run_timeout}s (often subprocess-spawning tests)"
        return r
    finally:
        shutil.rmtree(rundir, ignore_errors=True)
    blob = x.stdout + x.stderr
    r["tests"] = _passed_count(blob)
    if x.returncode == 0 and MARKER in x.stdout:
        r["passed"] = True
    else:
        r["error"] = _reason(blob)
    return r





# ─────────────────────────────────────────────────────────── CLI
def cmd_refresh(_a) -> int:
    led = load_ledger()
    for p in top_n():
        try:
            m = pypi_meta(p["name"])
        except Exception as e:  # noqa: BLE001
            print(f"  {p['name']}: metadata failed: {e}", file=sys.stderr)
            continue
        e = led.get(p["name"], {})
        e.update(rank=p.get("rank"), name=p["name"], version=m["version"],
                 repo_url=m["repo_url"], pypi_url=m["pypi_url"])
        led[p["name"]] = e
        print(f"  {p['name']:>18}  {m['version']:>10}  {m['repo_url']}")
    save_ledger(led)
    emit()
    return 0


def cmd_run(a) -> int:
    haru = shutil.which("haru-pack") or str(REPO / ".venv" / "bin" / "haru-pack")
    if not Path(haru).exists() and not shutil.which("haru-pack"):
        print("haru-pack not found on PATH", file=sys.stderr)
        return 2
    pkgs = top_n()
    if a.top_n:
        pkgs = pkgs[:a.top_n]
    if a.only:
        want = {s.strip() for s in a.only.split(",") if s.strip()}
        pkgs = [p for p in pkgs if p["name"] in want]
    rank_of = {p["name"]: p.get("rank", 0) for p in pkgs}
    out = REPO / "flex" / "out" / "exam"
    led = load_ledger()

    if not a.rerun_passed:
        skip = {p["name"] for p in pkgs if led.get(p["name"], {}).get("passed")}
        if skip:
            print(f"skipping {len(skip)} already-passed (use --rerun-passed to redo): "
                  + ", ".join(sorted(skip)))
        pkgs = [p for p in pkgs if p["name"] not in skip]

    def one(p):
        imp = p.get("import_name") or p["name"].replace("-", "_")
        # Belt-and-braces: run_exam already swallows package-level failures, but a bug in the
        # harness itself must still not abort the sweep and lose every other result.
        try:
            return run_exam(p["name"], imp, haru, out / p["name"], a.timeout, a.run_timeout)
        except Exception as e:  # noqa: BLE001
            return {"name": p["name"], "passed": False, "tests": 0, "error": f"harness: {e}"}

    print(f"exam: {len(pkgs)} package(s), {a.jobs} job(s)\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futs = {ex.submit(one, p): p for p in pkgs}
        for fut in concurrent.futures.as_completed(futs):    # first-done, not first-submitted
            res = fut.result()
            apply_result(led, rank_of[res["name"]], res)
            mark = "PASS" if res["passed"] else "FAIL"
            extra = f"{res.get('tests', 0)} tests" if res["passed"] else res.get("error", "")
            print(f"  {mark}  {res['name']:>18}  {extra[:80]}")
            save_ledger(led)                    # checkpoint after each, so a crash keeps progress
    emit()
    return 0


_NOSUITE = ("no test suite in sdist", "no sdist on PyPI")


def _hud_frame(interval: float) -> str:
    """One rendered HUD frame from the checkpointed ledger vs the top-N matrix."""
    pkgs = top_n()
    total = len(pkgs)
    led = load_ledger()
    rows, npass, nfail, nnosuite, ntests = [], 0, 0, 0, 0
    fails = []
    for p in pkgs:
        name = p["name"]
        e = led.get(name)
        if not e:
            rows.append((p.get("rank", 0), name, "pending", ""))
            continue
        rank = e.get("rank", p.get("rank", 0))
        tests = e.get("tests", 0) or 0
        err = e.get("error", "") or ""
        if e.get("passed"):
            npass += 1; ntests += tests
            rows.append((rank, name, "pass", f"{tests} tests"))
        elif any(s in err for s in _NOSUITE):
            nnosuite += 1
            rows.append((rank, name, "nosuite", err))
        else:
            nfail += 1; ntests += tests
            fails.append(name)
            rows.append((rank, name, "fail", err[:64]))
    examined = npass + nfail + nnosuite
    pct = (examined / total * 100) if total else 0.0
    cols, height = shutil.get_terminal_size((100, 44))
    bar_w = 32
    filled = int(bar_w * examined / total) if total else 0
    mark = {"pass": "✔", "fail": "✘", "nosuite": "∅", "pending": "·"}
    out = [
        f"flex exam HUD   {pct:5.1f}%   [{'#' * filled}{'.' * (bar_w - filled)}]   "
        f"{examined}/{total} examined",
        f"  ✔ pass {npass}   ✘ fail {nfail}   ∅ no-suite {nnosuite}   "
        f"· pending {total - examined}       {ntests:,} tests run",
        "",
    ]
    rows.sort(key=lambda r: r[0])
    examined_rows = [r for r in rows if r[2] != "pending"]     # the ones carrying a pytest result
    pending_rows = [r for r in rows if r[2] == "pending"]      # rank order -> next up is first
    room = max(6, height - len(out) - 6)
    shown = examined_rows[-room:]                              # most-recent results (frontier)
    out += [f"  {mark[st]} {rank:>4}  {name:<26.26} {detail}"
            for rank, name, st, detail in shown]
    if pending_rows:
        nxt = ", ".join(n for _, n, _, _ in pending_rows[:6])
        out += ["", f"  next up ({len(pending_rows)} pending): {nxt}"[:cols - 2]]
    if fails:
        out += [f"  fails ({len(fails)}): {', '.join(fails)}"[:cols - 2]]
    out += [f"  (refresh {interval:g}s · Ctrl-C to quit)"]
    return "\n".join(out)


def cmd_hud(a) -> int:
    """Live view of an exam run: reads the ledger (checkpointed after every package) against the
    top-N matrix and redraws every --interval seconds — percent complete, pass/fail/no-suite
    tallies, total tests run, and each package's pytest result. Run it on the box the exam is on
    (or against a synced ledger). Ctrl-C to quit."""
    import time
    if a.once:
        print(_hud_frame(a.interval))
        return 0
    try:
        while True:
            print("\033[2J\033[H" + _hud_frame(a.interval), flush=True)   # clear + home
            time.sleep(max(0.5, a.interval))
    except KeyboardInterrupt:
        print()
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("refresh", help="pull rank/version/repo-url for the top-N (network)")
    pr = sub.add_parser("run", help="sit the exam and update the ledger")
    pr.add_argument("--only", default="", help="comma-separated package names")
    pr.add_argument("--top-n", type=int, default=0, help="only the first N by rank")
    pr.add_argument("-j", "--jobs", type=int, default=1)
    pr.add_argument("--timeout", type=int, default=1800, help="per-package BUILD timeout (s)")
    pr.add_argument("--run-timeout", type=int, default=420,
                    help="per-package RUN timeout (s); a suite that overruns is a FAIL")
    pr.add_argument("--rerun-passed", action="store_true",
                    help="re-run packages already marked passed (default: skip them)")
    sub.add_parser("emit", help="render top_n_pypi_stats.md from the ledger (offline)")
    hp = sub.add_parser("hud", help="live HUD of a run: percent, tallies, per-package result")
    hp.add_argument("--interval", type=float, default=2.0, help="refresh seconds (default 2)")
    hp.add_argument("--once", action="store_true", help="render a single frame and exit")
    a = ap.parse_args()
    return {"refresh": cmd_refresh, "run": cmd_run, "emit": lambda _a: emit() or 0,
            "hud": cmd_hud}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())

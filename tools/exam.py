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

"THE NETWORK DENIED" IS LITERAL, AND SO IS THE SANDBOX

Running a package's own test suite is the largest quantity of stranger code anything in this
repo executes, and `uv sync` runs its build backend before that. Both happen inside a
throwaway container: the build gets the network, the suite gets `--network none` and a cache
volume that has never been used (INV-SANDBOX-01/02, docs/adr/0005).

`--no-docker` runs it on this host instead, after printing what that means. There the
"denied" is the older approximation — uv forced offline and the proxy variables pointed at a
dead port — which a package can bypass with a socket of its own. Results carry which one
they were produced under; they are not the same evidence.

The page is generated, never hand-edited, and never written by an AI: `emit` is pure
formatting over `flex/exam-results.json`, which is itself produced by real build+run results.
`emit` touches no network, so the committed page reproduces byte-for-byte from the ledger.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
if str(REPO / "tools") not in sys.path:
    sys.path.insert(0, str(REPO / "tools"))

import sandbox  # noqa: E402

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


class HostRunner:
    """Build and run the exam directly on this machine. Opt-in via --no-docker.

    The exam is the one harness that runs a package's OWN test suite, which is the largest
    quantity of stranger code anything in this repo executes.
    """

    kind = "host"
    offline_is_real = False       # no network namespace; offline_env is an approximation

    def __init__(self, haru: str):
        self.haru = haru

    def build(self, work: Path, proj: Path, out: Path, timeout: int) -> tuple:
        b = subprocess.run([self.haru, "build", str(proj), "-o", str(out), "--thick"],
                           capture_output=True, text=True, timeout=timeout)
        return b.returncode, (b.stderr or b.stdout)

    def execute(self, work: Path, out: Path, timeout: int) -> dict:
        # A NEUTRAL directory outside the repo. If the suite runs from inside flex/out/,
        # pytest walks up and discovers haru-pack's own pyproject.toml / conftest.py, applies
        # their addopts (the summary line vanishes → a passing suite reports 0 tests) and
        # imports their fixtures. A real end user's cache is in ~/.cache, not in a checkout.
        rundir = Path(tempfile.mkdtemp(prefix="haru-exam-"))
        try:
            x = subprocess.run([str(out)], capture_output=True, text=True, timeout=timeout,
                               cwd=rundir, env=offline_env(rundir / "cold"))
            return {"rc": x.returncode, "stdout": x.stdout, "stderr": x.stderr,
                    "timed_out": False}
        except subprocess.TimeoutExpired:
            return {"rc": None, "stdout": "", "stderr": "", "timed_out": True}
        finally:
            shutil.rmtree(rundir, ignore_errors=True)


class DockerRunner:
    """Build and run the exam in throwaway containers (INV-SANDBOX-01/02)."""

    kind = "docker"
    offline_is_real = True

    def __init__(self, image: str, uid: int, gid: int):
        self.image, self.uid, self.gid = image, uid, gid

    def _env(self) -> dict:
        return sandbox.container_env()

    def build(self, work: Path, proj: Path, out: Path, timeout: int) -> tuple:
        r = sandbox.run(
            self.image,
            cmd=["haru-pack", "build", f"{sandbox.WORKDIR}/{proj.name}",
                 "-o", f"{sandbox.WORKDIR}/{out.name}", "--thick"],
            work=work, network=True, cache=sandbox.CACHE_RW, uid=self.uid, gid=self.gid,
            repo=REPO, env=self._env(), timeout=timeout)
        if r["infra"]:
            return 125, f"the sandbox could not start this build: {r['stderr'].strip()[-300:]}"
        return (r["rc"] if r["rc"] is not None else 124), (r["stderr"] or r["stdout"])

    def execute(self, work: Path, out: Path, timeout: int) -> dict:
        # `--network none` is the whole claim the exam page makes: the suite passed with the
        # network DENIED, so the payload carried a working library. A cold cache volume and
        # no interface is that claim made literally true.
        #
        # workdir is /cache, not /w: /w holds the generated project's pyproject.toml, and
        # pytest walking up into it is the same rootdir trap the host path avoids with a
        # temp dir. The cold volume is empty, which is exactly what "neutral" means here.
        r = sandbox.run(
            self.image, cmd=[f"{sandbox.WORKDIR}/{out.name}"], work=work,
            network=False, cache=sandbox.CACHE_COLD, uid=self.uid, gid=self.gid,
            env=self._env(), workdir=sandbox.CACHEDIR, timeout=timeout)
        return {"rc": r["rc"], "stdout": r["stdout"], "stderr": r["stderr"],
                "timed_out": r["timed_out"]}


def run_exam(pkg: str, imp: str, runner, work: Path,
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
        rc, output = runner.build(work, work / "proj", out, build_timeout)
    except subprocess.TimeoutExpired:
        r["error"] = f"build timed out after {build_timeout}s"
        return r
    if not out.exists():
        r["error"] = "build: " + _reason(output)
        return r
    r["mb"] = round(out.stat().st_size / 1e6, 1)
    # Run the binary from a NEUTRAL directory OUTSIDE the repo, with its cache there too. If it
    # runs from inside flex/out/ (the repo worktree), pytest walks up from the staged suite and
    # discovers *haru-pack's own* pyproject.toml / conftest.py, applies their addopts (the
    # summary line vanishes → a passing suite reports 0 tests) and imports their fixtures
    # (spurious collection errors). That is the same "run-in-place adopts the surrounding
    # project" trap the launcher itself guards against; a real end user's cache is in ~/.cache,
    # not in a checkout, so this reproduces their conditions rather than the harness's.
    # A separate, shorter cap for the RUN: a suite that shells out to subprocesses (click's
    # does) can hang or crawl inside a packed offline binary, and that is an honest FAIL, not
    # a reason to stall the whole sweep behind one package.
    ex = runner.execute(work, out, run_timeout)
    if ex["timed_out"]:
        r["error"] = f"suite did not finish inside {run_timeout}s (often subprocess-spawning tests)"
        return r
    blob = ex["stdout"] + ex["stderr"]
    r["tests"] = _passed_count(blob)
    r["offline_is_real"] = runner.offline_is_real
    if ex["rc"] == 0 and MARKER in ex["stdout"]:
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

    # The sandbox decision, before any sdist is fetched or any suite is run.
    if a.no_docker:
        print(sandbox.host_warning(len(pkgs), "packages' own test suites"), file=sys.stderr)
        haru = shutil.which("haru-pack") or str(REPO / ".venv" / "bin" / "haru-pack")
        if not Path(haru).exists() and not shutil.which("haru-pack"):
            print("haru-pack not found on PATH", file=sys.stderr)
            return 2
        runner = HostRunner(haru)
        where = "ON THIS HOST (--no-docker)"
    else:
        try:
            image = sandbox.preflight(require_rootless=a.require_rootless,
                                      log=lambda m: print(m, file=sys.stderr))
        except sandbox.SandboxUnavailable as e:
            print(f"\nexam: {e}", file=sys.stderr)
            return 2
        runner = DockerRunner(image, os.getuid(), os.getgid())
        where = f"in containers ({image})"

    def one(p):
        imp = p.get("import_name") or p["name"].replace("-", "_")
        # Belt-and-braces: run_exam already swallows package-level failures, but a bug in the
        # harness itself must still not abort the sweep and lose every other result.
        try:
            return run_exam(p["name"], imp, runner, out / p["name"], a.timeout, a.run_timeout)
        except Exception as e:  # noqa: BLE001
            return {"name": p["name"], "passed": False, "tests": 0, "error": f"harness: {e}"}

    print(f"exam: {len(pkgs)} package(s), {a.jobs} job(s), {where}\n")
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
    pr.add_argument("--no-docker", action="store_true",
                    help="run the packages' own test suites DIRECTLY ON THIS HOST instead "
                         "of in a container. Prints what that puts at risk before it starts.")
    pr.add_argument("--require-rootless", action="store_true",
                    help="refuse to run against a rootful docker daemon")
    sub.add_parser("emit", help="render top_n_pypi_stats.md from the ledger (offline)")
    a = ap.parse_args()
    return {"refresh": cmd_refresh, "run": cmd_run, "emit": lambda _a: emit() or 0}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())

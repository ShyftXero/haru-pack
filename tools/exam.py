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
import datetime as _dt
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
from haru_pack import tomlio  # noqa: E402

PACKAGES = REPO / "flex" / "packages.toml"
LEDGER = REPO / "flex" / "exam-results.json"
PAGE = REPO / "top_n_pypi_stats.md"
MARKER = "EXAM_OK"


# ─────────────────────────────────────────────────────────── the top-N, from the matrix
def top_n() -> list[dict]:
    """The ranked top-N packages, from the same generated matrix flex already reads, so this
    page and the flex matrix cannot disagree about who the top-N are."""
    data = tomlio.load(PACKAGES)
    pk = [p for p in data.get("package", []) if p.get("list") == "top25"]
    pk.sort(key=lambda p: p.get("rank", 10**6))
    return pk


# ─────────────────────────────────────────────────────────── acquisition (network)
def pypi_meta(pkg: str) -> dict:
    """(sdist_url, version, repo_url, pypi_url) from PyPI's JSON API."""
    d = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/json", timeout=30))
    ver = d["info"]["version"]
    sd = next((f["url"] for f in d["releases"].get(ver, [])
               if f["packagetype"] == "sdist"), "")
    urls = {k.lower(): v for k, v in (d["info"].get("project_urls") or {}).items()}
    repo = ""
    for key in ("source", "source code", "repository", "code", "github", "homepage"):
        if key in urls:
            repo = urls[key]
            break
    return {"sdist_url": sd, "version": ver, "repo_url": repo,
            "pypi_url": f"https://pypi.org/project/{pkg}/"}


def fetch_sdist(url: str, dest: Path) -> Path:
    raw = urllib.request.urlopen(url, timeout=120).read()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as t:
        # filter="data" is the safe extractor: it refuses absolute paths, `..` escapes,
        # device/pipe members and unsafe metadata. These sdists come from PyPI — semi-trusted
        # at best — so a hostile one must not be able to write outside `dest`. It also silences
        # the Python 3.14 DeprecationWarning, which is warning about exactly this default.
        t.extractall(dest, filter="data")
    return next(p for p in dest.iterdir() if p.is_dir())


def locate_suite(root: Path) -> tuple[str, list[Path]]:
    """The test tree at the sdist root. Layouts seen across the top-25: a tests/ or test/ or
    testing/ directory, or a bare test_*.py at the root (six). The whole directory is taken,
    not just *.py — packaging's tests carry binary fixtures the suite reads."""
    for name in ("tests", "test", "testing"):
        d = root / name
        if d.is_dir() and (any(d.rglob("test_*.py")) or any(d.rglob("*_test.py"))):
            return "dir", [d]
    roots = sorted(root.glob("test_*.py")) + sorted(root.glob("*_test.py"))
    conf = [root / "conftest.py"] if (root / "conftest.py").exists() else []
    if roots:
        return "files", roots + conf
    return "none", []


def test_deps(root: Path) -> list[str]:
    """The package's OWN declared test dependencies. Guessing pytest+hypothesis is not enough
    (packaging's suite imports `pretend` and `tomli_w`), and neither is a fixed list of group
    NAMES — idna puts its test deps under an extra called `all`, others use `test`/`dev`/`ci`.
    So the group is found by content: any optional-dependency group or dependency-group that
    itself lists pytest is a test group, and we take it whole. Extra tools it drags in (ruff,
    mypy, coverage) are harmless; a missing test import is a collection error."""
    pp = root / "pyproject.toml"
    found: list[str] = []
    if pp.exists():
        data = tomllib.loads(pp.read_text(encoding="utf-8"))
        groups = {**data.get("project", {}).get("optional-dependencies", {}),
                  **data.get("dependency-groups", {})}
        for items in groups.values():
            strs = [i for i in items if isinstance(i, str)]   # skip {include-group: ...}
            if any("pytest" in s.lower() for s in strs):
                found += strs
    if not any("pytest" in d.lower() for d in found):
        found.append("pytest")
    return sorted(set(found))


# ─────────────────────────────────────────────────────────── build the exam project
def make_project(pkg: str, imp: str, ver: str, kind: str, suite: list[Path], deps: list[str],
                 proj: Path) -> None:
    app = proj / "exam"
    (app / "_suite").mkdir(parents=True)
    (app / "__init__.py").write_text("")
    if kind == "dir":
        shutil.copytree(suite[0], app / "_suite" / suite[0].name)
    else:
        for f in suite:
            shutil.copy2(f, app / "_suite" / f.name)
    (app / "__main__.py").write_text(
        "import pathlib, sys\n"
        "import pytest\n"
        f"import {imp}  # noqa: F401  — proves it imports before the suite even starts\n"
        "suite = pathlib.Path(__file__).parent / '_suite'\n"
        "rc = pytest.main(['-q', '--no-header', '-p', 'no:cacheprovider', str(suite)])\n"
        f"if rc == 0:\n    print({MARKER!r}, {pkg!r}, 'passed its own suite inside the binary')\n"
        "sys.exit(rc)\n")
    dep_line = ", ".join(f'"{d}"' for d in [f"{pkg}=={ver}", *deps])
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "exam"\nversion = "0.1.0"\n'
        'requires-python = ">=3.12"\n'
        f"dependencies = [{dep_line}]\n")
    (proj / "haru_pack.toml").write_text('entrypoint = ["python", "-m", "exam"]\n')


def offline_env(cold: Path) -> dict:
    import os
    env = dict(os.environ)
    env["XDG_CACHE_HOME"] = str(cold)
    env["UV_OFFLINE"] = "1"
    env["UV_PYTHON_DOWNLOADS"] = "never"
    for v in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
              "http_proxy", "https_proxy", "all_proxy"):
        env[v] = "http://127.0.0.1:9"          # discard port; nothing listens
    env.pop("NO_PROXY", None)
    tmp = cold / "tmp"                          # pytest's tmp_path wants an owned base dir
    tmp.mkdir(parents=True, exist_ok=True)
    env["TMPDIR"] = str(tmp)
    return env


def _passed_count(text: str) -> int:
    import re
    clean = re.sub(r"\x1b\[[0-9;]*m", "", text)     # pytest colours its summary line
    m = re.search(r"(\d+) passed", clean)
    return int(m.group(1)) if m else 0


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
        r["error"] = "build: " + (b.stderr or b.stdout).strip()[-400:]
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
        r["error"] = (blob.strip().splitlines() or [""])[-1][:300]
    return r


# ─────────────────────────────────────────────────────────── the ledger (git-tracked)
def load_ledger() -> dict:
    if LEDGER.exists():
        return json.loads(LEDGER.read_text(encoding="utf-8"))
    return {}


def save_ledger(led: dict) -> None:
    # Sorted keys + trailing newline so the committed file diffs cleanly and deterministically.
    LEDGER.write_text(json.dumps(led, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def today() -> str:
    return _dt.date.today().isoformat()


def apply_result(led: dict, rank: int, res: dict) -> None:
    e = led.get(res["name"], {})
    e["rank"] = rank
    e["name"] = res["name"]
    for k in ("version", "repo_url", "pypi_url", "layout", "mb"):
        if res.get(k):
            e[k] = res[k]
    e["tests"] = res.get("tests", e.get("tests", 0))
    e["passed"] = bool(res["passed"])
    e["last_run"] = today()
    e["error"] = res.get("error", "")
    if res["passed"]:
        e["last_passed"] = today()             # only a pass moves this date
    led[res["name"]] = e


# ─────────────────────────────────────────────────────────── emit (offline, deterministic)
def emit() -> None:
    """Render top_n_pypi_stats.md from packages.toml (the row set) + the ledger (the results).
    No network, no clock beyond the dates already recorded in the ledger — so the committed
    page reproduces exactly from the committed ledger."""
    pkgs = top_n()
    led = load_ledger()
    n = len(pkgs)
    passing = sum(1 for p in pkgs if led.get(p["name"], {}).get("passed"))
    examined = sum(1 for p in pkgs if led.get(p["name"], {}).get("last_run"))
    asof = max((led.get(p["name"], {}).get("last_run", "") for p in pkgs), default="")

    lines = [
        "# top-N PyPI packages — the flex exam",
        "",
        "<!-- GENERATED by tools/exam.py — do not hand-edit. Regenerate: "
        "`python tools/exam.py emit`. -->",
        "",
        "Each package below **sits its own test suite** from inside a haru-pack **thick** "
        "binary, with the network denied. A pass is the strongest statement this project "
        "makes about a packaged dependency: not that it imports, but that its own tests pass "
        "against the code the payload actually carried. Mechanism and rationale: "
        "[`docs/FLEX.md`](docs/FLEX.md) · invariant `INV-TIER-01`.",
        "",
        f"**{passing} of {n} passing**, {examined} examined"
        + (f", as of {asof}." if asof else "."),
        "",
        "| # | Package | Repo | Exam | Tests | Last passed |",
        "|--:|---------|------|:----:|------:|-------------|",
    ]
    for p in pkgs:
        name = p["name"]
        e = led.get(name, {})
        pypi = e.get("pypi_url") or f"https://pypi.org/project/{name}/"
        repo = e.get("repo_url") or ""
        repo_cell = f"[source]({repo})" if repo else "—"
        if not e.get("last_run"):
            exam = "·"                          # not yet examined
        elif e.get("passed"):
            exam = "✅"
        else:
            exam = "❌"
        tests = str(e.get("tests", "")) if e.get("passed") else ""
        last = e.get("last_passed", "") or "—"
        lines.append(f"| {p.get('rank', '')} | [{name}]({pypi}) | {repo_cell} | "
                     f"{exam} | {tests} | {last} |")
    lines += [
        "",
        "Legend: ✅ passed its own suite offline · ❌ examined, did not pass · "
        "· not yet examined.",
        "",
        "A ❌ is not always a packaging defect — a suite may need a system library, a display, "
        "or the network, none of which a thick binary provides. The `error` field in "
        "[`flex/exam-results.json`](flex/exam-results.json) records why. `hard_targets` "
        "(torch, playwright, …) are a separate, harder axis and are not counted here.",
        "",
    ]
    PAGE.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {PAGE.relative_to(REPO)}  ({passing}/{n} passing, {examined} examined)")


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
    a = ap.parse_args()
    return {"refresh": cmd_refresh, "run": cmd_run, "emit": lambda _a: emit() or 0}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())

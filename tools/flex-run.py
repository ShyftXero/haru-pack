#!/usr/bin/env python3
"""Run the flex harness: pack each package into a binary, then run the binary.

    python tools/flex-run.py                    # the whole matrix
    python tools/flex-run.py --list top25       # breadth only
    python tools/flex-run.py --list hard_targets
    python tools/flex-run.py --only numpy,pyyaml
    python tools/flex-run.py -j 4               # 4 builds at once
    python tools/flex-run.py --dry-run          # show what would run

WHAT THIS PROVES

For each package: write a PEP 723 script that imports it and does one small real thing,
`haru-pack build` that script, then EXECUTE the resulting binary and require it to print
FLEX_OK. Building is not the test — a binary that builds and then dies on startup is a
failure, and only running it catches that.

Results go to flex/out/results.json and a summary table on stdout. Both the build and the
run are timed, and the payload size is recorded, because "it works" and "it works and the
binary is 900 MB" are different answers.

TWO LISTS, DIFFERENT MEANINGS

  top25         Breadth. Mostly pure-Python wheels. Expected to pass; a failure here is a
                real regression in ordinary packaging.
  hard_targets  Shapes that break packaging tools — browser binaries, post-install
                downloads, giant native wheels, system libraries. Some are marked
                `expect_failure`, where FAILING is the correct result and passing is the
                surprise worth investigating.

NO AI REQUIRED. It shells out to `haru-pack` and reads exit codes.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from haru_pack import tomlio  # noqa: E402

MANIFEST = REPO / "flex" / "packages.toml"
OUT = REPO / "flex" / "out"
MARKER = "FLEX_OK"


def script_for(pkg: dict) -> str:
    """A PEP 723 script: inline dependency metadata + the smoke body."""
    name = pkg["name"]
    imp = pkg.get("import_name", name.replace("-", "_"))
    body = (pkg.get("smoke") or "").strip("\n")
    if not body:
        body = (f"import {imp} as _m\n"
                f"print('version:', getattr(_m, '__version__', 'unknown'))\n"
                f"print('{MARKER}')")
    return (f"# /// script\n"
            f'# requires-python = ">={pkg.get("python", "3.12")}"\n'
            f'# dependencies = ["{name}"]\n'
            f"# ///\n"
            f"{body}\n")


def run_one(pkg: dict, haru: str, timeout: int, keep: bool) -> dict:
    name = pkg["name"]
    work = OUT / name
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    script = work / f"{name.replace('-', '_')}_smoke.py"
    script.write_text(script_for(pkg))
    exe = work / name.replace("-", "_")

    res = {"name": name, "list": pkg.get("list"), "tier": pkg.get("tier"),
           "expect_failure": bool(pkg.get("expect_failure")),
           "build_ok": False, "run_ok": False, "bytes": 0,
           "build_s": 0.0, "run_s": 0.0, "error": ""}

    t0 = time.monotonic()
    b = subprocess.run([haru, "build", str(script), "-o", str(exe),
                        "--tier", pkg.get("tier", "default")],
                       capture_output=True, text=True, timeout=timeout)
    res["build_s"] = round(time.monotonic() - t0, 1)
    if b.returncode != 0 or not exe.exists():
        res["error"] = "build: " + (b.stderr or b.stdout).strip()[-600:]
        return res
    res["build_ok"] = True
    res["bytes"] = exe.stat().st_size

    t0 = time.monotonic()
    try:
        # cwd is the work dir so a package that writes files does not litter the repo
        r = subprocess.run([str(exe)], capture_output=True, text=True,
                           timeout=timeout, cwd=work)
    except subprocess.TimeoutExpired:
        res["run_s"] = round(time.monotonic() - t0, 1)
        res["error"] = f"run: timed out after {timeout}s"
        return res
    res["run_s"] = round(time.monotonic() - t0, 1)
    if r.returncode != 0:
        res["error"] = f"run: exit {r.returncode}: " + (r.stderr or r.stdout).strip()[-600:]
    elif MARKER not in r.stdout:
        res["error"] = f"run: no {MARKER} in output: {r.stdout.strip()[:300]!r}"
    else:
        res["run_ok"] = True

    if not keep and res["run_ok"]:
        shutil.rmtree(work, ignore_errors=True)
    return res


def verdict(r: dict) -> str:
    ok = r["build_ok"] and r["run_ok"]
    if r["expect_failure"]:
        return "xfail" if not ok else "XPASS"
    return "ok" if ok else "FAIL"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", dest="which", choices=["top25", "hard_targets", "all"],
                    default="all")
    ap.add_argument("--only", default="", help="comma-separated package names")
    ap.add_argument("-j", "--jobs", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--keep", action="store_true", help="keep work dirs for passing builds")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if not MANIFEST.exists():
        print(f"{MANIFEST.relative_to(REPO)} missing — run tools/gen-package-manifest.py",
              file=sys.stderr)
        return 1
    pkgs = tomlio.load(MANIFEST).get("package", [])
    if a.which != "all":
        pkgs = [p for p in pkgs if p.get("list") == a.which]
    if a.only:
        want = {s.strip() for s in a.only.split(",") if s.strip()}
        pkgs = [p for p in pkgs if p["name"] in want]
        missing = want - {p["name"] for p in pkgs}
        if missing:
            print(f"not in the manifest: {', '.join(sorted(missing))}", file=sys.stderr)
            return 1
    if not pkgs:
        print("nothing selected", file=sys.stderr)
        return 1

    haru = shutil.which("haru-pack") or str(REPO / ".venv" / "bin" / "haru-pack")
    if not Path(haru).exists() and not shutil.which("haru-pack"):
        print("haru-pack not found on PATH", file=sys.stderr)
        return 1

    if a.dry_run:
        for p in pkgs:
            print(f"{p['name']:24} {p.get('list'):13} tier={p.get('tier')}")
        print(f"\n{len(pkgs)} package(s); nothing was run.")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    print(f"flex: {len(pkgs)} package(s), {a.jobs} job(s), haru-pack at {haru}\n")

    results = []
    if a.jobs > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
            futs = {ex.submit(run_one, p, haru, a.timeout, a.keep): p for p in pkgs}
            for f in concurrent.futures.as_completed(futs):
                r = f.result()
                results.append(r)
                print(f"  {verdict(r):5} {r['name']}")
    else:
        for p in pkgs:
            r = run_one(p, haru, a.timeout, a.keep)
            results.append(r)
            print(f"  {verdict(r):5} {r['name']}")

    results.sort(key=lambda r: (r["list"] or "", r["name"]))
    (OUT / "results.json").write_text(json.dumps(results, indent=2) + "\n")

    print(f"\n{'package':24} {'list':13} {'verdict':7} {'size':>9} {'build':>7} {'run':>6}")
    print("-" * 72)
    for r in results:
        size = f"{r['bytes'] / 1e6:.1f}MB" if r["bytes"] else "-"
        print(f"{r['name']:24} {(r['list'] or ''):13} {verdict(r):7} {size:>9} "
              f"{r['build_s']:>6}s {r['run_s']:>5}s")

    bad = [r for r in results if verdict(r) in ("FAIL", "XPASS")]
    print(f"\n{len(results) - len(bad)}/{len(results)} as expected; "
          f"results in {(OUT / 'results.json').relative_to(REPO)}")
    if bad:
        print("\nnot as expected:")
        for r in bad:
            print(f"  {verdict(r)} {r['name']}: {r['error'][:300]}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())

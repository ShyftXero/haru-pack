#!/usr/bin/env python3
"""Run the flex harness: pack each package into a binary, then run the binary.

    python tools/flex-run.py                    # the whole matrix
    python tools/flex-run.py --list top25       # breadth only
    python tools/flex-run.py --list hard_targets
    python tools/flex-run.py --only numpy,pyyaml
    python tools/flex-run.py -j 4               # 4 builds at once
    python tools/flex-run.py --tier thick --offline-check    # prove the payload carries deps
    python tools/flex-run.py --dry-run          # show what would run

WHAT THIS PROVES

For each package: build a tiny project that depends on it, whose `__main__` imports it and
does one small real thing, then EXECUTE the resulting binary and require it to print
FLEX_OK. Building is not the test — a binary that builds and then dies on startup is a
failure, and only running it catches that.

The entrypoint is `python -m flexapp`, so stdout comes from a module that had to be
importable inside the packaged environment. A bare `import` in a script proves less.

THICK MODE IS THE ONE THAT PROVES ANYTHING ABOUT THE PAYLOAD

At the default tier the dependency is fetched on FIRST RUN, so a green result proves the
packaging path and nothing about what the binary carries. At `--thick` the payload is
supposed to carry uv, the interpreter and every dependency.

`--offline-check` proves it: run the thick binary again with a PRISTINE cache directory and
uv forced offline. Pristine matters — with a warm ~/.cache/haru-pack the run succeeds from
cache and the test is vacuous. If it still prints FLEX_OK, the dependencies came out of the
payload.

Note this is not a network namespace (this box cannot create one). It forces uv offline and
points the proxy variables at a dead port, which blocks the fetch path that matters; it does
not stop a package from opening a raw socket of its own. Stated so the result is not read as
stronger than it is.

A thick *script* build would not prove this: assemble_payload only warms the dependency
cache for `kind == "project"`, so the harness builds projects, not PEP 723 scripts.

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
import os
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


def smoke_body(pkg: dict) -> str:
    """The body of flexapp/__main__.py: exercise the package, then print the marker."""
    name = pkg["name"]
    imp = pkg.get("import_name", name.replace("-", "_"))
    body = (pkg.get("smoke") or "").strip("\n")
    if not body:
        body = (f"import {imp} as _m\n"
                f"print('version:', getattr(_m, '__version__', 'unknown'))\n"
                f"print('{MARKER}')")
    extra = ""
    mod = pkg.get("module")
    if mod:
        # The package ships its own `python -m` entrypoint; run it too, in-process, so its
        # stdout is part of the evidence that the module is importable AND executable.
        extra = ("\nimport runpy\n"
                 f"print('--- python -m {mod} ---')\n"
                 "try:\n"
                 f"    runpy.run_module({mod!r}, run_name='__main__')\n"
                 "except SystemExit:\n"
                 "    pass\n")
    return body + extra + "\n"


def make_project(pkg: dict, root: Path) -> Path:
    """A minimal real project: pyproject + a flexapp package with a __main__.

    A project, not a PEP 723 script, because only `kind == "project"` gets its dependency
    cache warmed into the payload at the thick tier — which is the whole point of the
    offline check. Declared sharp edges (bundle / post_install, taken from the curation
    file, which mirrors scaffold.KNOWN) are written into haru_pack.toml so they are handled
    at build time rather than discovered as a failure.
    """
    proj = root / "proj"
    (proj / "flexapp").mkdir(parents=True)
    (proj / "flexapp" / "__init__.py").write_text("")
    (proj / "flexapp" / "__main__.py").write_text(smoke_body(pkg))
    (proj / "pyproject.toml").write_text(
        "[project]\n"
        'name = "flexapp"\n'
        'version = "0.1.0"\n'
        f'requires-python = ">={pkg.get("python", "3.12")}"\n'
        f'dependencies = ["{pkg["name"]}"]\n')

    lines = ['entrypoint = ["python", "-m", "flexapp"]']
    for block in ("bundle", "post_install"):
        if pkg.get(block):
            lines.append("")
            lines.append(pkg[block].strip())
    (proj / "haru_pack.toml").write_text("\n".join(lines) + "\n")
    return proj


def _execute(exe: Path, work: Path, timeout: int, env=None) -> tuple:
    """(ok, seconds, detail). ok means exit 0 AND the marker in stdout."""
    t0 = time.monotonic()
    try:
        r = subprocess.run([str(exe)], capture_output=True, text=True,
                           timeout=timeout, cwd=work, env=env)
    except subprocess.TimeoutExpired:
        return False, round(time.monotonic() - t0, 1), f"timed out after {timeout}s"
    dt = round(time.monotonic() - t0, 1)
    if r.returncode != 0:
        return False, dt, f"exit {r.returncode}: " + (r.stderr or r.stdout).strip()[-600:]
    if MARKER not in r.stdout:
        return False, dt, f"no {MARKER} in output: {r.stdout.strip()[:300]!r}"
    return True, dt, r.stdout.strip()[-200:]


def _offline_env(cold: Path) -> dict:
    """Environment for the offline check: a cache that has never been used, and uv barred
    from the network.

    The pristine cache is the load-bearing part. With a warm ~/.cache/haru-pack the staged
    tree is reused and the run proves nothing about the payload.
    """
    env = dict(os.environ)
    env["XDG_CACHE_HOME"] = str(cold)
    env["UV_OFFLINE"] = "1"
    env["UV_PYTHON_DOWNLOADS"] = "never"
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy"):
        env[var] = "http://127.0.0.1:9"      # discard port; nothing listens
    env.pop("NO_PROXY", None)
    env.pop("no_proxy", None)
    return env


def run_one(pkg: dict, haru: str, timeout: int, keep: bool, offline_check: bool) -> dict:
    name = pkg["name"]
    tier = pkg.get("tier", "default")
    work = OUT / name
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    proj = make_project(pkg, work)
    exe = work / name.replace("-", "_")

    res = {"name": name, "list": pkg.get("list"), "tier": tier,
           "expect_failure": bool(pkg.get("expect_failure")),
           "build_ok": False, "run_ok": False, "offline_ok": None, "bytes": 0,
           "build_s": 0.0, "run_s": 0.0, "offline_s": 0.0, "error": "", "stdout": ""}

    t0 = time.monotonic()
    b = subprocess.run([haru, "build", str(proj), "-o", str(exe), "--tier", tier],
                       capture_output=True, text=True, timeout=timeout)
    res["build_s"] = round(time.monotonic() - t0, 1)
    if b.returncode != 0 or not exe.exists():
        res["error"] = "build: " + (b.stderr or b.stdout).strip()[-600:]
        return res
    res["build_ok"] = True
    res["bytes"] = exe.stat().st_size

    ok, dt, detail = _execute(exe, work, timeout)
    res["run_s"], res["run_ok"] = dt, ok
    if not ok:
        res["error"] = "run: " + detail
        return res
    res["stdout"] = detail

    # The payload check. Only meaningful at thick: at other tiers the dependency is SUPPOSED
    # to be fetched at first run, so failing offline is correct behaviour, not a defect.
    if offline_check and tier == "thick":
        cold = work / "cold-cache"
        cold.mkdir(exist_ok=True)
        ok2, dt2, detail2 = _execute(exe, work, timeout, env=_offline_env(cold))
        res["offline_ok"], res["offline_s"] = ok2, dt2
        if not ok2:
            res["error"] = ("offline: the thick payload did not carry its dependencies — "
                            + detail2)

    if not keep and res["run_ok"] and res["offline_ok"] is not False:
        shutil.rmtree(work, ignore_errors=True)
    return res


def verdict(r: dict) -> str:
    ok = r["build_ok"] and r["run_ok"] and r.get("offline_ok") is not False
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
    ap.add_argument("--tier", default="", help="override the tier for every package")
    ap.add_argument("--offline-check", action="store_true",
                    help="for thick builds, re-run with a pristine cache and uv offline")
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
    if a.tier:
        pkgs = [{**p, "tier": a.tier} for p in pkgs]
    if a.offline_check and not any(p.get("tier") == "thick" for p in pkgs):
        print("note: --offline-check only applies to thick builds; none selected",
              file=sys.stderr)

    haru = shutil.which("haru-pack") or str(REPO / ".venv" / "bin" / "haru-pack")
    if not Path(haru).exists() and not shutil.which("haru-pack"):
        print("haru-pack not found on PATH", file=sys.stderr)
        return 1

    if a.dry_run:
        for p in pkgs:
            print(f"{p['name']:24} {p.get('list'):13} tier={p.get('tier')}"
                  f"{'  +offline' if (a.offline_check and p.get('tier') == 'thick') else ''}")
        print(f"\n{len(pkgs)} package(s); nothing was run.")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    print(f"flex: {len(pkgs)} package(s), {a.jobs} job(s), haru-pack at {haru}\n")

    results = []
    if a.jobs > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
            futs = {ex.submit(run_one, p, haru, a.timeout, a.keep, a.offline_check): p
                    for p in pkgs}
            for f in concurrent.futures.as_completed(futs):
                r = f.result()
                results.append(r)
                print(f"  {verdict(r):5} {r['name']}")
    else:
        for p in pkgs:
            r = run_one(p, haru, a.timeout, a.keep, a.offline_check)
            results.append(r)
            print(f"  {verdict(r):5} {r['name']}")

    results.sort(key=lambda r: (r["list"] or "", r["name"]))
    (OUT / "results.json").write_text(json.dumps(results, indent=2) + "\n")

    print(f"\n{'package':22} {'list':13} {'tier':8} {'verdict':7} {'size':>9} "
          f"{'build':>7} {'run':>6} {'offline':>8}")
    print("-" * 88)
    for r in results:
        size = f"{r['bytes'] / 1e6:.1f}MB" if r["bytes"] else "-"
        off = {True: "carried", False: "FETCHED", None: "-"}[r.get("offline_ok")]
        print(f"{r['name']:22} {(r['list'] or ''):13} {(r['tier'] or ''):8} {verdict(r):7} "
              f"{size:>9} {r['build_s']:>6}s {r['run_s']:>5}s {off:>8}")

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

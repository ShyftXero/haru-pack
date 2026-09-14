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

`--offline-check` proves it: run the thick binary again in a container with NO NETWORK
INTERFACE and a cache volume that has never been used. Pristine matters — with a warm cache
the staged tree is reused and the run proves nothing about the payload. If it still prints
FLEX_OK, the dependencies came out of the payload.

This is a real network namespace. It used to force uv offline and point the proxy variables
at a dead port, and said so: that blocked the fetch path that matters but did not stop a
package opening a raw socket of its own. `--network none` does (INV-SANDBOX-02).

EVERYTHING RUNS IN A CONTAINER, BY DEFAULT

This harness downloads code written by strangers, chosen by download rank rather than by
audit, and executes it — at three points: sdist build backends under `uv sync`, the binary
the build produces, and any [[bundle]]/[[post_install]] step in the manifest. Each package
gets its own throwaway containers, so a poisoned one cannot reach $HOME, your keys, or the
next package's result (INV-SANDBOX-01, docs/adr/0005).

`--no-docker` runs it on this host instead, after printing what that means. There is no
silent fallback: if docker is missing and you did not pass the flag, this stops.

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
sys.path.insert(0, str(REPO / "tools"))

import sandbox  # noqa: E402
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


def _verdict_from_output(rc, stdout, stderr, timed_out, timeout, secs) -> tuple:
    """(ok, seconds, detail) from one execution, whoever ran it.

    Shared by both runners so that "what counts as a pass" is decided in exactly one place.
    A container and a host process disagreeing about that would be a very annoying bug.
    """
    if timed_out:
        return False, secs, f"timed out after {timeout}s"
    if rc != 0:
        return False, secs, f"exit {rc}: " + (stderr or stdout).strip()[-600:]
    if MARKER not in stdout:
        return False, secs, f"no {MARKER} in output: {stdout.strip()[:300]!r}"
    return True, secs, stdout.strip()[-200:]


class HostRunner:
    """Build and run directly on this machine. Opt-in via --no-docker; see host_warning()."""

    kind = "host"
    #: The host cannot create a network namespace, so its offline check is an
    #: APPROXIMATION and every result it produces is labelled as one.
    offline_is_real = False

    def __init__(self, haru: str):
        self.haru = haru

    def build(self, work: Path, proj: Path, exe: Path, tier: str, timeout: int) -> tuple:
        b = subprocess.run([self.haru, "build", str(proj), "-o", str(exe), "--tier", tier],
                           capture_output=True, text=True, timeout=timeout)
        return b.returncode, (b.stderr or b.stdout)

    def execute(self, work: Path, exe: Path, timeout: int, *, offline: bool) -> tuple:
        env = _offline_env(work / "cold-cache") if offline else None
        t0 = time.monotonic()
        try:
            r = subprocess.run([str(exe)], capture_output=True, text=True,
                               timeout=timeout, cwd=work, env=env)
            rc, out, err, to = r.returncode, r.stdout, r.stderr, False
        except subprocess.TimeoutExpired:
            rc, out, err, to = None, "", "", True
        return _verdict_from_output(rc, out, err, to, timeout,
                                    round(time.monotonic() - t0, 1))


class DockerRunner:
    """Build and run each package in its own throwaway containers (INV-SANDBOX-01).

    Two per package: the build gets the network and a writable cache, the run gets a
    read-only cache and — at thick — no network interface at all.
    """

    kind = "docker"
    offline_is_real = True

    def __init__(self, image: str, uid: int, gid: int):
        self.image, self.uid, self.gid = image, uid, gid

    def _env(self) -> dict:
        return sandbox.container_env()

    def build(self, work: Path, proj: Path, exe: Path, tier: str, timeout: int) -> tuple:
        r = sandbox.run(
            self.image,
            cmd=["haru-pack", "build", f"{sandbox.WORKDIR}/{proj.name}",
                 "-o", f"{sandbox.WORKDIR}/{exe.name}", "--tier", tier],
            work=work, network=True, cache=sandbox.CACHE_RW,
            uid=self.uid, gid=self.gid, repo=REPO, env=self._env(), timeout=timeout)
        if r["infra"]:
            return 125, f"the sandbox could not start this build: {r['stderr'].strip()[-300:]}"
        return (r["rc"] if r["rc"] is not None else 124), (r["stderr"] or r["stdout"])

    def execute(self, work: Path, exe: Path, timeout: int, *, offline: bool) -> tuple:
        r = sandbox.run(
            self.image, cmd=[f"{sandbox.WORKDIR}/{exe.name}"], work=work,
            # A real network namespace, which is what makes the offline check mean
            # something. At other tiers the dependency is SUPPOSED to be fetched on first
            # run, so the network stays on.
            network=not offline,
            cache=sandbox.CACHE_COLD if offline else sandbox.CACHE_RO,
            uid=self.uid, gid=self.gid, env=self._env(), timeout=timeout)
        return _verdict_from_output(r["rc"], r["stdout"], r["stderr"], r["timed_out"],
                                    timeout, r["seconds"])


def _offline_env(cold: Path) -> dict:
    """The HOST path's approximation of offline. Not used by the container path.

    A container gets `--network none` — a real namespace, with no interface for a package to
    open a socket on. This function is what is left when the harness is run with
    --no-docker: it forces uv offline and points the proxy variables at a dead port, which
    blocks the fetch path that matters but does NOT stop a package reaching the network by
    other means. Results produced this way are marked approximate in the summary, because a
    weaker check reported in the same column as a stronger one is how evidence gets
    overstated.

    The pristine cache is the load-bearing part either way. With a warm ~/.cache/haru-pack
    the staged tree is reused and the run proves nothing about the payload.
    """
    cold.mkdir(parents=True, exist_ok=True)
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


def print_summary(results: list) -> int:
    """The table, and the process exit code. Non-zero if anything came out unexpected."""
    print(f"\n{'package':22} {'list':13} {'tier':8} {'verdict':7} {'size':>9} "
          f"{'build':>7} {'run':>6} {'offline':>8}")
    print("-" * 88)
    for r in results:
        size = f"{r['bytes'] / 1e6:.1f}MB" if r["bytes"] else "-"
        # `carried*` is not decoration. The host path cannot create a network namespace, so
        # its offline result is weaker evidence than the container path's, and printing both
        # in one column without a mark is how the weaker one gets read as the stronger one.
        carried = "carried" if r.get("offline_is_real", True) else "carried*"
        off = {True: carried, False: "FETCHED", None: "-"}[r.get("offline_ok")]
        print(f"{r['name']:22} {(r['list'] or ''):13} {(r['tier'] or ''):8} {verdict(r):7} "
              f"{size:>9} {r['build_s']:>6}s {r['run_s']:>5}s {off:>8}")

    if any(not r.get("offline_is_real", True) for r in results):
        print("\n  * approximate: produced with --no-docker, which cannot create a network "
              "namespace.\n    uv was forced offline and the proxy variables pointed at a "
              "dead port; a package\n    could still have reached the network by other means.")

    bad = [r for r in results if verdict(r) in ("FAIL", "XPASS")]
    print(f"\n{len(results) - len(bad)}/{len(results)} as expected; "
          f"results in {(OUT / 'results.json').relative_to(REPO)}")
    if bad:
        print("\nnot as expected:")
        for r in bad:
            print(f"  {verdict(r)} {r['name']}: {r['error'][:300]}")
    return 1 if bad else 0


def choose_runner(a, count: int) -> tuple:
    """(runner, description), or (None, "") after printing why it cannot run.

    The sandbox decision, made once and before anything is downloaded or executed. Its own
    function because it is the security-relevant branch in this file and should be readable
    without scrolling through argument parsing (INV-SANDBOX-01).
    """
    if a.no_docker:
        # Not a log line among log lines: this is the one moment the operator can still
        # decide they did not mean it.
        print(sandbox.host_warning(count, "third-party package(s)"), file=sys.stderr)
        haru = shutil.which("haru-pack") or str(REPO / ".venv" / "bin" / "haru-pack")
        if not Path(haru).exists() and not shutil.which("haru-pack"):
            print("haru-pack not found on PATH", file=sys.stderr)
            return None, ""
        return HostRunner(haru), f"ON THIS HOST (--no-docker), haru-pack at {haru}"

    try:
        image = sandbox.preflight(require_rootless=a.require_rootless,
                                  log=lambda m: print(m, file=sys.stderr))
    except sandbox.SandboxUnavailable as e:
        # Never a fallback to the host: that is how the safe default stops being the default.
        print(f"\nflex: {e}", file=sys.stderr)
        return None, ""
    return DockerRunner(image, os.getuid(), os.getgid()), f"in containers ({image})"


def run_one(pkg: dict, runner, timeout: int, keep: bool, offline_check: bool) -> dict:
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
           "build_s": 0.0, "run_s": 0.0, "offline_s": 0.0, "error": "", "stdout": "",
           "sandbox": runner.kind, "offline_is_real": runner.offline_is_real}

    t0 = time.monotonic()
    rc, output = runner.build(work, proj, exe, tier, timeout)
    res["build_s"] = round(time.monotonic() - t0, 1)
    if rc != 0 or not exe.exists():
        res["error"] = "build: " + output.strip()[-600:]
        return res
    res["build_ok"] = True
    res["bytes"] = exe.stat().st_size

    ok, dt, detail = runner.execute(work, exe, timeout, offline=False)
    res["run_s"], res["run_ok"] = dt, ok
    if not ok:
        res["error"] = "run: " + detail
        return res
    res["stdout"] = detail

    # The payload check. Only meaningful at thick: at other tiers the dependency is SUPPOSED
    # to be fetched at first run, so failing offline is correct behaviour, not a defect.
    if offline_check and tier == "thick":
        ok2, dt2, detail2 = runner.execute(work, exe, timeout, offline=True)
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
                    help="for thick builds, re-run with a pristine cache and no network")
    ap.add_argument("--no-docker", action="store_true",
                    help="run the packages' code DIRECTLY ON THIS HOST instead of in a "
                         "container. Prints what that puts at risk before it starts.")
    ap.add_argument("--require-rootless", action="store_true",
                    help="refuse to run against a rootful docker daemon")
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

    if a.dry_run:
        for p in pkgs:
            print(f"{p['name']:24} {p.get('list'):13} tier={p.get('tier')}"
                  f"{'  +offline' if (a.offline_check and p.get('tier') == 'thick') else ''}")
        print(f"\n{len(pkgs)} package(s); nothing was run.")
        return 0

    runner, where = choose_runner(a, len(pkgs))
    if runner is None:
        return 1

    OUT.mkdir(parents=True, exist_ok=True)
    print(f"flex: {len(pkgs)} package(s), {a.jobs} job(s), {where}\n")

    results = []
    if a.jobs > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
            futs = {ex.submit(run_one, p, runner, a.timeout, a.keep, a.offline_check): p
                    for p in pkgs}
            for f in concurrent.futures.as_completed(futs):
                r = f.result()
                results.append(r)
                print(f"  {verdict(r):5} {r['name']}")
    else:
        for p in pkgs:
            r = run_one(p, runner, a.timeout, a.keep, a.offline_check)
            results.append(r)
            print(f"  {verdict(r):5} {r['name']}")

    results.sort(key=lambda r: (r["list"] or "", r["name"]))
    (OUT / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    return print_summary(results)


if __name__ == "__main__":
    raise SystemExit(main())

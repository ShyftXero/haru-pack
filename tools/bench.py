#!/usr/bin/env python3
"""Measure haru-pack's size + startup across tiers, against a plain-Python baseline.

    uv run python tools/bench.py                      # thin, default, thick + baseline -> markdown
    uv run python tools/bench.py --tiers default,thick --runs 7 --json bench.json

What it measures, for a TRIVIAL script (so the number is launcher overhead, not app work):
  * size     — the built binary, in MB.
  * cold     — first run wall time, from an empty stage cache. For thin/default this INCLUDES the
               network fetch of uv + a standalone Python; for thick it is expand-and-stage only.
  * warm     — median of --runs subsequent runs against the now-staged tree (no extraction; the
               launcher verifies the staged tree by hash — INV-STAGE-01 — and hands off to uv).
The baseline row is `python <script>` (pure interpreter spawn) for the same script.

It is a REGRESSION GUARD as much as a brag: run it before and after a change to the staging or
build path and the warm/size columns should not move without a reason. Numbers are machine- and
network-specific; the emitted table records the host so a committed table is reproducible-in-kind.
Cold/network rows vary run-to-run; warm and size are the stable ones to gate on.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT_BODY = "print('hello from a single binary')\n"  # trivial: isolates launcher overhead


def _run_timed(argv, env=None):
    """Return (seconds, returncode, tail_of_output). Wall time of one full run."""
    t0 = time.perf_counter()
    r = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=1200)
    dt = time.perf_counter() - t0
    return dt, r.returncode, (r.stdout + r.stderr)[-400:]


def _build(script: Path, tier: str, out: Path, python: str) -> None:
    flag = {"thin": ["--thin"], "default": [], "thick": ["--thick"]}[tier]
    argv = ["uv", "run", "--quiet", "haru-pack", "build", str(script),
            "-e", script.name, "--target", "host", "--python", python, "-o", str(out), *flag]
    r = subprocess.run(argv, cwd=REPO, capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        raise RuntimeError(f"build --{tier} failed:\n{(r.stdout + r.stderr)[-1500:]}")


def _median_warm(binary: Path, cache: Path, runs: int) -> float:
    # cache is already warm (cold run staged it); time `runs` more and take the median.
    env = {**os.environ, "XDG_CACHE_HOME": str(cache)}
    samples = []
    for _ in range(runs):
        dt, rc, out = _run_timed([str(binary)], env=env)
        if rc != 0:
            raise RuntimeError(f"warm run failed (rc {rc}): {out}")
        samples.append(dt)
    return statistics.median(samples)


def bench_tier(script: Path, tier: str, python: str, runs: int, workdir: Path) -> dict:
    out = workdir / f"hello-{tier}"
    _build(script, tier, out, python)
    size_mb = out.stat().st_size / 1_000_000
    cache = workdir / f"cache-{tier}"   # a private, empty stage cache -> a true cold run
    if cache.exists():
        shutil.rmtree(cache)
    cache.mkdir()
    env = {**os.environ, "XDG_CACHE_HOME": str(cache)}
    cold, rc, out_txt = _run_timed([str(out)], env=env)
    if rc != 0:
        raise RuntimeError(f"cold run --{tier} failed (rc {rc}): {out_txt}")
    warm = _median_warm(out, cache, runs)
    return {"tier": tier, "size_mb": round(size_mb, 1),
            "cold_s": round(cold, 2), "warm_s": round(warm, 3)}


def bench_baseline(script: Path, runs: int) -> dict:
    samples = []
    for _ in range(runs + 1):
        dt, rc, out = _run_timed([sys.executable, str(script)])
        if rc != 0:
            raise RuntimeError(f"baseline run failed: {out}")
        samples.append(dt)
    return {"tier": "python <script> (baseline)", "size_mb": None,
            "cold_s": round(samples[0], 3), "warm_s": round(statistics.median(samples[1:]), 3)}


def to_markdown(rows: list, host: str, when: str) -> str:
    def cell(v):
        return "—" if v is None else (f"{v:.1f}" if isinstance(v, float) and v >= 10 else str(v))
    head = ("| tier | size | cold start | warm start |\n"
            "|---|--:|--:|--:|\n")
    body = ""
    for r in rows:
        size = "—" if r["size_mb"] is None else f"{r['size_mb']} MB"
        cold = "—" if r.get("cold_s") is None else f"{r['cold_s']}s"
        warm = f"{r['warm_s']}s"
        body += f"| {r['tier']} | {size} | {cold} | {warm} |\n"
    note = (f"\n_Measured on {host}, {when}. Cold rows for thin/default include a network fetch of "
            f"uv + a standalone Python; warm = median of the staged reuse path. Regenerate with "
            f"`uv run python tools/bench.py`._\n")
    return head + body + note


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tiers", default="thin,default,thick")
    ap.add_argument("--runs", type=int, default=5, help="warm samples per tier (median)")
    ap.add_argument("--python", default="", help="Python to stage (default: haru-pack's default)")
    ap.add_argument("--json", default="", help="also write raw results here")
    ap.add_argument("--when", default="", help="timestamp label for the table (pass one in; the "
                    "tool does not read the clock so its output is reproducible)")
    args = ap.parse_args(argv)

    python = args.python
    if not python:
        r = subprocess.run(["uv", "run", "--quiet", "python", "-c",
                            "from haru_pack.build import DEFAULT_PYTHON; print(DEFAULT_PYTHON)"],
                           cwd=REPO, capture_output=True, text=True)
        python = r.stdout.strip() or "3.13"

    with tempfile.TemporaryDirectory(prefix="haru-bench-") as td:
        work = Path(td)
        script = work / "hello.py"
        script.write_text(SCRIPT_BODY)
        rows = []
        for tier in [t.strip() for t in args.tiers.split(",") if t.strip()]:
            print(f"==> benching --{tier} (build + cold + {args.runs} warm) ...", file=sys.stderr)
            try:
                rows.append(bench_tier(script, tier, python, args.runs, work))
            except Exception as e:  # a tier that cannot build/run is reported, not fatal
                print(f"    SKIP --{tier}: {e}", file=sys.stderr)
        rows.append(bench_baseline(script, args.runs))

    host = f"{platform.system()} {platform.machine()}, Python {python} staged"
    when = args.when or "see git history"
    md = to_markdown(rows, host, when)
    print(md)
    if args.json:
        Path(args.json).write_text(json.dumps({"host": host, "when": when, "rows": rows}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

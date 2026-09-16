#!/usr/bin/env python3
"""What files does this command ACTUALLY open? — the diagnostic behind `--shake`.

Run any command under `strace -e trace=%file`, then report, for a directory you name,
which files it touched and which it did not, biggest-unused first. This is the general
form of the question `--shake` asks about a payload, and it is worth having standalone
because it answers a much broader family of questions:

    # why is my venv/image/payload this big, and what of it is dead weight?
    tools/file-trace.py --root .venv/lib/python3.12/site-packages -- pytest -q

    # which of these bundled shared libraries does the program really load?
    tools/file-trace.py --root vendor --only '*.so*' -- ./myapp

    # debug a --shake that pruned something it should not have
    tools/file-trace.py --root payload/vendor/cache -- python -m myapp --selftest

Why syscall tracing and not `coverage.py`: line coverage sees executed *Python lines* in
*.py files*. It cannot see a data file being read, a template, a model weight, a locale, a
certificate bundle, or — the one that matters most — a shared library `dlopen`ed from
inside a C extension. Those are exactly where the megabytes are. `slim` (formerly
docker-slim) makes the same choice for container images for the same reason.

Two things this tool learned the hard way, both preserved in the code below:

  * **Normalize the paths.** A manylinux wheel that vendors its libraries links them with
    an `$ORIGIN` RPATH, so the loader opens them through the package:
    `site-packages/numpy/_core/../../numpy.libs/libscipy_openblas64_-f48b354e.so`. Compare
    that string against a file listing and it matches nothing, so the library looks unused.
  * **Drop the failed calls.** Every import probes a dozen `sys.path` candidates. Keeping
    the `ENOENT` ones tells you nothing and manufactures phantom dependencies.

Linux only (strace). `--audit` uses a Python audit hook instead, which needs no strace and
no privileges but cannot see a C extension's own `dlopen` — the report says which ran.
"""
from __future__ import annotations

import argparse, fnmatch, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

PATH_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
FAIL_RE = re.compile(r"=\s*-1\s")

AUDIT_HOOK = '''\
import os, sys
_p = os.environ.get("FILE_TRACE_OUT")
if _p:
    try:
        _f = open("%s.%d" % (_p, os.getpid()), "a", buffering=1)
    except OSError:
        _f = None
    if _f is not None:
        def _hook(event, args):
            try:
                if event in ("open", "ctypes.dlopen", "ctypes.LoadLibrary"):
                    p = args[0]
                    if isinstance(p, bytes):
                        p = p.decode("utf-8", "replace")
                    if isinstance(p, str):
                        _f.write(p + "\\n")
            except Exception:
                pass
        sys.addaudithook(_hook)
'''


def parse_strace(path: Path) -> set:
    out = set()
    with path.open(errors="replace") as fh:
        for line in fh:
            if FAIL_RE.search(line):      # a failed probe is not a dependency
                continue
            for m in PATH_RE.finditer(line):
                s = m.group(1)
                if s.startswith("/"):
                    out.add(os.path.normpath(s))   # collapse $ORIGIN-relative `../..`
    return out


def trace(cmd: list, use_audit: bool) -> tuple:
    with tempfile.TemporaryDirectory(prefix="file-trace-") as td:
        out = Path(td) / "trace.txt"
        env = dict(os.environ)
        argv, how = list(cmd), "audit"
        if not use_audit and shutil.which("strace"):
            argv = ["strace", "-f", "-qq", "-s", "8192", "-e", "trace=%file",
                    "-o", str(out), *cmd]
            how = "strace"
        else:
            hook = Path(td) / "ft_hook.py"
            hook.write_text(AUDIT_HOOK)
            (Path(td) / "zzz-ft.pth").write_text("import ft_hook\n")
            env["PYTHONPATH"] = td + os.pathsep + env.get("PYTHONPATH", "")
            env["FILE_TRACE_OUT"] = str(out)
        rc = subprocess.run(argv, env=env).returncode
        seen = parse_strace(out) if how == "strace" and out.exists() else set()
        for extra in Path(td).glob("trace.txt.*"):
            seen |= {os.path.normpath(ln.strip())
                     for ln in extra.read_text(errors="replace").splitlines()
                     if ln.strip().startswith("/")}
        return seen, how, rc


def main() -> int:
    ap = argparse.ArgumentParser(
        description="report which files under --root a command opens, and which it does not")
    ap.add_argument("--root", required=True, type=Path,
                    help="directory to account for (a venv, a payload, vendor/, ...)")
    ap.add_argument("--only", default="*", help="glob limiting which files are accounted")
    ap.add_argument("--top", type=int, default=25, help="how many unused files to list")
    ap.add_argument("--audit", action="store_true",
                    help="use the Python audit hook instead of strace (misses C dlopen)")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        ap.error("give a command after `--`")

    root = a.root.resolve()
    seen, how, rc = trace(cmd, a.audit)
    files = [p for p in root.rglob("*")
             if p.is_file() and fnmatch.fnmatch(p.name, a.only)]
    used = [p for p in files if str(p.resolve()) in seen]
    unused = sorted((p for p in files if str(p.resolve()) not in seen),
                    key=lambda p: -p.stat().st_size)

    tot = sum(p.stat().st_size for p in files) or 1
    dead = sum(p.stat().st_size for p in unused)
    print(f"\ntracer          {how}"
          f"{'   (cannot see a C extension dlopen)' if how == 'audit' else ''}")
    print(f"command exited  {rc}")
    print(f"paths traced    {len(seen)}")
    print(f"under {root}:")
    print(f"  touched       {len(used):6}  {(tot - dead) / 1e6:8.1f} MB")
    print(f"  untouched     {len(unused):6}  {dead / 1e6:8.1f} MB   "
          f"({100 * dead / tot:.0f}% of the tree)")
    if rc != 0:
        print("\nWARNING: the command failed, so everything after the failure went "
              "unexecuted and is reported as untouched. Treat this run as unusable.")
    print(f"\nbiggest untouched files (top {a.top}):")
    for p in unused[:a.top]:
        print(f"  {p.stat().st_size / 1e6:8.2f} MB  {p.relative_to(root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

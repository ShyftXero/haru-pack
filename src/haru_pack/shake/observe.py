"""Phase 1 — run the suite and record every path the interpreter actually opened.

`strace -e trace=%file` when available, because it sees `dlopen` from inside a C extension
and every data file read — the two things line coverage cannot see. A Python audit hook is
the fallback, and its blind spot is recorded in the report rather than papered over.

Split out of shake.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import ShakeConfig, ShakeError


_STRACE_PATH_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_STRACE_FAIL_RE = re.compile(r"=\s*-1\s")

_TRACE_HOOK = '''\
# Written by haru-pack --shake. Records every path this interpreter opens, so a build can
# tell which bundled files the program actually needs. Build-time only; never shipped.
import os, sys
_dir = os.environ.get("HARU_SHAKE_TRACE")
if _dir:
    try:
        _f = open(os.path.join(_dir, "audit-%d.txt" % os.getpid()), "a", buffering=1)
    except OSError:
        _f = None
    if _f is not None:
        def _haru_hook(event, args):
            # Writing through an already-open file object raises no `open` audit event,
            # so this cannot recurse.
            try:
                if event == "open" or event == "ctypes.dlopen" or event == "ctypes.LoadLibrary":
                    p = args[0]
                    if isinstance(p, bytes):
                        p = p.decode("utf-8", "replace")
                    if isinstance(p, str):
                        _f.write(p + "\\n")
                elif event == "exec" or event == "import":
                    pass
            except Exception:
                pass
        sys.addaudithook(_haru_hook)
'''


def _install_audit_hook(env_dir: Path) -> None:
    """Arm the fallback tracer inside an env we own.

    A `.pth` rather than a `sitecustomize.py`: a `.pth` whose line starts with `import`
    executes at interpreter start and cannot shadow a `sitecustomize` the project itself
    ships. Nothing here reaches the payload — the env is a build-time throwaway.
    """
    for sp in _site_packages(env_dir):
        (sp / "haru_shake_trace.py").write_text(_TRACE_HOOK, encoding="utf-8")
        (sp / "zzz-haru-shake.pth").write_text("import haru_shake_trace\n", encoding="utf-8")


def _site_packages(env_dir: Path) -> list:
    out = [p for p in env_dir.glob("lib/python*/site-packages") if p.is_dir()]
    out += [p for p in env_dir.glob("Lib/site-packages") if p.is_dir()]
    return out


def _tracer() -> str:
    """`strace` if we have it, else the in-process audit hook.

    Preference is not a style choice. strace sees `openat` from anywhere in the process
    tree, which is the only way to observe a C extension's own `dlopen` — the exact case
    that makes torch's CUDA libraries prunable. The audit hook cannot see it, so a payload
    shaken without strace keeps native libraries it might not need, and the report says so.
    """
    return "strace" if shutil.which("strace") else "audit"


def _observe(cfg: ShakeConfig, obs_env: Path, app_dir: Path, py: Path,
             log=None) -> tuple:
    """Run the declared commands under a tracer. Returns (observed_paths, runs, tracer)."""
    say = log or (lambda _m: None)
    tracer = _tracer()
    if tracer == "audit":
        _install_audit_hook(obs_env)
    observed: set = set()
    runs = []
    bindir = obs_env / ("Scripts" if sys.platform == "win32" else "bin")
    commands = [list(cfg.test), *[list(c) for c in cfg.also_run]]
    with tempfile.TemporaryDirectory(prefix="haru-shake-trace-") as td:
        tdp = Path(td)
        for i, cmd in enumerate(commands):
            env = dict(os.environ)
            env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
            env["VIRTUAL_ENV"] = str(obs_env)
            env["HARU_SHAKE_TRACE"] = str(tdp)
            env["NO_COLOR"] = "1"
            env.pop("PYTHONHOME", None)
            # A shake is only as good as the run that informs it, and a suite that skips
            # half its tests because an env var was missing produces a confidently wrong
            # keep set. Deselection is the operator's business, so nothing is filtered here.
            trace_out = tdp / f"strace-{i}.txt"
            argv = list(cmd)
            if tracer == "strace":
                argv = ["strace", "-f", "-qq", "-s", "8192", "-e", "trace=%file",
                        "-o", str(trace_out), *cmd]
            say(f"shake: observing `{' '.join(cmd)}` under {tracer}")
            r = subprocess.run(argv, cwd=str(app_dir), env=env,
                               capture_output=True, text=True)
            runs.append({"command": cmd, "exit": r.returncode,
                         "tail": (r.stdout or r.stderr or "")[-800:]})
            if r.returncode != 0:
                raise ShakeError(
                    f"the observation run `{' '.join(cmd)}` failed (exit {r.returncode}) "
                    f"before anything was pruned.\n\nA failing suite cannot tell haru-pack "
                    f"which files the program needs — everything after the failure went "
                    f"unobserved and would look prunable. Fix the run, then rebuild.\n\n"
                    + (r.stdout or r.stderr or "")[-1500:])
            if tracer == "strace":
                observed |= _parse_strace(trace_out)
        for f in tdp.glob("audit-*.txt"):
            observed |= {_normalize(ln.strip())
                         for ln in f.read_text(errors="replace").splitlines()
                         if ln.strip().startswith("/")}
    return observed, runs, tracer


def _parse_strace(path: Path) -> set:
    """Every path argument of a SUCCEEDING file syscall in a trace.

    Failed calls are dropped: an interpreter probing a dozen `sys.path` entries for a
    module tells us nothing about which one it found, and keeping ENOENT paths would keep
    files that do not exist anyway. Truncated strings (strace `-s`) are kept — a truncated
    path is a path we cannot map, and losing it is safer than mapping it wrong, so it is
    simply left out of the keep set by failing to match any real file.
    """
    out: set = set()
    if not path.exists():
        return out
    with path.open(errors="replace") as fh:
        for line in fh:
            if _STRACE_FAIL_RE.search(line):
                continue
            for m in _STRACE_PATH_RE.finditer(line):
                s = m.group(1)
                if s.startswith("/"):
                    out.add(_normalize(s))
    return out


def _normalize(p: str) -> str:
    """Collapse `..` out of a traced path before anything tries to map it.

    This is not tidiness, it is the difference between `--shake` working on a scientific
    wheel and silently breaking it. A manylinux wheel that vendors its shared libraries
    links them with an `$ORIGIN`-relative RPATH, so the dynamic loader opens them by a path
    that walks back out through the package:

        .../site-packages/numpy/_core/../../numpy.libs/libscipy_openblas64_-f48b354e.so

    Un-normalized, that produces the relpath `numpy/_core/../../numpy.libs/...`, which
    matches nothing in the archive tree — so the library looks untouched and gets pruned,
    and the payload dies at `import numpy`. numpy, scipy, torch, pillow and lxml all use
    this pattern. Caught by the verify step on the first real end-to-end run, 2026-09-10,
    with numpy's own "Original error was: libscipy_openblas64_-f48b354e.so: cannot open
    shared object file".
    """
    return os.path.normpath(_unescape(p))


def _unescape(s: str) -> str:
    """Undo strace's C-style escaping of a path."""
    if "\\" not in s:
        return s
    try:
        return s.encode("latin-1", "backslashreplace").decode("unicode_escape")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return s

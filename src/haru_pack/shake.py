"""`--shake` — drop payload files the project's own test suite proves it never touches.

The idea, and the reason it is not just "delete what looks unused": a `--thick` payload
carries an entire dependency closure because that is what the tier promises, but a closure
resolved by a *resolver* is much larger than the set of files a *program* opens. Torch is
the canonical case — the wheel is gigabytes of CUDA kernels and a CPU-only inference app
dlopens none of them. Docker's `slim` makes the same bet for container images, and makes it
the same way: **observe** a real execution, keep what was touched, verify the result still
works. It does not read the code and reason about it.

So this module is three phases, and the third is not optional:

1. **Observe.** Run the project's declared test command (plus any extra smoke runs) against
   the *bundled* interpreter and an env built from the *bundled* cache, under a file-access
   tracer. `strace -e trace=%file` when available, because it sees `dlopen` from inside a C
   extension and every data file read — the two things line coverage cannot see. A Python
   audit hook is the fallback and its blind spot is recorded in the report.
2. **Prune.** Intersect the observed set with rules that keep things whose absence breaks
   importability rather than a feature (`*.dist-info`, `__init__.py` on a retained path, the
   static closure of every *lazy* import inside a kept module). Files go to a quarantine
   dir, not to `unlink`.
3. **Verify.** Build a fresh env from the pruned cache, offline, exactly as the target will
   — then re-run the test suite against it. A shaken payload is never emitted without this
   passing (INV-SHAKE-01), because the failure mode of guessing wrong here is an
   `ImportError` on a customer machine at first run, which is the worst place to find out.

What this deliberately does NOT claim: that a passing test suite proves runtime safety. A
suite that never exercises a code path is evidence about the suite, not about the program.
`--shake` is opt-in for that reason, it refuses to run without a declared test command
(INV-SHAKE-03), and it writes down every file it removed so an operator debugging a field
failure has something better than a bisect.
"""
from __future__ import annotations

import ast, fnmatch, json, os, re, shutil, subprocess, sys, tempfile
from dataclasses import dataclass, field
from pathlib import Path


class ShakeError(RuntimeError):
    """A shake could not be performed, or could not be proven safe. Always fatal."""


# ---------------------------------------------------------------------------- cache buckets
#
# uv's cache is several independently-versioned buckets. Which ones a runtime `uv sync
# --frozen --offline` actually needs was determined empirically on 2026-09-10 (uv 0.10.4)
# by deleting each bucket from a warmed cache and re-syncing into a fresh env:
#
#   archive-v0     REQUIRED  unpacked wheel trees; this is what gets linked into the venv
#   wheels-v6      REQUIRED  without it: "Failed to download werkzeug==3.1.8 ... wasn't
#                            found in the cache"
#   sdists-v9      kept      empty for wheel-only projects, load-bearing for sdist deps
#   simple-v20     DROPPED   PyPI index responses. 4.4 MB on a five-dependency project.
#                            Only a *resolve* reads them and thick resolves at build time.
#   builds-v0      DROPPED   build backend scratch
#   interpreter-v4 DROPPED   cached interpreter probes — and they embed the BUILD HOST's
#                            absolute paths (`/home/<operator>`) in a payload that gets
#                            shipped and signed. Dropping it is a size win and a hygiene
#                            one; cf. INV-PAYLOAD-01.
#
# Matched by prefix because the version suffix moves with uv. An UNRECOGNISED bucket is
# KEPT: a future uv that stores something load-bearing under a new name must not be
# silently pruned by a rule written before it existed.
_CACHE_KEEP_PREFIXES = ("archive-", "wheels-", "sdists-")
_CACHE_DROP_PREFIXES = ("simple-", "builds-", "interpreter-")


# ------------------------------------------------------------------- interpreter rulepack
#
# The bundled standalone Python is pruned by RULE, not by observation, and that asymmetry
# is deliberate. The stdlib is where lazy and conditional imports are densest (`encodings`
# resolved by name at runtime, `ctypes` reaching for `lib-dynload`, codecs chosen by
# locale), so "delete every stdlib file the test run did not open" buys tens of megabytes
# and risks a failure the suite cannot see. These entries are things that cannot be
# imported at all, or that exist to *build* against the interpreter rather than run on it.
_PY_DROP_ALWAYS = (
    "lib/python*/test/*",              # CPython's own regression suite
    "lib/python*/*/test/*",
    "lib/python*/idlelib/*",           # the bundled IDE
    "lib/python*/turtledemo/*",
    "lib/python*/pydoc_data/*",         # topic text for interactive help()
    "lib/python*/ensurepip/_bundled/*",  # a whole bundled pip wheel (~2.1 MB)
    "lib/python*/config-*/*",          # Makefile + libpython*.a: for compiling extensions
    "include/*",                        # C headers, same reason
    "share/man/*", "share/doc/*", "share/terminfo/*",
    "lib/*.a", "lib/*.o",
)
# Dropped only when the observation run never touched the feature. Tk is a 10-20 MB family
# spread across the stdlib, lib-dynload and `lib/`, and a GUI app must keep all of it.
_PY_DROP_UNLESS_OBSERVED = {
    "tkinter": ("lib/python*/tkinter/*", "lib/python*/lib-dynload/_tkinter*",
                "lib/libtcl*", "lib/libtk*", "lib/tcl8*", "lib/tk8*", "lib/itcl*",
                "lib/tdbc*", "lib/thread2*", "lib/libBLT*"),
    "lib2to3": ("lib/python*/lib2to3/*",),
    "sqlite3": (),        # intentionally empty: named here so nobody "optimises" it in
}                          # later. sqlite3 is small and reached by lazy import constantly.

# Never pruned from a dependency tree, whatever the tracer saw. These are not features, they
# are the machinery that makes a package findable: `importlib.metadata`, entry points and
# `uv`'s own install bookkeeping all read `*.dist-info`, and a `.pth` runs at interpreter
# start. `*.data/` holds the wheel's non-purelib payload (scripts, headers, shared data);
# it is small and getting it wrong is silent, so it stays whole.
_DIST_ALWAYS_KEEP_DIRS = (".dist-info", ".data", ".egg-info")
_DIST_ALWAYS_KEEP_GLOBS = ("*.pth", "*/py.typed", "py.typed")


@dataclass
class ShakeConfig:
    """Resolved `[shake]` block. `test` is mandatory — see INV-SHAKE-03."""
    test: list = field(default_factory=list)
    also_run: list = field(default_factory=list)
    keep: list = field(default_factory=list)
    follow_lazy_imports: bool = True
    shake_interpreter: bool = True


def resolve_config(app_dir: Path, decl: dict, cli_keep=()) -> ShakeConfig:
    """Work out how to *observe* this project, or refuse.

    A shake with no observation is a shake with no evidence, and a deletion with no
    evidence is exactly the class of bug this repo refuses to ship (INV-SHAKE-03). So the
    absence of a test command is a hard error with instructions, not a fallback to some
    default "probably fine" rulepack.
    """
    sh = dict(decl.get("shake") or {})
    test = list(sh.get("test") or [])
    if not test and _has_pytest_config(app_dir):
        test = ["pytest"]
    if not test:
        raise ShakeError(
            "--shake needs a test command to observe, and this project does not declare "
            "one.\nAdd it to haru_pack.toml:\n\n"
            "    [shake]\n    test = [\"pytest\", \"-q\"]\n\n"
            "haru-pack will not delete files from a payload on the strength of a guess "
            "about what the program needs. If the project has no suite, build without "
            "--shake.")
    also = [list(c) if isinstance(c, (list, tuple)) else [c] for c in (sh.get("also_run") or [])]
    return ShakeConfig(test=test, also_run=also,
                       keep=[*(sh.get("keep") or []), *cli_keep],
                       follow_lazy_imports=bool(sh.get("follow_lazy_imports", True)),
                       shake_interpreter=bool(sh.get("shake_interpreter", True)))


def _has_pytest_config(app_dir: Path) -> bool:
    """Does the project configure pytest, or at least have somewhere for it to look?

    A bare `tests/` directory counts. `[tool.pytest.ini_options]` in pyproject.toml counts.
    A `pytest.ini`/`tox.ini`/`setup.cfg` is not parsed for a pytest section — presence of
    the file plus a test directory is enough of a signal, and a wrong guess here only ever
    produces "no tests ran", which the verify phase reports as a failure.
    """
    if (app_dir / "tests").is_dir() or (app_dir / "test").is_dir():
        return True
    if (app_dir / "pytest.ini").exists():
        return True
    pp = app_dir / "pyproject.toml"
    if pp.exists():
        try:
            return "[tool.pytest.ini_options]" in pp.read_text(encoding="utf-8")
        except OSError:
            return False
    return False


# ------------------------------------------------------------------------------- observing

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


# --------------------------------------------------------------------- the dependency side

@dataclass
class Archive:
    """One unpacked wheel tree in `vendor/cache/archive-v0/<opaque-id>/`."""
    root: Path
    dist: str = ""
    version: str = ""

    def files(self) -> list:
        return [p for p in self.root.rglob("*") if p.is_file() or p.is_symlink()]


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _index_archives(cache_dir: Path) -> list:
    """Identify each cached wheel tree by reading its own `*.dist-info/METADATA`.

    The directory names under `archive-v0/` are content-addressed and opaque, so the dist
    name has to come from inside the tree. A tree with no readable METADATA is returned
    with an empty `dist`, which makes it unmatchable against the runtime resolution and
    therefore never wholesale-dropped — unknown means keep.
    """
    root = None
    for d in sorted(cache_dir.iterdir()) if cache_dir.is_dir() else []:
        if d.is_dir() and d.name.startswith("archive-"):
            root = d
            break
    if root is None:
        return []
    out = []
    for tree in sorted(p for p in root.iterdir() if p.is_dir()):
        a = Archive(root=tree)
        for di in tree.glob("*.dist-info"):
            meta = di / "METADATA"
            if not meta.exists():
                continue
            for line in meta.read_text(errors="replace").splitlines():
                if line.startswith("Name:") and not a.dist:
                    a.dist = _canon(line.split(":", 1)[1].strip())
                elif line.startswith("Version:") and not a.version:
                    a.version = line.split(":", 1)[1].strip()
                if a.dist and a.version:
                    break
            break
        out.append(a)
    return out


def _runtime_dists(app_dir: Path) -> set:
    """The dists a shipped binary can possibly import: the `--no-dev` resolution.

    This is what makes `--shake` safe against its own instrument. The observation run is a
    pytest run, so pytest, its plugins and every dev-group dependency get *touched* and
    would otherwise look load-bearing. They are not — they are the measuring device. Any
    cached tree outside this set is dropped whole rather than pruned by observation.
    (`uv sync`, which warms the cache, installs the default groups — `dev` included — so
    these trees really are in the payload today.)
    """
    r = subprocess.run(["uv", "export", "--project", str(app_dir), "--no-dev",
                        "--no-hashes", "--no-header", "--no-emit-project",
                        "--format", "requirements-txt"],
                       capture_output=True, text=True, env=dict(os.environ, NO_COLOR="1"))
    if r.returncode != 0:
        raise ShakeError("could not determine the runtime dependency set "
                         f"(`uv export --no-dev` failed):\n{(r.stderr or r.stdout)[-800:]}")
    out = set()
    for line in r.stdout.splitlines():
        s = line.strip()
        if not s or s.startswith(("#", "-", "\t")):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)", s)
        if m:
            out.add(_canon(m.group(1)))
    # `--no-emit-project` leaves the project's OWN distribution out of the export, and a
    # packaged project is installed from a wheel of itself that uv built into the cache.
    # Without this line that wheel looks dev-only and gets dropped whole — caught by the
    # verify step on the first real run (2026-09-10), which refused to ship and named the
    # missing METADATA. Keeping the flag and adding the name back is deliberate: the
    # alternative spelling emits a `-e .` line that says nothing about the dist name.
    own = _project_name(app_dir)
    if own:
        out.add(own)
    return out


def _project_name(app_dir: Path) -> str:
    """`[project].name`, canonicalised. Read directly rather than asked of uv, because
    this has to work even when the export above is what we are correcting."""
    pp = app_dir / "pyproject.toml"
    if not pp.exists():
        return ""
    try:
        from . import tomlio
        return _canon(str((tomlio.load(pp).get("project") or {}).get("name") or ""))
    except Exception:
        return ""


def _observed_relpaths(observed: set, obs_env: Path) -> set:
    """Map traced absolute paths to paths relative to a wheel root.

    A wheel's archive tree is rooted where site-packages is rooted, so
    `<env>/lib/python3.12/site-packages/jinja2/loaders.py` and
    `archive-v0/<id>/jinja2/loaders.py` share the relative path `jinja2/loaders.py`. That
    is the whole mapping — no inode games, no hash matching, and it holds whether uv
    hardlinked or copied the file into the env.
    """
    sps = [str(sp) + os.sep for sp in _site_packages(obs_env)]
    out = set()
    for p in observed:
        for sp in sps:
            if p.startswith(sp):
                out.add(p[len(sp):].replace(os.sep, "/"))
                break
    return out


def _module_index(archives: list) -> dict:
    """relpath -> Archive, for resolving an import name to a file we hold."""
    idx = {}
    for a in archives:
        for f in a.files():
            idx[f.relative_to(a.root).as_posix()] = a
    return idx


def _lazy_import_closure(keep: set, index: dict, log=None) -> set:
    """Add every module importable *from inside* a kept module, exercised or not.

    This is the safety net for the break that observation cannot see:

        def upload(path):
            import boto3            # never called by the test suite

    A module-level import always runs when its module is imported, so the tracer already
    saw it. A function-level one did not, and deleting its target turns a working feature
    into an `ImportError` on the customer's machine. So every kept `.py` is parsed and ALL
    of its import statements — at any nesting depth — are resolved against the files we
    hold, transitively.

    Note what this does not pull back: a `.so`, a model weight, a bundled browser. Nothing
    reaches those through an `import` statement, so the closure protects importability
    while leaving the gigabyte-scale native payload prunable. That asymmetry is why
    `--shake` can be both conservative and worth running.
    """
    say = log or (lambda _m: None)
    frontier = {r for r in keep if r.endswith(".py")}
    seen_src: set = set()
    added: set = set()
    while frontier:
        rel = frontier.pop()
        if rel in seen_src:
            continue
        seen_src.add(rel)
        a = index.get(rel)
        if a is None:
            continue
        try:
            tree = ast.parse((a.root / rel).read_text(errors="replace"), filename=rel)
        except (SyntaxError, ValueError, OSError):
            continue                      # a py2 file or a stub; nothing to learn from it
        pkg = rel.rsplit("/", 1)[0] if "/" in rel else ""
        if rel.endswith("/__init__.py"):
            pkg = rel[: -len("/__init__.py")]
        elif rel == "__init__.py":
            pkg = ""
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [al.name for al in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:            # relative: `from ..pkg import x`
                    parts = pkg.split("/") if pkg else []
                    parts = parts[: len(parts) - (node.level - 1)] if node.level > 1 else parts
                    base = "/".join([*parts, *(base.split(".") if base else [])]).replace("/", ".")
                names = [base] if base else []
                names += [f"{base}.{al.name}" for al in node.names if base]
            for name in names:
                for cand in _candidates(name):
                    if cand in index and cand not in keep:
                        keep.add(cand); added.add(cand)
                        if cand.endswith(".py"):
                            frontier.add(cand)
    if added:
        say(f"shake: lazy-import closure kept {len(added)} additional file(s)")
    return keep


def _candidates(dotted: str) -> list:
    """The files a dotted module name could live in, inside a wheel root."""
    if not dotted:
        return []
    base = dotted.replace(".", "/")
    return [f"{base}.py", f"{base}/__init__.py", f"{base}.pyd",
            f"{base}.so", f"{base}.abi3.so"]


def _always_keep(rel: str, keep_globs) -> bool:
    parts = rel.split("/")
    if any(p.endswith(_DIST_ALWAYS_KEEP_DIRS) for p in parts):
        return True
    for g in (*_DIST_ALWAYS_KEEP_GLOBS, *keep_globs):
        if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(parts[-1], g):
            return True
    return False


def _retain_package_inits(keep: set, index: dict) -> set:
    """Keep the `__init__.py` of every package on the path to a kept file.

    `import a.b.c` executes `a/__init__.py` and `a/b/__init__.py` first. The tracer
    normally sees those, but a file reached only through the lazy-import closure has no
    observation behind it, and a package directory missing its `__init__.py` is not a
    package — the import fails with a message that names the leaf, not the missing file.
    """
    extra = set()
    for rel in list(keep):
        parts = rel.split("/")[:-1]
        for i in range(len(parts)):
            cand = "/".join(parts[: i + 1]) + "/__init__.py"
            if cand in index:
                extra.add(cand)
    return keep | extra


# --------------------------------------------------------------------------------- pruning

def _quarantine(src: Path, root: Path, qroot: Path) -> int:
    """Move one file out of the payload, preserving its path under the quarantine root."""
    rel = src.relative_to(root)
    dest = qroot / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    n = src.stat().st_size if not src.is_symlink() else 0
    shutil.move(str(src), str(dest))
    return n


def _prune_cache_buckets(cache_dir: Path, qroot: Path, log=None) -> tuple:
    say = log or (lambda _m: None)
    dropped, freed = [], 0
    for d in sorted(cache_dir.iterdir()) if cache_dir.is_dir() else []:
        if not d.is_dir():
            continue
        if d.name.startswith(_CACHE_KEEP_PREFIXES):
            continue
        if not d.name.startswith(_CACHE_DROP_PREFIXES):
            say(f"shake: keeping unrecognised uv cache bucket {d.name!r} "
                f"(no rule says it is safe to drop)")
            continue
        for f in sorted(p for p in d.rglob("*") if p.is_file()):
            freed += _quarantine(f, cache_dir.parent.parent, qroot)
            dropped.append(f)
        shutil.rmtree(d, ignore_errors=True)
    return dropped, freed


def _prune_interpreter(pydir: Path, payload: Path, qroot: Path, observed: set,
                       keep_globs, log=None) -> tuple:
    """Apply the static rulepack to the bundled standalone Python."""
    say = log or (lambda _m: None)
    obs_blob = "\n".join(sorted(observed))
    globs = list(_PY_DROP_ALWAYS)
    for feature, pats in _PY_DROP_UNLESS_OBSERVED.items():
        if not pats:
            continue
        if re.search(rf"/{re.escape(feature)}(/|\.py|\b)", obs_blob):
            say(f"shake: keeping {feature} — the observation run used it")
            continue
        globs += list(pats)
    dropped, freed = [], 0
    for f in sorted(p for p in pydir.rglob("*") if p.is_file()):
        rel = f.relative_to(pydir).as_posix()
        cands = _suffixes(rel)
        if any(fnmatch.fnmatch(c, g) for c in cands for g in keep_globs):
            continue
        if any(fnmatch.fnmatch(c, g) for c in cands for g in globs):
            freed += _quarantine(f, payload, qroot)
            dropped.append(f)
    return dropped, freed


def _suffixes(rel: str) -> list:
    """Every path-component suffix of `rel`, so a rule can be written prefix-free.

    python-build-standalone's archive extracts to a `python/` directory, and some layouts
    add an `install/` level under that, so the interpreter actually lands at
    `vendor/python/python/lib/python3.12/...`. The first version of the rulepack matched
    against the full relative path and therefore matched NOTHING — the interpreter came
    through a `--shake` untouched and the saving was silently zero. Rules are written
    against the prefix that is stable (`lib/python*/test/*`) and matched against every
    suffix, so a new upstream layout cannot quietly disable them.
    """
    parts = rel.split("/")
    return ["/".join(parts[i:]) for i in range(len(parts))]


def _prune_dependencies(archives: list, payload: Path, qroot: Path, keep: set,
                        runtime: set, keep_globs, own: str = "", log=None) -> tuple:
    say = log or (lambda _m: None)
    dropped, freed = [], 0
    per_dist = {}
    # Relpaths pruned from dists that ARE in the runtime resolution. Only these have to
    # stay missing from the verification env (INV-SHAKE-02): a dev-only tree is dropped
    # *because* it is the measuring device, and the verify step installs the test tooling
    # back on purpose, so including those paths made the absence check fire on every real
    # project. Found on the first end-to-end run, 2026-09-10 — 491 false positives, all of
    # them `_pytest/**`.
    runtime_dropped: set = set()
    for a in archives:
        whole = bool(a.dist) and a.dist not in runtime
        if whole:
            say(f"shake: {a.dist} {a.version} is not in the runtime resolution "
                f"(dev-only) — dropping the whole tree")
        if own and a.dist == own:
            # The project's OWN code is never file-pruned. It is small, it is the part the
            # operator wrote, and it is the part whose untested branches they are most
            # likely to know about and least likely to expect a packager to delete. The
            # size in a thick payload is in the dependencies and the interpreter, so
            # exempting it costs nothing worth having.
            say(f"shake: keeping all of {a.dist} — the project's own code is not pruned")
            per_dist[a.dist] = {"kept": len(a.files()), "dropped": 0, "dropped_bytes": 0}
            continue
        for f in a.files():
            rel = f.relative_to(a.root).as_posix()
            st = per_dist.setdefault(a.dist or a.root.name,
                                     {"kept": 0, "dropped": 0, "dropped_bytes": 0})
            if not whole and (rel in keep or _always_keep(rel, keep_globs)):
                st["kept"] += 1
                continue
            n = _quarantine(f, payload, qroot)
            freed += n
            st["dropped"] += 1
            st["dropped_bytes"] += n
            dropped.append(f)
            if not whole:
                runtime_dropped.add(rel)
    return dropped, freed, per_dist, runtime_dropped


# -------------------------------------------------------------------------------- verifying

def _verify(app_dir: Path, cache_dir: Path, py: Path, cfg: ShakeConfig, workdir: Path,
            dropped_rel: set, sources=None, log=None) -> dict:
    """Rebuild the runtime env from the PRUNED cache, offline, then re-run the suite.

    Two things are being proven, and the second is the one that is easy to get wrong:

    1. The pruned cache still installs offline — the same `uv sync` the launcher does on
       the target, with `UV_OFFLINE=1` and the bundled interpreter.
    2. The suite passes *against a tree that really is missing the pruned files*. The test
       tooling is installed from the BUILD HOST's cache afterwards (network allowed; it is
       build-time only, and it must not come from the payload since we just deleted it from
       there). A dev dependency that pins a different version of a runtime dist can make uv
       reinstall it — unpruned — and the suite would then pass against files the customer
       will not have. So the pruned paths are re-checked for absence before the suite runs
       (INV-SHAKE-02). A false green here is worse than no verification at all: it converts
       "we did not check" into "we checked and it was fine".
    """
    say = log or (lambda _m: None)
    venv = workdir / "shake-verify"
    shutil.rmtree(venv, ignore_errors=True)
    base = dict(os.environ, NO_COLOR="1", UV_PYTHON_DOWNLOADS="never")
    off = dict(base, UV_CACHE_DIR=str(cache_dir), UV_OFFLINE="1",
               UV_PROJECT_ENVIRONMENT=str(venv), UV_PYTHON=str(py))
    r = subprocess.run(["uv", "sync", "--project", str(app_dir), "--frozen", "--no-dev"],
                       env=off, capture_output=True, text=True)
    if r.returncode != 0:
        raise ShakeError(
            "the shaken payload no longer installs offline — `uv sync --frozen --no-dev` "
            "failed against the pruned cache, which is exactly what the target does on "
            f"first run:\n\n{(r.stderr or r.stdout)[-1500:]}\n\n"
            "Nothing was shipped. A uv cache bucket this build needs is being dropped; "
            "report it, and build without --shake meanwhile.")

    vpy = _env_python(venv)
    # Test tooling, from OUTSIDE the payload. `--inexact`-style: pip install leaves the
    # already-satisfied runtime dists alone, which is what the absence check below confirms.
    dev = subprocess.run(["uv", "export", "--project", str(app_dir), "--only-dev",
                          "--no-hashes", "--no-header", "--no-emit-project",
                          "--format", "requirements-txt"],
                         env=base, capture_output=True, text=True)
    reqs = [ln.strip() for ln in dev.stdout.splitlines()
            if ln.strip() and not ln.strip().startswith(("#", "-"))]
    if reqs:
        rf = workdir / "shake-dev-reqs.txt"
        rf.write_text("\n".join(reqs) + "\n")
        idx = list(sources.uv_index_args()) if sources is not None else []
        r = subprocess.run(["uv", "pip", "install", "--python", str(vpy), *idx,
                            "-r", str(rf)], env=base, capture_output=True, text=True)
        if r.returncode != 0:
            raise ShakeError("could not install the project's dev dependencies into the "
                             "shake verification env (build-time only, network allowed):\n"
                             + (r.stderr or r.stdout)[-1200:])

    resurrected = _resurrected(venv, dropped_rel)
    if resurrected:
        raise ShakeError(
            f"{len(resurrected)} pruned file(s) came back into the verification env, so "
            "verifying against it would prove nothing about the shipped payload "
            "(INV-SHAKE-02). This happens when a dev dependency pulls a different version "
            "of a runtime dist and uv reinstalls it whole.\n  "
            + "\n  ".join(sorted(resurrected)[:8])
            + "\n\nNothing was shipped. Pin the dev group to the runtime versions, or "
              "build without --shake.")

    bindir = venv / ("Scripts" if sys.platform == "win32" else "bin")
    results = []
    for cmd in [list(cfg.test), *[list(c) for c in cfg.also_run]]:
        env = dict(base, VIRTUAL_ENV=str(venv),
                   PATH=str(bindir) + os.pathsep + base.get("PATH", ""))
        env.pop("PYTHONHOME", None)
        say(f"shake: verifying with `{' '.join(cmd)}` against the pruned payload")
        r = subprocess.run(cmd, cwd=str(app_dir), env=env, capture_output=True, text=True)
        results.append({"command": cmd, "exit": r.returncode})
        if r.returncode != 0:
            raise ShakeError(
                f"the suite FAILED against the shaken payload (`{' '.join(cmd)}` exited "
                f"{r.returncode}). Nothing was shipped.\n\n"
                f"{(r.stdout or r.stderr or '')[-2000:]}\n\n"
                "Something the program needs was observed as unused. Keep it explicitly:\n"
                "    haru-pack build ... --shake --shake-keep 'pkg/thefile.so'\n"
                "or in haru_pack.toml:\n"
                "    [shake]\n    keep = [\"pkg/thefile.so\"]")
    return {"env": str(venv), "runs": results}


def _env_python(venv: Path) -> Path:
    for c in (venv / "bin" / "python", venv / "bin" / "python3",
              venv / "Scripts" / "python.exe"):
        if c.exists():
            return c
    raise ShakeError(f"no interpreter in the verification env {venv}")


def _resurrected(venv: Path, dropped_rel: set) -> set:
    sps = _site_packages(venv)
    return {rel for rel in dropped_rel for sp in sps if (sp / rel).exists()}


# ------------------------------------------------------------------------------ entry point

def shake(payload: Path, app_dir: Path, cache_dir: Path, py: Path, obs_env: Path,
          cfg: ShakeConfig, workdir: Path, sources=None, log=None) -> dict:
    """Observe, prune, verify. Returns the report; raises ShakeError rather than shipping."""
    say = log or (lambda _m: None)
    qroot = workdir / "shake-quarantine"
    qroot.mkdir(parents=True, exist_ok=True)
    before = _tree_bytes(payload)

    runtime = _runtime_dists(app_dir)
    archives = _index_archives(cache_dir)
    if not archives:
        raise ShakeError(
            f"--shake found no unpacked wheel trees in {cache_dir} to shake. A thick build "
            "warms `vendor/cache` from the project's lockfile; if that did not happen there "
            "is nothing to prune and the flag is a no-op, which haru-pack reports rather "
            "than passing off as a saving.")

    observed, runs, tracer = _observe(cfg, obs_env, app_dir, py, log=say)
    keep = _observed_relpaths(observed, obs_env)
    index = _module_index(archives)
    say(f"shake: {len(observed)} path(s) traced, {len(keep)} inside the dependency trees")
    if cfg.follow_lazy_imports:
        keep = _lazy_import_closure(keep, index, log=say)
    keep = _retain_package_inits(keep, index)

    dep_dropped, dep_freed, per_dist, dropped_rel = _prune_dependencies(
        archives, payload, qroot, keep, runtime, cfg.keep,
        own=_project_name(app_dir), log=say)
    bucket_dropped, bucket_freed = _prune_cache_buckets(cache_dir, qroot, log=say)
    py_dropped, py_freed = ([], 0)
    if cfg.shake_interpreter:
        pydir = payload / "vendor" / "python"
        if pydir.is_dir():
            py_dropped, py_freed = _prune_interpreter(pydir, payload, qroot, observed,
                                                      cfg.keep, log=say)

    freed = dep_freed + bucket_freed + py_freed
    say(f"shake: pruned {len(dep_dropped) + len(bucket_dropped) + len(py_dropped)} file(s), "
        f"{freed / 1e6:.1f} MB uncompressed — verifying")

    verify = _verify(app_dir, cache_dir, py, cfg, workdir, dropped_rel,
                     sources=sources, log=say)

    after = _tree_bytes(payload)
    return {
        "tracer": tracer,
        "observation": {"runs": runs, "paths_traced": len(observed)},
        "verification": verify,
        "payload_bytes_before": before,
        "payload_bytes_after": after,
        "freed_bytes": freed,
        "dropped_files": len(dep_dropped) + len(bucket_dropped) + len(py_dropped),
        "dropped": {
            "dependencies": {"files": len(dep_dropped), "bytes": dep_freed},
            "uv_cache_buckets": {"files": len(bucket_dropped), "bytes": bucket_freed},
            "interpreter": {"files": len(py_dropped), "bytes": py_freed},
        },
        "per_dist": per_dist,
        "kept_globs": list(cfg.keep),
        "quarantine": str(qroot),
        "dropped_paths": sorted(p.relative_to(payload).as_posix()
                                for p in [*dep_dropped, *bucket_dropped, *py_dropped]
                                if _is_within(p, payload)),
    }


def _is_within(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root); return True
    except ValueError:
        return False


def _tree_bytes(root: Path) -> int:
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file())


def write_report(report: dict, out: Path) -> Path:
    """Drop the receipt next to the binary.

    An operator debugging "it works here and ImportErrors on the customer's box" needs the
    list of files this build removed, and needs it without rebuilding. The summary also
    goes into the payload manifest, but the full path list would bloat every launcher, so
    it lives here.
    """
    dest = Path(str(out) + ".shake.json")
    dest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return dest


def manifest_summary(report: dict) -> dict:
    """The part of the report small enough to ship inside the payload."""
    return {
        "shaken": True,
        "tracer": report["tracer"],
        "dropped_files": report["dropped_files"],
        "freed_bytes": report["freed_bytes"],
        "verified": all(r["exit"] == 0 for r in report["verification"]["runs"]),
    }

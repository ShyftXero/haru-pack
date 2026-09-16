"""Phase 2a — what is IN the payload, and what has to be kept whatever the tracer saw.

The rules here all answer one question: does removing this file break a FEATURE, or break
IMPORTABILITY? A missing `*.dist-info` or a missing `__init__.py` on a retained path is the
second kind, and so is the static closure of every lazy import inside a kept module — a
function-level `import scipy` is invisible to a tracer that never called that function.

Split out of shake.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import ast
import fnmatch
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .. import tomlio
from .config import _DIST_ALWAYS_KEEP_DIRS, _DIST_ALWAYS_KEEP_GLOBS, ShakeError
from .observe import _site_packages


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
        # tomlio is imported at module scope on purpose: inside this `except Exception` a
        # bad import would be indistinguishable from a malformed pyproject, and would make
        # every project look unnamed. That is exactly what the shake/ package split did on
        # 2026-09-13 when the import was still spelled `from . import tomlio`.
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

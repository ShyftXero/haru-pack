"""Discover build settings from a target project so you rarely hand-write config.

Sources (later overrides earlier): pyproject.toml / PEP 723 / .python-version  ->
haru_pack.toml (explicit declarations) -> CLI flags.
"""
from __future__ import annotations
import re
from pathlib import Path
from . import tomlio

_PYVER = re.compile(r"(\d+\.\d+)")

def _pyver_from_spec(spec: str) -> str:
    m = _PYVER.search(spec or "")
    return m.group(1) if m else ""

def _dot_python_version(d: Path) -> str:
    f = d / ".python-version"
    return _pyver_from_spec(f.read_text()) if f.exists() else ""

def _pep723(script: Path) -> dict:
    """Parse a PEP 723 `# /// script` block for requires-python and dependencies.

    The dependency list matters for more than information: at the thick tier a script's
    declared dependencies have to be staged into the payload, or `--thick` ships a binary
    that still needs the network on first run (INV-TIER-01).
    """
    txt = script.read_text()
    m = re.search(r"# /// script\s*(.*?)# ///", txt, re.S)
    out = {"dependencies": []}
    if m:
        body = "\n".join(l[2:] if l.startswith("# ") else l.lstrip("#")
                         for l in m.group(1).splitlines())
        try:
            meta = tomlio._toml.loads(body)
            out["python"] = _pyver_from_spec(meta.get("requires-python", ""))
            deps = meta.get("dependencies") or []
            out["dependencies"] = [d for d in deps if isinstance(d, str)]
        except Exception:
            pass
    return out

class AmbiguousProject(ValueError):
    """More than one defensible entrypoint. Refuse, list the candidates, scaffold.

    Guessing here is the worst option available. A wrong pick produces a binary that builds
    cleanly, runs the wrong thing, and gives the operator no reason to suspect it — the
    failure surfaces at the customer, not at the build.
    """

    def __init__(self, message: str, candidates: list, *, kind: str = "project",
                 name: str = "app", source=None, python: str = ""):
        super().__init__(message)
        self.candidates = list(candidates)
        self.kind, self.name, self.source, self.python = kind, name, source, python


def discover(path) -> dict:
    """Return {kind, name, app_subdir, entrypoint, python, source} for a project or script.

    Raises `AmbiguousProject` when more than one entrypoint is defensible.
    """
    path = Path(path)
    if path.is_file() and path.suffix == ".py":
        d = {"kind": "script", "name": path.stem, "app_subdir": "app",
             "entrypoint": [path.name], "python": "", "source": path}
        d.update(_pep723(path)); return d

    pyproj = path / "pyproject.toml"
    if pyproj.exists():
        proj = tomlio.load(pyproj).get("project", {})
        name = proj.get("name", "app")
        py = _pyver_from_spec(proj.get("requires-python", "")) or _dot_python_version(path)
        scripts = list((proj.get("scripts") or {}).keys())

        # A declared console script IS the artifact. Loose .py files at the project root are
        # not candidates once [project.scripts] exists — in a real tree they are helpers,
        # plugins, and one-off utilities that the console script invokes or takes as
        # arguments. lotek is the worked example: `ls` shows a dozen root .py files, and the
        # only correct answer is the single `lotek` script its pyproject declares.
        if len(scripts) == 1:
            return {"kind": "project", "name": name, "app_subdir": "app",
                    "entrypoint": [scripts[0]], "python": py, "source": path}
        if len(scripts) > 1:
            raise AmbiguousProject(
                f"{name} declares {len(scripts)} console scripts; haru-pack will not pick "
                f"one for you.", scripts, kind="project", name=name, source=path, python=py)

        # No scripts table: fall back to `python -m <package>`, which only makes sense if
        # that package actually exists in the tree.
        mod = name.replace("-", "_")
        if (path / mod / "__init__.py").exists() or (path / "src" / mod / "__init__.py").exists():
            return {"kind": "project", "name": name, "app_subdir": "app",
                    "entrypoint": ["python", "-m", mod], "python": py, "source": path}
        raise AmbiguousProject(
            f"{name} has no [project.scripts] and no importable package named {mod!r}, so "
            f"there is nothing obvious to run.", [], kind="project", name=name,
            source=path, python=py)

    pys = sorted(p for p in path.glob("*.py") if p.name != "setup.py")
    if len(pys) == 1:
        d = {"kind": "script", "name": pys[0].stem, "app_subdir": "app",
             "entrypoint": [pys[0].name], "python": "", "source": pys[0]}
        d.update(_pep723(pys[0])); return d
    if len(pys) > 1:
        raise AmbiguousProject(
            f"{path} has no pyproject.toml and {len(pys)} top-level .py files; haru-pack "
            f"will not guess which one is the program.", [p.name for p in pys],
            kind="script", name=path.name or "app", source=path)

    raise ValueError(f"can't discover a project in {path}: no pyproject.toml and no .py files")

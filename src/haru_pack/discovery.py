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
    """Parse a PEP 723 `# /// script` block for requires-python."""
    txt = script.read_text()
    m = re.search(r"# /// script\s*(.*?)# ///", txt, re.S)
    out = {}
    if m:
        body = "\n".join(l[2:] if l.startswith("# ") else l.lstrip("#")
                         for l in m.group(1).splitlines())
        try:
            meta = tomlio._toml.loads(body)
            out["python"] = _pyver_from_spec(meta.get("requires-python", ""))
        except Exception:
            pass
    return out

def discover(path) -> dict:
    """Return {kind, name, app_subdir, entrypoint, python, source} for a project or script."""
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
        scripts = proj.get("scripts") or {}
        entrypoint = [next(iter(scripts))] if scripts else ["python", "-m", name.replace("-", "_")]
        return {"kind": "project", "name": name, "app_subdir": "app",
                "entrypoint": entrypoint, "python": py, "source": path}

    pys = list(path.glob("*.py"))
    if len(pys) == 1:
        d = {"kind": "script", "name": pys[0].stem, "app_subdir": "app",
             "entrypoint": [pys[0].name], "python": "", "source": pys[0]}
        d.update(_pep723(pys[0])); return d

    raise ValueError(f"can't discover a project in {path}: no pyproject.toml and not a single .py")

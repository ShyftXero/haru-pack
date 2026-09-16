"""Every relative import in the package points at something that exists.

Written on 2026-09-13, immediately after the INV-MODULARITY-01 splits produced four of
these in one afternoon. Turning `haru_pack/shake.py` into `haru_pack/shake/` silently
changes what `from . import tomlio` means in every line that moved, and the ones that hurt
are not at module scope — they are late-bound imports inside a function, which nothing
executes until a user runs that exact command:

    def _project_name(app_dir):
        try:
            from . import tomlio          # was haru_pack.tomlio, now haru_pack.shake.tomlio
            ...
        except Exception:
            return ""                     # ...and the ImportError lands here

That one was caught by a test that happened to cover it. `from . import scaffold` inside
`cli.init` was not covered by anything, and would have failed for the first person to run
`haru-pack init` after the split.

This is a STATIC check — it reads the imports rather than running them, so a function-local
import is no harder to see than a top-level one, and nothing here needs a build toolchain.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PKG = REPO / "src" / "haru_pack"

MODULES = sorted(p for p in PKG.rglob("*.py"))


def _dotted(path: Path) -> str:
    """`src/haru_pack/build/tree.py` -> `haru_pack.build.tree` (a package -> its own name)."""
    rel = path.relative_to(PKG.parent).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve(importer: str, level: int, module: str | None) -> str:
    """The absolute dotted name a relative import refers to, per Python's own rules.

    `level` is the number of leading dots. Inside a package's `__init__`, one dot means the
    package itself; inside a submodule it means the package that CONTAINS it — which is the
    whole reason a file moving into a new subpackage changes the meaning of its imports
    without changing their text.
    """
    base = importer.split(".")
    if (PKG.parent / Path(*base) / "__init__.py").exists():
        base.append("")            # a package: `from .` starts at the package itself
    base = base[:-level] if level <= len(base) else []
    return ".".join([*base, module] if module else base)


def _exists(dotted: str) -> bool:
    stem = Path(*dotted.split("."))
    return ((PKG.parent / stem).with_suffix(".py").exists()
            or (PKG.parent / stem / "__init__.py").exists())


def _defines(package: str, name: str) -> bool:
    """Does `package/__init__.py` bind `name` at module scope?

    `from .. import __version__` is a perfectly good import of an ATTRIBUTE, not a
    submodule, and a check that did not know the difference would fail on it.
    """
    if not package:
        return False
    init = PKG.parent / Path(*package.split(".")) / "__init__.py"
    if not init.exists():
        return False
    tree = ast.parse(init.read_text(encoding="utf-8"))
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            bound.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            bound.update(a.asname or a.name.split(".")[0] for a in node.names)
    return name in bound


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.relative_to(REPO).as_posix())
def test_every_relative_import_resolves(path: Path):
    """Red-path: change any `from .. import tomlio` back to `from . import tomlio`."""
    importer = _dotted(path)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    broken = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or not node.level:
            continue
        target = _resolve(importer, node.level, node.module)
        if node.module:
            if not _exists(target):
                broken.append((node.lineno, "." * node.level + node.module, target))
            continue
        # `from . import a, b` — each NAME is either a submodule or a name the target
        # package's __init__ defines (`from .. import __version__` is the latter).
        for alias in node.names:
            candidate = f"{target}.{alias.name}" if target else alias.name
            if _exists(candidate) or _defines(target, alias.name):
                continue
            broken.append((node.lineno, f"{'.' * node.level} import {alias.name}",
                           candidate))
    assert not broken, (
        f"{path.relative_to(REPO)} has relative import(s) that resolve to nothing:\n"
        + "\n".join(f"  line {ln}: `from {spec}` -> {target}" for ln, spec, target in broken)
        + "\nA file that moved into a subpackage needs one more dot. Watch for imports "
          "INSIDE a function — nothing runs them until someone runs that command."
    )


def test_the_scanner_sees_the_package():
    """A scanner that finds no modules passes the whole file."""
    assert len(MODULES) > 25, (
        f"only {len(MODULES)} modules found under {PKG}; the scan path is wrong and every "
        f"other test here is vacuous"
    )


def test_the_resolver_can_tell_a_package_from_a_module():
    """The rule this whole file turns on, asserted directly rather than assumed.

    From `haru_pack.shake` (a package's __init__) a single dot is `haru_pack.shake`.
    From `haru_pack.shake.index` (a submodule) the same single dot is also `haru_pack.shake` —
    but from `haru_pack.tomlio`, a top-level module, it is `haru_pack`.
    """
    assert _resolve("haru_pack.shake", 1, "config") == "haru_pack.shake.config"
    assert _resolve("haru_pack.shake.index", 1, "config") == "haru_pack.shake.config"
    assert _resolve("haru_pack.shake.index", 2, "tomlio") == "haru_pack.tomlio"
    assert _resolve("haru_pack.tomlio", 1, "targets") == "haru_pack.targets"


def test_an_attribute_import_is_not_mistaken_for_a_missing_module():
    """`from .. import __version__` is an attribute of haru_pack/__init__.py, not a
    submodule. A checker that did not know the difference would cry wolf on it — and a
    checker that cries wolf gets deleted."""
    assert not _exists("haru_pack.__version__"), "test premise: it is not a module"
    assert _defines("haru_pack", "__version__"), (
        "haru_pack/__init__.py no longer binds __version__; `haru-pack version` is broken"
    )

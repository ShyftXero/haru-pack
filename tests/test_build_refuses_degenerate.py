"""The build refuses degenerate inputs intelligibly — it never dies with a raw traceback.

Both defects here were found by busybody's composed `greenhorn` cases (a degenerate SOURCE
handed to the packer), which the run graded CRASHED — the FATAL class — because the compose
contract is "refuse intelligibly under any stack of hostile conditions", not "always works".
The old behaviour leaked a raw `ValueError` / `FileNotFoundError` and a Python traceback:

  * a directory of only compiled `.pyc` files (or an empty one) -> `discovery.discover` fell
    through to a bare `ValueError` no caller caught (`greenhorn_source_is_a_pyc`);
  * an `-o` path whose parent directory does not exist -> the final `out.write_bytes` raised
    `FileNotFoundError` (`greenhorn_output_into_missing_dir`).

Reproduced identically on x86 and aarch64 — these are build-side Python, upstream of Nim, so
they are platform-independent (INV-BUILD-01 / INV-BUILD-03).
"""
from __future__ import annotations

import py_compile
from pathlib import Path

import pytest

from haru_pack.build import build, BuildError
from haru_pack.discovery import discover, EmptyProject, AmbiguousProject


def _pyc_only(dirpath: Path) -> Path:
    """A directory whose only content is a compiled .pyc — no .py, no pyproject.toml."""
    dirpath.mkdir(parents=True, exist_ok=True)
    src = dirpath / "mod.py"
    src.write_text("x = 1\n")
    py_compile.compile(str(src), cfile=str(dirpath / "compiled.pyc"))
    src.unlink()
    return dirpath


def test_discover_pyc_only_raises_empty_project(tmp_path):
    proj = _pyc_only(tmp_path / "proj")
    with pytest.raises(EmptyProject) as ei:
        discover(proj)
    # actionable, and specifically NOT the old bare ValueError message shape
    assert "nothing to pack" in str(ei.value)
    assert ".pyc" in str(ei.value)


def test_discover_empty_dir_raises_empty_project(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(EmptyProject):
        discover(empty)


def test_empty_project_is_not_ambiguous(tmp_path):
    # AmbiguousProject (too MANY entrypoints) and EmptyProject (NONE) are siblings, not
    # parent/child — so build.py's `except AmbiguousProject` (which lets --entry-point
    # rescue) does NOT swallow the empty case, and the CLI refuses it outright.
    assert not issubclass(EmptyProject, AmbiguousProject)
    assert not issubclass(AmbiguousProject, EmptyProject)


def test_build_refuses_pyc_only_source_without_traceback(tmp_path):
    proj = _pyc_only(tmp_path / "proj")
    # Refusal happens in discovery, upstream of any toolchain, so this needs no Nim.
    with pytest.raises(EmptyProject):
        build(proj, tmp_path / "out")


def test_build_creates_missing_output_parent(tmp_path, stub_toolchain, monkeypatch):
    # stub_toolchain's bundle_uv lambda predates build.py's `sources=` kwarg; tolerate it
    # locally so this test can drive a full default build down to the output write.
    monkeypatch.setattr(stub_toolchain, "bundle_uv",
                        lambda target, vendor, **kw: vendor.mkdir(parents=True, exist_ok=True))
    src = tmp_path / "hello.py"
    src.write_text("print('hi')\n")
    out = tmp_path / "does" / "not" / "exist" / "hello"      # parent missing
    info = build(src, out, tier="default")
    assert out.exists(), "build must create the -o parent dir, not FileNotFoundError"
    assert info["out"] == str(out)


def test_build_refuses_unbuildable_output_parent(tmp_path, stub_toolchain):
    # A parent that cannot be created is a clean BuildError, still never a raw OSError.
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory\n")
    src = tmp_path / "hello.py"
    src.write_text("print('hi')\n")
    out = blocker / "sub" / "hello"          # blocker is a file -> mkdir(parents) fails
    with pytest.raises(BuildError):
        build(src, out, tier="default")

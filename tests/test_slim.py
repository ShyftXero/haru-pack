"""`--slim-python` — drop the known-unused interpreter furniture, opt-in.

`--slim-python` is the sibling of `--shake` and deliberately NOT the same feature: `--shake`
deletes on *evidence* (a traced test run, re-proven afterwards) and refuses without a test
command; `--slim-python` drops a FIXED, known-unused set with no suite required. The one
property both share, and the reason this feature is worth an invariant, is provenance: a
`--thick` binary ships python-build-standalone byte-for-byte so `INV-SUPPLY-01`'s digest
check is repeatable, and `--slim-python` may only prune AFTER that verification and must
record every path it removed. These tests pin that order, that recording, and that a default
build touches nothing.
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from haru_pack.build import receipt
from haru_pack.build import slim


# --------------------------------------------------------------------------------- fixtures

def _write(p: Path, text: str = "x") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


class _FakeSources:
    """receipt.finish only needs `.describe()`; a real Sources would drag in network state."""
    def describe(self) -> dict:
        return {}


@pytest.fixture
def fake_interpreter(tmp_path):
    """A python-build-standalone tree, small enough to assert about file by file.

    The interpreter is deliberately placed under `python/install/` — the exact nested layout
    some PBS releases use — so the rules are proven to match whatever prefix upstream extracts
    to, not just a flat `lib/`. Every file is tagged in a comment: dropped, or KEEP.
    """
    payload = tmp_path / "payload"
    pydir = payload / "vendor" / "python"
    root = pydir / "python" / "install"
    lib = root / "lib" / "python3.12"
    _write(lib / "os.py", "pass\n")                                 # stdlib — KEEP
    _write(lib / "encodings" / "__init__.py", "pass\n")             # stdlib — KEEP
    _write(lib / "sqlite3" / "__init__.py", "pass\n")               # stdlib — KEEP
    _write(lib / "tkinter" / "__init__.py", "K" * 64)               # drop
    _write(lib / "lib-dynload" / "_tkinter.cpython-312.so", "K" * 512)  # drop
    _write(lib / "idlelib" / "idle.py", "I" * 256)                  # drop
    _write(lib / "pydoc_data" / "topics.py", "P" * 256)             # drop
    _write(lib / "ensurepip" / "__init__.py", "E" * 64)             # drop
    _write(lib / "ensurepip" / "_bundled" / "pip-24.0.whl", "W" * 512)  # drop
    _write(lib / "site-packages" / "pip" / "__init__.py", "pip" * 64)   # drop
    _write(lib / "site-packages" / "pip-24.0.dist-info" / "METADATA", "m")  # drop
    _write(root / "lib" / "libtcl8.6.so", "tcl" * 64)               # drop
    _write(root / "lib" / "tcl8.6" / "init.tcl", "t" * 64)          # drop
    _write(root / "include" / "python3.12" / "Python.h", "H" * 256)  # drop
    _write(root / "share" / "man" / "man1" / "python3.1", "man")    # drop
    _write(root / "share" / "terminfo" / "x" / "xterm", "ti")       # KEEP
    return payload, pydir


def _rel(payload: Path):
    return {p.relative_to(payload).as_posix() for p in payload.rglob("*") if p.is_file()}


# ----------------------------------- (a) --slim-python removes the furniture; (c) keeps the rest

@pytest.mark.invariant("INV-SHAKE-05")
def test_slim_removes_the_furniture_and_keeps_terminfo_and_stdlib(fake_interpreter):
    """One pass over a PBS-shaped tree, asserting every category of decision.

    The keep half is the point of (c): the prune must never touch terminfo (a console app
    needs it) or the stdlib, only the fixed known-unused set.
    """
    payload, pydir = fake_interpreter
    report = slim.slim_python(pydir, payload)
    left = _rel(payload)

    # the fixed known-unused set is gone
    assert not any("tkinter" in p or "_tkinter" in p for p in left)
    assert not any("/idlelib/" in p for p in left)
    assert not any("/pydoc_data/" in p for p in left)
    assert not any("/ensurepip/" in p for p in left)
    assert not any("site-packages/pip" in p for p in left)          # pip AND pip-*.dist-info
    assert not any("libtcl" in p or "/tcl8.6/" in p for p in left)
    assert not any("include/python3.12" in p for p in left)
    assert not any("share/man/" in p for p in left)

    # (c) terminfo and the stdlib survive — the prune is structural, not a wildcard
    assert any(p.endswith("share/terminfo/x/xterm") for p in left), "terminfo was pruned"
    assert any(p.endswith("lib/python3.12/os.py") for p in left), "stdlib os.py was pruned"
    assert any("/encodings/" in p for p in left), "stdlib encodings was pruned"
    assert any("/sqlite3/" in p for p in left), "stdlib sqlite3 was pruned"

    assert report["freed_bytes"] > 0
    assert report["removed_files"] >= 8


# ---------------------------------------------- (b) a default build (no flag) prunes nothing

@pytest.mark.invariant("INV-SHAKE-05")
def test_a_default_build_prunes_nothing(fake_interpreter):
    """Without --slim-python the interpreter ships byte-for-byte the verified PBS artifact,
    which is what keeps INV-SUPPLY-01's digest check repeatable. The gate is `maybe_slim`.

    Red-path: make `maybe_slim` ignore its `slim` flag and always prune. This asserts the
    tree is untouched and the report is empty, so that goes red.
    """
    payload, pydir = fake_interpreter
    before = _rel(payload)
    report = slim.maybe_slim(pydir, payload, slim=False)
    assert _rel(payload) == before, "a build without --slim-python removed interpreter files"
    assert report == {}, "a default build must produce no slim report"


# ------------------------------- (a) the receipt records every removed path; ordering vs verify

@pytest.mark.invariant("INV-SHAKE-05")
def test_the_receipt_lists_every_removed_path(fake_interpreter):
    """The provenance record: the receipt must name every path removed, not just a count.

    Red-path: drop the `info["slim_python"] = {...}` block in `receipt.finish`. This goes red
    with a KeyError because the removed set is no longer on the receipt.
    """
    payload, pydir = fake_interpreter
    slim_report = slim.slim_python(pydir, payload)
    info = receipt.finish(
        {}, sources=_FakeSources(), provider="zig", tier="thick", tgt="linux-x86_64",
        nim="/n", compiler="zig", out=Path("/tmp/slim-x"), enc={"enabled": False},
        manifest={"kind": "project"}, pyver="3.12", canary={}, reap=False, overwrite=False,
        ram_only=False, base_path="", source_url="", unpacked_bytes=0, shake_report={},
        slim_report=slim_report)

    rec = info["slim_python"]
    assert rec["removed_files"] == slim_report["removed_files"] > 0
    assert rec["freed_bytes"] == slim_report["freed_bytes"] > 0
    # EVERY removed path is on the receipt, and the actual furniture is named, not just tallied
    assert set(rec["removed_paths"]) == set(slim_report["removed_paths"])
    assert any("tkinter" in p for p in rec["removed_paths"])
    assert any("site-packages/pip" in p for p in rec["removed_paths"])
    assert any("include/python3.12" in p for p in rec["removed_paths"])
    # all removed paths point inside the staged interpreter, not somewhere else in the payload
    assert all(p.startswith("vendor/python/") for p in rec["removed_paths"])


@pytest.mark.invariant("INV-SHAKE-05")
def test_slim_prunes_only_after_the_interpreter_is_verified():
    """The order is the invariant: `bundle_python` fetches and digest-verifies the interpreter
    (INV-SUPPLY-01), and only THEN may a file be pruned.

    Red-path: move the `maybe_slim(...)` call above the `bundle_python(...)` line in
    `thick.stage`. This goes red — the prune would run against an unverified (or not-yet-
    fetched) tree.
    """
    from haru_pack.build import thick as thick_mod

    src = inspect.getsource(thick_mod.stage)
    assert "bundle_python(" in src and "maybe_slim(" in src, (
        "thick.stage no longer both fetches the interpreter and offers to slim it"
    )
    assert src.index("bundle_python(") < src.index("maybe_slim("), (
        "--slim-python must prune a verified interpreter: the fetch-and-verify (bundle_python, "
        "INV-SUPPLY-01) has to come BEFORE the prune, never after"
    )


# ------------------------------------------------------------------- kept distinct from --shake

@pytest.mark.invariant("INV-SHAKE-05")
def test_slim_needs_no_test_command_unlike_shake(fake_interpreter):
    """--shake refuses without a declared test command (INV-SHAKE-03); --slim-python is the
    distinct capability that drops a fixed set with no observation. Proven by pruning with no
    project, no suite, and no config at all."""
    payload, pydir = fake_interpreter
    report = slim.slim_python(pydir, payload)   # no app_dir, no ShakeConfig, no test command
    assert report["removed_files"] > 0


def test_the_layout_prefix_cannot_silently_disable_a_rule(tmp_path):
    """PBS extracts under `python/`, and some layouts add `install/`. A rule matched against
    the full relative path would match nothing under a new prefix — the trap that once made
    --shake's interpreter prune a silent no-op. Rules are matched against every path suffix.

    Red-path: match `rel` alone instead of `_suffixes(rel)` in `slim.slim_python`.
    """
    payload = tmp_path / "payload"
    pydir = payload / "vendor" / "python"
    _write(pydir / "python" / "install" / "lib" / "python3.12" / "idlelib" / "idle.py", "I")
    _write(pydir / "python" / "lib" / "python3.12" / "os.py", "keep me")
    report = slim.slim_python(pydir, payload)
    left = {p.name for p in payload.rglob("*") if p.is_file()}
    assert "idle.py" not in left, "the rule did not match under the nested PBS prefix"
    assert "os.py" in left
    assert report["removed_files"] == 1

from __future__ import annotations

import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:          # so `import _invariants` works without a package
    sys.path.insert(0, str(TESTS))


@pytest.fixture
def stub_toolchain(monkeypatch, tmp_path):
    """Let build.build() run end-to-end without Nim or a C compiler.

    Everything under test — enablement, encryption, the payload contents, the
    post-condition — is upstream of compilation. Stubbing the compiler keeps these
    invariants checkable in CI on a box with no Nim, which is the difference between a
    guard that runs on every push and one that runs when someone remembers.
    """
    from haru_pack import build as build_mod

    def fake_compile(nim, target, workdir):
        out = Path(workdir) / "launcher"
        out.write_bytes(b"\x7fELF" + b"\x00" * 512)     # plausible stub, not a real ELF
        return out

    monkeypatch.setattr(build_mod, "find_nim", lambda: "/nonexistent/nim")
    monkeypatch.setattr(build_mod, "detect_c_toolchain",
                        lambda target: {"ok": True, "compiler": "stub-cc", "advice": ""})
    monkeypatch.setattr(build_mod, "compile_launcher", fake_compile)
    monkeypatch.setattr(build_mod, "bundle_uv", lambda target, vendor: vendor.mkdir(
        parents=True, exist_ok=True))
    return build_mod


@pytest.fixture
def script_project(tmp_path):
    """A minimal single-script project that discovery accepts."""
    d = tmp_path / "proj"
    d.mkdir()
    (d / "hello.py").write_text("print('hi')\n")
    return d


@pytest.fixture(scope="session")
def nim_launcher(tmp_path_factory):
    """The REAL launcher, compiled once per session and shared by the Phase-2 staging tests
    (tests/test_reap.py, tests/test_ram_only.py). Skips the requesting test when nim is absent,
    so a pure-Python build test in the same file still runs on a no-nim box."""
    import shutil

    if shutil.which("nim") is None:
        pytest.skip("nim not installed; the launcher cannot be built")
    from _stage_helpers import compile_launcher

    return compile_launcher(tmp_path_factory.mktemp("nim-stub-p2") / "launcher")

"""The payload carries the runtime resolution, not the project's toolbox (INV-PAYLOAD-03).

`uv sync` installs the *default* dependency groups, and `dev` is one of them. So the call
that warms a thick payload's bundled cache used to download the project's own test runner,
linters and build backend into the binary — 11 dists and 6.5 MB on `examples/shake-demo`,
none of it reachable by a launcher that runs the entrypoint and never the suite.

These tests assert on the argv rather than on a built payload for a reason: building one
means downloading an interpreter and a dependency closure, so it cannot run in CI on every
push, and an invariant that only gets checked when someone remembers is not a guard.
"""
from __future__ import annotations

import inspect

import pytest

from haru_pack import bundle, build as build_mod


def _argv_of(calls):
    """The first `uv` argv a recorder captured."""
    return next(c for c in calls if c and c[0] == "uv")


@pytest.fixture
def record_uv(monkeypatch):
    """Capture argv instead of running uv."""
    calls = []

    class R:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, *a, **kw):
        calls.append(list(cmd))
        return R()

    monkeypatch.setattr(bundle.subprocess, "run", fake_run)
    return calls


@pytest.mark.invariant("INV-PAYLOAD-03")
def test_the_host_cache_warm_excludes_the_dev_group(record_uv, tmp_path):
    """Red-path: drop `--no-dev` from the `uv sync` in `warm_cache_and_lock`. This goes red,
    and a thick build starts shipping pytest again."""
    bundle.warm_cache_and_lock(tmp_path / "app", tmp_path / "py", tmp_path / "cache",
                               tmp_path / "env")
    argv = _argv_of(record_uv)
    assert argv[1] == "sync"
    assert "--no-dev" in argv, f"the bundled cache is warmed with dev deps: {argv}"


@pytest.mark.invariant("INV-PAYLOAD-03")
def test_the_cross_path_excludes_the_dev_group_too(monkeypatch, tmp_path):
    """The Windows-from-Linux path resolves wheels with a separate code path, and it had the
    same defect. Two paths meant one of them would be fixed and the other forgotten."""
    seen = {}

    def fake_export(app_dir, dev=True):
        seen["dev"] = dev
        return []

    monkeypatch.setattr(bundle, "_export_reqs", fake_export)
    monkeypatch.setattr(bundle, "_run", lambda *a, **kw: type("R", (), {"stdout": ""})())
    bundle.warm_cache_windows(tmp_path / "app", tmp_path / "cache", "3.12")
    assert seen["dev"] is False, "the cross path downloads dev wheels into the payload"


@pytest.mark.invariant("INV-PAYLOAD-03")
@pytest.mark.parametrize("dev,expect_flag", [(False, True), (True, False)])
def test_export_reqs_passes_no_dev_to_uv_only_when_asked(monkeypatch, tmp_path,
                                                         dev, expect_flag):
    """The `dev` parameter has to actually reach uv's argv, or it is decoration that reads
    as a guarantee."""
    seen = {}

    def fake_run(cmd, **kw):
        seen["argv"] = list(cmd)
        return type("R", (), {"stdout": ""})()

    monkeypatch.setattr(bundle, "_run", fake_run)
    bundle._export_reqs(tmp_path / "app", dev=dev)
    assert ("--no-dev" in seen["argv"]) is expect_flag, seen["argv"]


@pytest.mark.invariant("INV-PAYLOAD-03")
def test_dev_tools_are_installed_outside_the_payload(monkeypatch, tmp_path):
    """The other half of the fix: the tools still exist at build time, from the BUILD
    HOST's cache. If either uv call here ever got a `UV_CACHE_DIR` pointing into the
    payload, the bytes would be back and the `--no-dev` sync above would be pointless.

    Asserted on the env actually handed to uv rather than on the source text — the first
    version of this test grepped `inspect.getsource` and matched the docstring explaining
    why `UV_CACHE_DIR` is absent, which is a test that can only ever pass or lie.
    """
    envs, argvs = [], []

    def fake_run(cmd, **kw):
        argvs.append(list(cmd))
        envs.append(kw.get("env") or {})
        return _res(0, "pytest>=8\n") if len(envs) == 1 else _res(0)

    monkeypatch.setattr(bundle.subprocess, "run", fake_run)
    bundle.install_dev_tools(tmp_path / "app", tmp_path / "env")
    assert envs, "install_dev_tools never invoked uv"
    import os

    ambient = os.environ.get("UV_CACHE_DIR")
    for env in envs:
        # The requirement is that install_dev_tools does not REDIRECT the cache at the
        # payload — not that UV_CACHE_DIR is unset. Inheriting the operator's own cache is
        # correct and is the point: the dev tools should come from the build host.
        #
        # The first version asserted plain absence and passed only because this machine had
        # no UV_CACHE_DIR set. CI's setup-uv action exports one
        # (`/home/runner/work/_temp/setup-uv-cache`), so it failed there the first time the
        # invariant contract actually ran — which is what fixing the linter pin unblocked.
        assert env.get("UV_CACHE_DIR") == ambient, (
            "install_dev_tools overrode UV_CACHE_DIR; if it points at the payload cache the "
            "dev group ships inside the binary again, which INV-PAYLOAD-03 forbids"
        )
    assert any("--only-dev" in a for a in argvs), "the dev group is no longer what is read"


@pytest.mark.invariant("INV-PAYLOAD-03")
def test_the_build_env_still_gets_its_tools_when_they_are_needed():
    """A bundle step or a --shake observation runs those tools. Removing them from the
    payload must not remove them from the env that executes build steps."""
    src = inspect.getsource(build_mod.assemble_payload)
    assert "install_dev_tools(" in src, (
        "nothing restores the dev tooling to the build env, so a [[bundle]] step that used "
        "a dev-group tool now fails"
    )
    assert "if steps or shake:" in src, (
        "the dev-tool install is not gated on actually needing it"
    )


def _seq_run(monkeypatch, results):
    """Fake `subprocess.run` handing back one canned result per call, in order."""
    calls = []

    def fake_run(cmd, *a, **kw):
        calls.append(list(cmd))
        return results[min(len(calls) - 1, len(results) - 1)]

    monkeypatch.setattr(bundle.subprocess, "run", fake_run)
    return calls


def _res(rc=0, out="", err=""):
    return type("R", (), {"returncode": rc, "stdout": out, "stderr": err})()


@pytest.mark.invariant("INV-PAYLOAD-03")
def test_a_broken_dev_group_does_not_fail_an_otherwise_fine_build(monkeypatch, tmp_path):
    """A dev group that will not install is a problem for the operator's tooling — not a
    reason to refuse to build a binary whose runtime dependencies resolved fine. But it is
    not silent either: a [[bundle]] step is about to fail for a reason that started here.
    """
    # export succeeds and names a tool; the install of it fails.
    _seq_run(monkeypatch, [_res(0, "pytest>=8\n"),
                           _res(1, "", "no matching distribution")])
    said = []
    got = bundle.install_dev_tools(tmp_path / "app", tmp_path / "env", log=said.append)
    assert got == []
    assert any("WARNING" in m for m in said), "a silent failure here is a confusing build"


@pytest.mark.invariant("INV-PAYLOAD-03")
def test_a_project_with_no_dev_group_is_not_a_warning(monkeypatch, tmp_path):
    """The common case. An empty dev group must not print anything, or every build of a
    dependency-free script starts nagging."""
    _seq_run(monkeypatch, [_res(0, "")])
    said = []
    assert bundle.install_dev_tools(tmp_path / "app", tmp_path / "env",
                                    log=said.append) == []
    assert said == []


@pytest.mark.invariant("INV-PAYLOAD-03")
def test_the_dev_install_targets_the_build_env_interpreter(monkeypatch, tmp_path):
    """`--python <tmp_env>` is what keeps the tools in the throwaway env. Without it uv
    picks its own interpreter and the bundle step still cannot see them."""
    calls = _seq_run(monkeypatch, [_res(0, "pytest>=8\n"), _res(0)])
    bundle.install_dev_tools(tmp_path / "app", tmp_path / "env")
    install = calls[-1]
    assert install[:3] == ["uv", "pip", "install"]
    assert "--python" in install
    assert str(tmp_path / "env") in install[install.index("--python") + 1]

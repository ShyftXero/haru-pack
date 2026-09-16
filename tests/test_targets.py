"""INV-BUILD-05 (architecture) and INV-BUILD-06 (the bare `haru-pack <path>` form).

Architecture used to be assumed: `--target` meant an OS and x86_64 was implied everywhere.
That assumption gets compiled into a binary a customer runs. The **default** tier bundles a
`uv` executable, so a mismatch does not degrade — it ships something the target cannot
execute at all, and the failure appears on the customer's machine as "cannot execute binary
file". A Raspberry Pi is an ordinary target for this project, so this is the common case,
not an exotic one.
"""
from __future__ import annotations

import inspect

import pytest

from haru_pack import bundle
from haru_pack.targets import (KNOWN_TARGETS, Target, TargetError, normalize_arch)


# ---------------------------------------------------------------- parsing

@pytest.mark.invariant("INV-BUILD-05")
@pytest.mark.parametrize("spec,expect", [
    ("linux-aarch64", ("linux", "aarch64")),
    ("linux-arm64", ("linux", "aarch64")),        # platform.machine() spelling
    ("macos-aarch64", ("macos", "aarch64")),
    ("darwin-x86_64", ("macos", "x86_64")),
    ("windows-aarch64", ("windows", "aarch64")),
    ("linux-armv7", ("linux", "armv7")),
])
def test_targets_parse(spec, expect):
    t = Target.parse(spec)
    assert (t.os, t.arch) == expect


@pytest.mark.invariant("INV-BUILD-05")
def test_legacy_os_only_targets_still_work():
    """`--target windows` predates arch awareness and is in the README and docs. Breaking
    it would break documented commands for no benefit."""
    assert Target.parse("windows") == Target("windows", "x86_64")
    assert Target.parse("host").os in ("linux", "macos", "windows")


@pytest.mark.invariant("INV-BUILD-05")
@pytest.mark.parametrize("bad", ["linux-sparc", "solaris-x86_64", "linux-", "nonsense"])
def test_unknown_targets_are_rejected(bad):
    """Red-path: make Target.parse fall back to a default instead of raising. A silently
    accepted target picks *some* asset, and the operator finds out on the customer's box."""
    with pytest.raises(TargetError):
        Target.parse(bad)


@pytest.mark.invariant("INV-BUILD-05")
def test_arch_aliases_normalize_to_one_vocabulary():
    """platform.machine() spells the same chip differently per OS. One vocabulary, or the
    dict lookups that key on it silently miss."""
    for alias in ("x86_64", "AMD64", "x64"):
        assert normalize_arch(alias) == "x86_64"
    for alias in ("aarch64", "arm64", "ARM64"):
        assert normalize_arch(alias) == "aarch64"
    with pytest.raises(TargetError):
        normalize_arch("sparc64")


# ---------------------------------------------------------------- artifact selection

@pytest.mark.invariant("INV-BUILD-05")
@pytest.mark.parametrize("spec", KNOWN_TARGETS)
def test_every_known_target_has_a_pinned_uv(spec):
    """Red-path: add a target to targets._UV_ASSETS without pinning its digest.

    A target haru-pack advertises but cannot verify an artifact for is worse than one it
    does not offer: it fails at build time after the operator has already committed to it.
    """
    t = Target.parse(spec)
    asset = t.uv_asset()
    digest = bundle.UV_SHA256.get(bundle.UV_VERSION, {}).get(asset)
    assert digest, f"{spec} selects {asset}, which has no pinned digest in bundle.UV_SHA256"
    assert len(digest) == 64, f"{asset} pin is not a sha256: {digest!r}"


@pytest.mark.invariant("INV-BUILD-05")
def test_uv_asset_names_are_arch_specific():
    """The whole bug in one assertion: no two architectures may share an asset."""
    seen = {}
    for spec in KNOWN_TARGETS:
        t = Target.parse(spec)
        a = t.uv_asset()
        assert a not in seen or seen[a] == (t.os, t.arch), (
            f"{spec} and {seen[a]} both select {a}; one of them would ship the wrong binary"
        )
        seen[a] = (t.os, t.arch)
    assert len({Target.parse(s).uv_asset() for s in KNOWN_TARGETS}) == len(KNOWN_TARGETS)


@pytest.mark.invariant("INV-BUILD-05")
def test_python_lookup_requests_all_arches():
    """Red-path: drop `--all-arches` from _find_python_url.

    Without it uv lists only x86_64 and armv7, so every aarch64 lookup returns nothing and
    the Pi target looks unsupported rather than unpinned. Verified against uv 0.10.4.
    """
    src = inspect.getsource(bundle._find_python_url)
    assert "--all-arches" in src, (
        "uv's catalog omits aarch64 unless --all-arches is passed; without it a Raspberry "
        "Pi target cannot resolve an interpreter at all"
    )


@pytest.mark.invariant("INV-BUILD-05")
def test_musl_builds_are_not_selected_by_accident():
    """python-build-standalone publishes gnu and musl for the same (os, arch). They are not
    interchangeable, and the catalog lists both."""
    src = inspect.getsource(bundle._find_python_url)
    assert "libc" in src, "no libc filter: a musl interpreter could be staged for a gnu target"


@pytest.mark.invariant("INV-BUILD-05")
def test_launcher_selects_its_uv_asset_by_compiled_arch():
    """The runtime half. Red-path: hardcode x86_64 in uvfetch.nim's uvAsset().

    A thin-tier launcher fetches uv on the customer's machine at first run, so the asset it
    asks for must follow the arch it was COMPILED for, not the build host's.
    """
    from pathlib import Path
    nim = (Path(__file__).resolve().parent.parent
           / "src/haru_pack/launcher/uvfetch.nim").read_text()
    body = nim[nim.index("proc uvAsset"):nim.index("proc isValidUvVersion")]
    assert "hostCPU" in body, "uvAsset() ignores the compiled architecture"
    for asset in ("uv-aarch64-unknown-linux-gnu.tar.gz",
                  "uv-armv7-unknown-linux-gnueabihf.tar.gz",
                  "uv-aarch64-apple-darwin.tar.gz"):
        assert asset in body, f"uvAsset() cannot ask for {asset}"
    # and every name it can produce must be one we pin
    pinned = set(bundle.UV_SHA256[bundle.UV_VERSION])
    import re
    for name in re.findall(r'"(uv-[^"]+)"', body):
        assert name in pinned, f"uvfetch.nim can request {name}, which is not pinned"


@pytest.mark.invariant("INV-BUILD-05")
def test_cross_compilation_names_a_compiler_and_how_to_get_it():
    """A missing cross toolchain must produce an actionable sentence, not a link error."""
    from haru_pack.bootstrap import detect_c_toolchain
    tc = detect_c_toolchain(Target("linux", "aarch64"))
    if not tc["ok"]:
        assert "aarch64-linux-gnu-gcc" in tc["advice"]
        assert "install" in tc["advice"].lower()
    flags = Target("linux", "aarch64").nim_flags()
    assert "--cpu:arm64" in flags and any("gcc.exe" in f for f in flags), (
        "naming only the CPU makes Nim emit ARM code and link it with the host gcc"
    )


# ---------------------------------------------------------------- the bare form

@pytest.mark.invariant("INV-BUILD-06")
def test_bare_path_dispatches_to_build_without_shadowing_subcommands():
    """`haru-pack somescript.py` means `haru-pack build somescript.py`, and every real
    subcommand still resolves.

    Red-path: implement this as a Typer callback with a positional argument instead. Click
    then binds the first token to that argument, and `haru-pack version` is parsed as
    "build the project named 'version'" — which is exactly what the first attempt did.
    """
    import subprocess
    import sys

    import typer.main

    from haru_pack import __version__
    from haru_pack.cli import app

    # No CliRunner, deliberately. `typer.testing` was not importable in CI on either 3.9 or
    # 3.13, and `click.testing` is not available either — typer 0.27 does not depend on
    # click at all (its requires are shellingham, rich, annotated-doc, colorama). A test for
    # this invariant must not rest on a test helper a dependency may stop shipping, and
    # re-implementing the routing rule in the test would only assert that the test agrees
    # with itself. So: the command table is read from the real group, and the routing is
    # exercised by running the real CLI.
    click_group = typer.main.get_command(app)
    for expected in ("build", "version", "doctor", "init", "verify", "bootstrap"):
        assert expected in click_group.commands, f"subcommand {expected} disappeared"

    def run_cli(*argv):
        return subprocess.run(
            [sys.executable, "-c", "from haru_pack.cli import app; app()", *argv],
            capture_output=True, text=True)

    # A registered subcommand must NOT be treated as a path. This is the assertion that
    # fails if the shortcut is ever reimplemented as a callback positional.
    r = run_cli("version")
    assert r.returncode == 0, f"`haru-pack version` broke: {r.stdout}{r.stderr}"
    assert __version__ in r.stdout, f"`version` did not print the version: {r.stdout!r}"

    # A path IS routed to build. Point it at a directory that cannot be discovered so the
    # run fails inside build (proving it got there) without doing 20 MB of work.
    r = run_cli("definitely-not-a-real-path-9f3a")
    assert r.returncode != 0
    combined = r.stdout + r.stderr
    # Which failure proves routing depends on the machine, and both answers are fine:
    #   * with a toolchain, `build` gets as far as discovery and complains about the path;
    #   * without one, `build` refuses at `find_nim()` first — and "Nim not found" is if
    #     anything the STRONGER evidence, because only `build` can emit it. A CI runner has
    #     no Nim, which is why this assertion had to learn about it the first time the
    #     invariant contract actually ran there.
    reached_build = ("discover" in combined or "No such" in combined
                     or "does not exist" in combined or "no pyproject" in combined
                     or "Nim not found" in combined)
    assert reached_build, f"a bare path did not reach `build`: {combined[:300]!r}"
    # ...and it must not have been mistaken for a subcommand.
    assert "No such command" not in combined, (
        f"the bare path was parsed as a subcommand, not routed to build: {combined[:200]!r}"
    )

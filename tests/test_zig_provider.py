"""INV-TOOL-02 — zig is the default compiler, pinned, and declinable.

The point of the default is that `uv tool install haru-pack` is the whole setup: no package
manager, no sudo. That is only safe because the compiler is pinned like every other artifact
haru-pack downloads and executes (`INV-SUPPLY-01`), so the pin check is tested as carefully
as the default is.
"""
from __future__ import annotations

import pytest

from haru_pack import toolchain as tc
from haru_pack.build import CC_ENV, CC_PROVIDERS, resolve_cc
from haru_pack.targets import KNOWN_TARGETS, Target


@pytest.mark.invariant("INV-TOOL-02")
def test_zig_is_the_default_compiler(monkeypatch):
    """Red-path: change `resolve_cc`'s default to "system" — this goes red, and a fresh
    install needs four system packages again."""
    monkeypatch.delenv(CC_ENV, raising=False)
    assert resolve_cc() == "zig"


@pytest.mark.invariant("INV-TOOL-02")
def test_the_flag_beats_the_env_and_the_env_beats_the_default(monkeypatch):
    monkeypatch.setenv(CC_ENV, "system")
    assert resolve_cc() == "system", "the env var is ignored"
    assert resolve_cc("zig") == "zig", "an explicit --cc did not win over the env"
    monkeypatch.delenv(CC_ENV, raising=False)
    assert resolve_cc("system") == "system"


@pytest.mark.invariant("INV-TOOL-02")
def test_an_unknown_provider_is_refused_with_the_choices(monkeypatch):
    from haru_pack.build import BuildError

    monkeypatch.delenv(CC_ENV, raising=False)
    with pytest.raises(BuildError) as e:
        resolve_cc("gcc-but-fancy")
    assert "zig" in str(e.value) and "system" in str(e.value)


@pytest.mark.invariant("INV-TOOL-02")
def test_a_macos_target_falls_back_to_the_system_compiler(monkeypatch):
    """zig's bundled macOS headers lack `fstore_t`, which Nim's posix module needs. Refusing
    outright would be worse than falling back: the operator asked for a Mac build."""
    monkeypatch.delenv(CC_ENV, raising=False)
    said = []
    assert resolve_cc(target="macos-aarch64", log=said.append) == "system"
    assert any("macos" in m.lower() or "zig" in m.lower() for m in said), (
        "the fallback was silent; the operator cannot tell which compiler ran"
    )


@pytest.mark.invariant("INV-TOOL-02")
@pytest.mark.parametrize("name,triple", [
    ("linux-x86_64", "x86_64-linux-gnu"),
    ("windows-x86_64", "x86_64-windows-gnu"),
    ("linux-aarch64", "aarch64-linux-gnu"),
    ("linux-armv7", "arm-linux-gnueabihf"),
])
def test_every_supported_target_maps_to_a_zig_triple(name, triple):
    assert Target.parse(name).zig_triple() == triple


@pytest.mark.invariant("INV-TOOL-02")
def test_macos_has_no_zig_triple_and_says_why():
    from haru_pack.targets import TargetError

    for name in [t for t in KNOWN_TARGETS if t.startswith("macos")]:
        tgt = Target.parse(name)
        assert not tgt.zig_can_build()
        with pytest.raises(TargetError) as e:
            tgt.zig_triple()
        assert "--cc system" in str(e.value), "the refusal does not say what to do instead"


@pytest.mark.invariant("INV-TOOL-02")
def test_an_unpinned_zig_is_refused(monkeypatch, tmp_path):
    """Red-path: drop the pin lookup from `install_zig`. haru-pack then downloads and
    EXECUTES an unverified compiler, which is precisely what INV-SUPPLY-01 forbids."""
    from haru_pack.archives import UnpinnedArtifact

    import haru_pack.pins as pins_mod

    monkeypatch.setattr(tc, "find_managed_zig", lambda: None)
    monkeypatch.setattr(pins_mod, "zig_digests", lambda: {})      # nothing pinned
    with pytest.raises(UnpinnedArtifact) as e:
        tc.install_zig(log=lambda _m: None)
    msg = str(e.value)
    assert "unverified" in msg
    assert "--cc system" in msg, "the refusal should offer the way out"


@pytest.mark.invariant("INV-TOOL-02")
def test_zig_is_pinned_for_this_build_host():
    """Not a hypothetical: this host must be able to get a verified zig, or the default is
    broken for whoever is running the suite."""
    import haru_pack.pins as pins
    from haru_pack.targets import host_arch, host_os

    host = f"{host_os()}-{host_arch()}"
    entry = (pins.zig_digests().get(tc.ZIG_VERSION) or {}).get(host)
    assert entry, f"no pinned zig {tc.ZIG_VERSION} for {host}"
    assert len(entry["sha256"]) == 64
    assert entry["url"].startswith("https://"), "a pin must name where the artifact comes from"


@pytest.mark.invariant("INV-TOOL-02")
def test_the_shim_translates_the_flag_zig_cannot_parse(tmp_path):
    """`nimcrypto` passes `-march=armv8-a+crypto`; zig's clang reads `-march` as a CPU name
    and dies with `unknown CPU: 'armv8'`. The shim is the only place that knows this."""
    shim = tc.zig_cc_shim("/usr/bin/zig", "aarch64-linux-gnu", tmp_path / "cc")
    body = shim.read_text()
    assert "-march=armv8-a+crypto" in body, "the flag zig cannot parse is not handled"
    assert "-mcpu=" in body, "it is not translated to a spelling zig accepts"
    assert "aarch64-linux-gnu" in body and "cc" in body


@pytest.mark.invariant("INV-TOOL-02")
def test_the_receipt_records_which_compiler_built_it(stub_toolchain, script_project, tmp_path,
                                                     monkeypatch):
    """zig is clang-based, so binaries are not byte-identical to GCC-built ones. An artifact
    that cannot be traced to its compiler cannot be reproduced, so the provider that resolve_cc
    chose must land in the receipt — checked by building, not by reading the source."""
    monkeypatch.delenv(CC_ENV, raising=False)
    out = tmp_path / "app"
    assert stub_toolchain.build(script_project, out, tier="thin")["cc"] == "zig", (
        "the receipt does not record the default provider")
    assert stub_toolchain.build(script_project, out, tier="thin", cc="system")["cc"] == "system", (
        "the receipt does not record an overridden provider")


@pytest.mark.invariant("INV-TOOL-02")
def test_providers_are_a_closed_set():
    assert CC_PROVIDERS == ("zig", "system")

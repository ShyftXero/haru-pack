"""INV-TOOL-01 — the kitchen sink is the default, and every part of it can be declined.

The default installs everything this host can cross-compile for, plus wine. That is a
deliberate ergonomic choice (`docs/PRINCIPLES.md` user 2: discovering a missing
cross-compiler three commands into a release is worse than installing one you did not need).
It is only defensible because it is *declinable*, so the selection logic is what these tests
pin — including the precedence, because an operator who guesses wrong here installs the
wrong hundreds of megabytes.
"""
from __future__ import annotations

import pytest

from haru_pack import toolchain as tc

NAMES = {c.name for c in tc.capabilities()}


@pytest.mark.invariant("INV-TOOL-01")
def test_the_default_is_everything():
    """Red-path: make `select_capabilities()` with no arguments return () and the kitchen
    sink silently becomes opt-in, which is the opposite of the documented promise."""
    caps, unknown = tc.select_capabilities()
    assert not unknown
    assert {c.name for c in caps} == NAMES, "the no-flags default is not the kitchen sink"
    assert "wine" in {c.name for c in caps}, (
        "wine is part of the kitchen sink by explicit decision; leaving it out makes "
        "`--wine` fail later on a host the operator believed was fully set up"
    )


@pytest.mark.invariant("INV-TOOL-01")
def test_minimal_declines_all_of_it():
    caps, unknown = tc.select_capabilities(minimal=True)
    assert caps == () and not unknown


@pytest.mark.invariant("INV-TOOL-01")
def test_naming_a_target_makes_the_selection_exact():
    """`--target linux-aarch64` means that and nothing else. If it merely ADDED to the
    kitchen sink, there would be no way to ask for one cross toolchain without wine."""
    caps, _ = tc.select_capabilities(targets=["linux-aarch64"])
    assert [c.name for c in caps] == ["linux-aarch64"]


@pytest.mark.invariant("INV-TOOL-01")
def test_with_adds_a_non_target_capability_exactly():
    caps, _ = tc.select_capabilities(with_=["wine"])
    assert [c.name for c in caps] == ["wine"]
    caps, _ = tc.select_capabilities(targets=["windows-x86_64"], with_=["wine"])
    assert {c.name for c in caps} == {"windows-x86_64", "wine"}


@pytest.mark.invariant("INV-TOOL-01")
def test_without_subtracts_from_the_default():
    caps, _ = tc.select_capabilities(without=["wine"])
    got = {c.name for c in caps}
    assert "wine" not in got
    assert got == NAMES - {"wine"}, "--without removed more than it was asked to"


@pytest.mark.invariant("INV-TOOL-01")
def test_an_unknown_name_is_reported_rather_than_ignored():
    """Silently ignoring `--without wein` would install wine and say nothing — the same
    class of failure as a config table nobody reads (INV-BUILD-07)."""
    _, unknown = tc.select_capabilities(without=["wein"])
    assert unknown == ("wein",)
    _, unknown = tc.select_capabilities(targets=["linux-risc"])
    assert unknown == ("linux-risc",)


@pytest.mark.invariant("INV-TOOL-01")
def test_capabilities_are_derived_from_the_target_table_not_duplicated():
    """A new target with a known cross package must become selectable for free; a hand-kept
    second list would drift from what `build` actually needs."""
    from haru_pack.targets import KNOWN_TARGETS, Target

    for name in NAMES - {"wine", "zig"}:   # zig is a capability, not a cross target
        assert name in KNOWN_TARGETS
        cc, pkg = Target.parse(name).cross_cc()
        cap = next(c for c in tc.capabilities() if c.name == name)
        assert cap.probe == cc and cap.packages == (pkg,)


@pytest.mark.invariant("INV-TOOL-01")
def test_the_host_compiler_is_not_a_capability():
    """It is not optional, so offering to decline it would be a lie."""
    assert not any(c.name in ("host", "cc", "build-essential") for c in tc.capabilities())
    # ...and it is still required regardless of what was selected
    import shutil
    if not any(shutil.which(c) for c in ("cc", "gcc", "clang")):
        assert tc.missing_packages(()) , "a host with no C compiler needs a package anyway"


@pytest.mark.invariant("INV-TOOL-01")
def test_missing_packages_only_asks_for_what_is_absent(monkeypatch):
    """One sudo prompt is the standing promise, so the package list is computed for the whole
    selection at once — and must not re-ask for something already installed."""
    monkeypatch.setattr(tc.shutil, "which", lambda n: "/usr/bin/" + n)   # everything present
    assert tc.missing_packages(tc.capabilities()) == []


@pytest.mark.invariant("INV-TOOL-01")
def test_install_weight_is_a_package_count_not_a_metapackage_size(monkeypatch):
    """The first version reported `apt-cache show`'s Installed-Size, which is the
    metapackage alone: it called wine "194 kB" when wine's cost is its dependency closure.
    A number that makes the kitchen sink look free is worse than no number.

    Asserted on BEHAVIOUR for a known input, not on the source text. An earlier version of
    this test grepped the source and matched the docstring explaining why the metapackage
    size is wrong — a trap that has now caught five tests in this repo.
    """
    seen = {}

    class R:
        stdout = ("Reading package lists...\n"
                  "The following NEW packages will be installed:\n"
                  "  a b c\n"
                  "0 upgraded, 16 newly installed, 0 to remove and 171 not upgraded.\n")

    def fake_run(cmd, **kw):
        seen["cmd"] = list(cmd)
        return R()

    monkeypatch.setattr(tc.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(tc.subprocess, "run", fake_run)

    assert tc.install_weight(["wine"]) == "16 pkgs", (
        "the weight is not the number of packages the closure would add"
    )
    assert "apt-get" in seen["cmd"] and "-s" in seen["cmd"], (
        "the closure must be resolved by simulating the install, not read off one package"
    )
    assert "wine" in seen["cmd"]


@pytest.mark.invariant("INV-TOOL-01")
def test_install_weight_is_silent_when_it_cannot_know(monkeypatch):
    """No apt, no guess. A fabricated size is worse than a blank column."""
    monkeypatch.setattr(tc.shutil, "which", lambda n: None)
    assert tc.install_weight(["wine"]) == ""
    assert tc.install_weight([]) == ""

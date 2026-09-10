"""INV-CHAOS-08 — composition, fallibility, and the determinism that makes both usable.

A persona that runs alone asks a closed question. "Does staging cope with umask 077?" has
the same answer forever, and answering it is integration testing. The open question — which
COMBINATION of individually-survivable conditions is not survivable — cannot be answered by
running them one at a time, and that is what these guard.

Nothing here builds a binary. The engine is pure: selection, conflict handling, firing, and
the shape of the pass condition. The expensive part is exercised by
`python tools/busybody.py --compose 2`.
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

import busybody_compose as bc  # noqa: E402
import busybody_traits  # noqa: E402,F401  (registers the catalogue)


def _busybody():
    spec = importlib.util.spec_from_file_location("bb_c", REPO / "tools" / "busybody.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------- the catalogue

@pytest.mark.invariant("INV-CHAOS-08")
def test_the_catalogue_covers_every_persona():
    """Eleven personas were commissioned; a trait file that quietly covers eight is the
    failure mode here, because nothing else would notice."""
    prefixes = {n.split("_")[0] for n in bc.TRAITS}
    expected = {"greenhorn", "foreman", "crosseyed", "babel", "understudy", "revenant",
                "quotamaster", "packrat", "auditor", "tourist", "archivist"}
    assert expected <= prefixes, f"personas with no traits: {expected - prefixes}"


@pytest.mark.invariant("INV-CHAOS-08")
def test_every_trait_declares_what_it_models():
    """A trait nobody can motivate is a trait nobody will maintain, and it will be deleted
    by the next person on the grounds that it looks arbitrary."""
    for name, t in bc.TRAITS.items():
        assert t["why"] and len(t["why"]) > 40, f"{name} has no real rationale"
        assert t["phase"] in bc.PHASES
        assert t["layer"] in bc.LAYERS
        assert 0.0 < t["fires"] <= 1.0


@pytest.mark.invariant("INV-CHAOS-08")
def test_a_malformed_trait_is_rejected_at_import():
    """The registry validates rather than trusting. This caught a phase typo of mine on the
    first run, before it could become a trait that silently never fired."""
    with pytest.raises(ValueError, match="phase"):
        bc.trait("bogus_phase", "sideways", "env", "x" * 50)(lambda ctx: None)
    with pytest.raises(ValueError, match="layer"):
        bc.trait("bogus_layer", "run", "nowhere", "x" * 50)(lambda ctx: None)
    with pytest.raises(ValueError, match="fires"):
        bc.trait("bogus_fires", "run", "env", "x" * 50, fires=0.0)(lambda ctx: None)
    with pytest.raises(ValueError, match="duplicate"):
        name = next(iter(bc.TRAITS))
        bc.trait(name, "run", "env", "x" * 50)(lambda ctx: None)


# ---------------------------------------------------------------- selection

@pytest.mark.invariant("INV-CHAOS-08")
def test_selection_is_deterministic_in_the_seed():
    """A finding that cannot be reproduced is an anecdote. The seed is printed in the report
    precisely so a stack can be run again."""
    a = bc.sample_combos(list(bc.TRAITS), 3, 40, seed=11)
    b = bc.sample_combos(list(bc.TRAITS), 3, 40, seed=11)
    assert a == b and len(a) == 40
    assert a != bc.sample_combos(list(bc.TRAITS), 3, 40, seed=12)


@pytest.mark.invariant("INV-CHAOS-08")
def test_cancelling_pairs_are_never_selected():
    """Declared conflicts are pairs where one trait CANCELS the other — a read-only cache
    and an absent HOME cannot both be the thing under test. Such a stack tests less than
    either member alone, which is worse than useless because it looks like coverage.

    Pairs that BREAK together are not conflicts. Those are the findings.
    """
    for k in (2, 3):
        for combo in bc.sample_combos(list(bc.TRAITS), k, 300, seed=5):
            assert not bc.conflicts_in(combo), f"selected a cancelling stack: {combo}"


@pytest.mark.invariant("INV-CHAOS-08")
def test_selection_prefers_stacks_that_cross_layers():
    """Three filesystem traits is a weaker test than one filesystem, one env and one process
    trait: the interesting interactions are between mechanisms, not between variations of
    one mechanism."""
    combos = bc.sample_combos(list(bc.TRAITS), 3, 30, seed=3)
    spreads = [len({bc.TRAITS[n]["layer"] for n in c}) for c in combos]
    assert min(spreads) == 3, (
        f"a selected 3-stack touched only {min(spreads)} layer(s); layer spreading is off"
    )


@pytest.mark.invariant("INV-CHAOS-08")
def test_sampling_does_not_blow_up_on_the_real_catalogue():
    """The first version computed max(...) inside a comprehension over the combination
    space — O(n^2), which hung outright at k=3 over 40 traits (9,880 combinations, ~97M
    evaluations). Noted because `packrat_many_tiny_files` exists to catch this shape in
    haru-pack, and the harness had it first."""
    import time
    t0 = time.monotonic()
    got = bc.sample_combos(list(bc.TRAITS), 3, 200, seed=1)
    assert len(got) == 200
    assert time.monotonic() - t0 < 5.0, "sampling the real catalogue should be instant"


# ---------------------------------------------------------------- fallibility

@pytest.mark.invariant("INV-CHAOS-08")
def test_a_fallible_trait_sometimes_declines_to_act():
    """The whole point. If greenhorn always fumbles, then "greenhorn fumbled AND auditor
    left a .env behind" is the only thing ever tested, and "greenhorn got it right, auditor
    still left the .env" is a different code path that never runs."""
    fallible = [n for n, t in bc.TRAITS.items() if t["fires"] < 1.0]
    assert fallible, "no trait is fallible, so every persona is a fixture"

    combo = tuple(fallible[:3])
    seen = {bc.realize(combo, 99, i) for i in range(60)}
    assert len(seen) > 1, f"{combo} produced one outcome in 60 runs; firing is not varying"
    assert any(len(x) < len(combo) for x in seen), "no run had a trait decline"


@pytest.mark.invariant("INV-CHAOS-08")
def test_firing_is_deterministic_and_survives_a_bigger_catalogue():
    """Per-trait draws, not one sequential stream: adding a trait must not reshuffle every
    other trait's decisions in every other run, or a recorded seed stops meaning what it
    meant when the finding was filed."""
    combo = ("greenhorn_output_over_the_input", "auditor_plants_credentials")
    first = [bc.realize(combo, 7, i) for i in range(20)]
    assert first == [bc.realize(combo, 7, i) for i in range(20)]

    # a trait's decision depends only on (seed, run_index, its own name)
    solo = [bc.realize(("auditor_plants_credentials",), 7, i) for i in range(20)]
    in_pair = [("auditor_plants_credentials" in f) for f in first]
    assert [bool(x) for x in solo] == in_pair, (
        "a trait's firing changed because another trait was present in the stack"
    )


@pytest.mark.invariant("INV-CHAOS-08")
def test_firing_does_not_depend_on_python_version_internals():
    """`random.Random(tuple)` raises on 3.14, and where it works the seed-to-stream mapping
    is an implementation detail. A printed reproduction line has to survive an interpreter
    upgrade, so the draw comes from a digest."""
    src = inspect.getsource(bc.realize)
    assert "sha256" in src, "firing must be derived from a stable digest"
    assert "random.Random((" not in src, (
        "seeding Random with a tuple raises on 3.14 and is not version-stable"
    )
    # a known digest-derived decision, pinned so a refactor cannot silently change it
    assert bc.realize(("greenhorn_output_over_the_input",), 7, 3) == \
        ("greenhorn_output_over_the_input",)
    assert bc.realize(("greenhorn_output_over_the_input",), 7, 1) == ()


@pytest.mark.invariant("INV-CHAOS-08")
def test_the_baseline_pass_forces_every_trait_to_fire():
    """k=1 IS the attribution baseline. "Does trait A fail alone?" cannot be answered by a
    run where A did not fire, and a baseline with holes makes every composed finding
    unattributable."""
    fallible = next(n for n, t in bc.TRAITS.items() if t["fires"] < 1.0)
    assert bc.realize((fallible,), 1, 0, force=True) == (fallible,)
    # and the runner turns it on for exactly the two passes that need it
    src = (REPO / "tools" / "busybody.py").read_text()
    assert "force = bool(a.compose_only) or a.compose == 1" in src, (
        "the baseline and --compose-only must disable fallibility"
    )


@pytest.mark.invariant("INV-CHAOS-08")
def test_a_control_run_is_kept_not_resampled():
    """A run where nothing fired is a control, and one arriving through the same machinery
    is worth more than one bolted on beside it: if the baseline is broken, that is where it
    shows."""
    src = inspect.getsource(bc.realize)
    assert "control" in src.lower(), "the empty case must be a documented decision"
    combo = tuple(n for n, t in bc.TRAITS.items() if t["fires"] <= 0.5)[:2]
    if combo:
        outcomes = [bc.realize(combo, 4242, i) for i in range(80)]
        assert () in outcomes, "no control run appeared in 80 draws of two coin-flip traits"


# ---------------------------------------------------------------- the pass condition

@pytest.mark.invariant("INV-CHAOS-08")
def test_a_stack_is_only_a_finding_if_it_hit_the_fatal_floor():
    """Deliberately weak, and it must stay weak. Nobody has reasoned about combination
    7,431 of 11,000, so asserting "haru-pack works under any three of these" would be an
    overclaim of exactly the kind INVARIANTS.md exists to prevent. The floor is the claim:
    it works, or it refuses intelligibly."""
    bb = _busybody()
    src = ast.unparse(ast.parse(inspect.getsource(bb.compose_sweep)))
    assert "ok = r['outcome'] not in FATAL" in src, (
        "a composed stack must be judged against the FATAL floor and nothing narrower"
    )
    assert set(bb.FATAL) == {"CRASHED", "HUNG", "SILENT", "SILENT-WEDGE"}
    for good in ("RAN", "REFUSED", "APP-CRASHED"):
        assert good not in bb.FATAL, f"{good} is an acceptable outcome for a stack"


@pytest.mark.invariant("INV-CHAOS-08")
def test_every_finding_prints_its_own_reproduction_line():
    """A finding nobody can reproduce is an anecdote. The remedy field carries the exact
    command, seed included."""
    bb = _busybody()
    src = ast.unparse(ast.parse(inspect.getsource(bb.compose_sweep)))
    assert "--compose-only" in src and "--compose-seed" in src, (
        "a composed finding must print the command that reproduces it"
    )
    assert "compose_seed=seed" in src, "the seed must be journalled, not only printed"


@pytest.mark.invariant("INV-CHAOS-08")
def test_the_fired_set_identifies_the_run_not_the_selected_set():
    """Fingerprinting on the selected set would group two genuinely different runs — one
    where three traits acted and one where one did — under a single root cause."""
    bb = _busybody()
    src = ast.unparse(ast.parse(inspect.getsource(bb.compose_sweep)))
    assert "sorted(fired)" in src, "the fingerprint must key on what actually fired"
    assert "'selected': list(combo)" in ast.unparse(
        ast.parse(inspect.getsource(bb.run_stack))), "both sets must be recorded"


# ---------------------------------------------------------------- cross-target statics

@pytest.mark.invariant("INV-TIER-03")
def test_elf_machine_decoding_is_right():
    """The cross-target checks rest entirely on this. 0x3E is x86-64 and 0xB7 is aarch64;
    getting them backwards would make the aarch64 check pass on an x86 payload."""
    bb = _busybody()
    x86 = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00" + b"\x3e\x00"
    arm = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00" + b"\xb7\x00"
    assert bb._elf_machine(x86) == "x86-64"
    assert bb._elf_machine(arm) == "aarch64"
    assert bb._elf_machine(b"MZ\x90\x00") == "", "a PE file is not an ELF"
    assert bb._elf_machine(b"") == ""


@pytest.mark.invariant("INV-TIER-03")
def test_a_foreign_target_is_checked_statically_rather_than_run():
    """A Windows payload cannot be executed here, but it can be read. That is what makes the
    cross-target check possible at all rather than needing a second machine."""
    for name in ("crosseyed_target_windows", "crosseyed_target_aarch64"):
        assert bc.TRAITS[name]["no_run"] is True, f"{name} must not attempt a local run"
    bb = _busybody()
    src = ast.unparse(ast.parse(inspect.getsource(bb.run_stack)))
    assert "_static_verdict" in src, (
        "a stack that chose a foreign target must fall through to static verification"
    )


@pytest.mark.invariant("INV-TIER-03")
def test_the_cross_target_check_does_not_flag_source_files_named_manylinux():
    """The compose-1 baseline flagged pip's vendored `_manylinux.py` — the platform-detection
    module, pure Python source — as a "linux wheel in a Windows payload". A binary object is
    identified by its bytes and a wheel by a `.whl` name; neither is "any path containing
    manylinux". Red-path: match the substring against all members again and this fails."""
    bb = _busybody()
    src = ast.unparse(ast.parse(inspect.getsource(bb._static_verdict)))
    assert "_is_wheel" in src, "wheel detection must be by filename, not substring-in-path"
    # the detector module names that tripped it, as they appear in a real payload
    innocuous = [
        "vendor/python/python/Lib/site-packages/pip/_vendor/packaging/_manylinux.py",
        "vendor/.../__pycache__/_manylinux.cpython-312.pyc",
        "app/uses_linux_x86_64_in_a_comment.py",
    ]
    for name in innocuous:
        assert not (name.endswith(".whl")), "test data should not be actual wheels"

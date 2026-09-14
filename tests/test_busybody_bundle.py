"""Forensic bundles: the state that EXPLAINS a finding, not only the record of it.

The rules these guard are all one rule wearing different hats — a collector runs when
something has ALREADY gone wrong, so it may never make things worse. It must not raise (that
turns a finding into a CASE-ERROR and loses both), must not block (a collector that hangs
while investigating a hang is a comedy this harness cannot afford), and must not perturb the
subject (a finding investigated by perturbing it further is not the finding you had).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

import busybody_bundle as bb  # noqa: E402


def test_collect_returns_every_section_even_with_nothing_to_look_at():
    """A missing section and an empty one look identical, and only one means "nothing here".

    So every collector returns a string, always, and the string explains itself when it could
    not collect. This is the difference between a reader concluding "the staged tree was
    empty" and "we never looked".
    """
    b = bb.collect(work=None, cache=None, reason="unit test")
    for key in ("loadavg", "scratch", "open_files", "staged_tree", "process_tree",
                "collected_at", "collection_seconds", "reason"):
        assert key in b, f"collect() dropped {key}"
    for key in ("loadavg", "scratch", "open_files", "staged_tree", "process_tree"):
        assert isinstance(b[key], str) and b[key], f"{key} came back empty rather than saying so"


def test_no_collector_raises_on_rubbish_input():
    """The failure path is the only path this code runs on."""
    nowhere = Path("/nonexistent/definitely/not/here")
    assert isinstance(bb.staged_tree(nowhere), str)
    assert isinstance(bb.staged_tree(None), str)
    assert isinstance(bb.scratch(nowhere), str)
    assert isinstance(bb.open_files(2**30), str)          # a pid that cannot exist
    assert isinstance(bb.process_tree(None), str)
    assert isinstance(bb.loadavg(), str)


def test_collection_is_bounded():
    """Evidence that arrives after the operator gave up reading is evidence nobody has."""
    b = bb.collect(work=Path("/tmp"), cache=None, reason="timing")
    budget = 6 * bb._PER_COLLECTOR_S
    assert b["collection_seconds"] < budget, (
        f"the bundle took {b['collection_seconds']}s against a {budget}s ceiling. A "
        f"collector is blocking; find it before it blocks on the failure path."
    )


def test_a_half_staged_tree_is_called_out_rather_than_left_to_be_noticed(tmp_path):
    """The `.tmp-<pid>` directory beside a committed one IS the finding, for a staging fault.

    A stage that died between extract and the atomic rename leaves exactly that shape, and
    it is the thing a reader scanning a directory listing will scroll past.
    """
    base = tmp_path / "haru-pack"
    (base / "abc123").mkdir(parents=True)
    (base / "abc123.tmp-4242").mkdir(parents=True)
    out = bb.staged_tree(tmp_path)
    assert "abc123" in out and "tmp-4242" in out
    assert "half-staged" in out, (
        "a half-staged tmp directory was listed but not called out; that is the one shape "
        "in this listing that is itself evidence"
    )


def test_open_files_does_not_shell_out_to_lsof():
    """`lsof` with no arguments walks every mount and blocks on a dead NFS mount.

    That is the single thing a collector on the failure path must never do, so this is a
    check on the mechanism rather than on the output.
    """
    import inspect

    src = inspect.getsource(bb.open_files)
    assert "lsof" not in src or "never with lsof" in src, (
        "open_files reaches for lsof. Read /proc/<pid>/fd instead; it cannot block on "
        "anything but the kernel."
    )
    assert "/proc/" in src


def test_a_bundle_is_written_beside_the_artifacts_and_failure_is_survivable(tmp_path):
    """Failing to write the bundle must never fail the case."""
    import json

    p = bb.write_bundle(tmp_path / "findings" / "x", {"reason": "test", "loadavg": "0"})
    assert p and Path(p).name == bb.BUNDLE_NAME
    assert json.loads(Path(p).read_text())["reason"] == "test"

    # an unwritable destination returns "" rather than raising
    assert bb.write_bundle(Path("/proc/nope/nope"), {"a": 1}) == ""


def test_the_stall_declaration_collects_while_the_children_are_still_alive():
    """The one moment in this harness where the interesting state has not evaporated.

    Ten seconds after a stall is declared every child has been killed and "stuck on what?"
    is unanswerable forever. Collecting at the declaration is the whole difference between a
    forensic bundle and a slower copy of the artifacts.
    """
    import inspect
    import textwrap

    import busybody_stall

    src = textwrap.dedent(inspect.getsource(busybody_stall.StallWatch._declare))
    assert "Ctx.forensics" in src, (
        "the stall declaration no longer collects a bundle. By the time the case returns, "
        "every process it is about is gone."
    )


def test_the_stall_record_is_written_before_the_bundle_is_collected():
    """Ordering inside `_declare`, pinned. This was a real regression, found the hard way.

    `_declare` runs on the WATCHDOG THREAD. `self.stalled_at` is set at the top of it, and
    that is what the case on the main thread polls for — so the instant it is set, the main
    thread may finish the case and call `Ctx.clear()`. Everything `_declare` does after that
    point finds `Ctx.work is None` and is silently dropped, because both `observe` and
    `forensics` no-op outside a case.

    Collecting the bundle first widened that window from microseconds to seconds (each
    collector is bounded at ~5s), and the stall record — the thing that EXPLAINS the
    finding — was lost while the stall itself was still declared. Reproduced 3/3 with the
    bundle first and 5/5 clean with the record first, on 2026-09-14.

    So: the cheap load-bearing record first, the aid to reading it second. Nothing
    perishable is given up, because the children are killed by `herd_collect` later and not
    here.
    """
    import inspect
    import textwrap

    import busybody_stall

    src = textwrap.dedent(inspect.getsource(busybody_stall.StallWatch._declare))
    observe_at = src.index('Ctx.observe("stall"')
    forensics_at = src.index("Ctx.forensics(")
    assert observe_at < forensics_at, (
        "the forensic bundle is collected BEFORE the stall record is written. _declare runs "
        "on the watchdog thread and the main thread may call Ctx.clear() as soon as "
        "stalled_at is set, so anything slow in between loses the record that explains the "
        "finding. Write the record first."
    )

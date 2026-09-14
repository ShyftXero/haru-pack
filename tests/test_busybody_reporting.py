"""The deterministic markdown report, `--replay` and `--author` (T-015).

Three tools that answer three different questions about a body of runs, and the guards here
are mostly about what each one must refuse to claim:

  * the markdown report must be byte-identical across regenerations, or it cannot be diffed
    and committing it generates noise forever;
  * `--replay` must say when a row cannot be reproduced, rather than emitting a confident
    command for a run that never happened;
  * `--author` must propose and never run, because the composed lines it proposes are
    hours of somebody's machine.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

import busybody_author as ba      # noqa: E402
import busybody_markdown as bmd   # noqa: E402
import busybody_replay as brp     # noqa: E402


def _result(**kw) -> dict:
    base = {"name": "a_case", "persona": "forger", "fixture": "synthetic",
            "outcome": "RAN", "expect": ["RAN"], "ok": True, "indeterminate": False,
            "severity": "note", "fingerprint": "abc123def456", "rc": 0, "seconds": 1.0,
            "blame": "none", "seed": 0, "post_stall": False, "stall_id": "",
            "inv": "", "remedy": "", "why": "because", "stdout": "", "stderr": ""}
    return {**base, **kw}


# ---------------------------------------------------------------- determinism


def test_the_markdown_report_is_byte_identical_across_regenerations():
    """Two calls, same input, same bytes. The only check that defends the actual property.

    Asserting "there is no timestamp in the output" tests ONE way of breaking determinism.
    Comparing two renders tests the property.
    """
    results = [_result(name="z_case", persona="vandal"),
               _result(name="a_case", ok=False, outcome="CRASHED", severity="critical")]
    first = bmd.render(results, "synthetic", run_id="bb20260913-120000")
    second = bmd.render(results, "synthetic", run_id="bb20260913-120000")
    assert first == second, "the markdown report is not deterministic"


def test_input_order_does_not_change_the_report():
    """Run order is an artefact of scheduling — it changes with --jobs.

    A report that reorders itself when you add a worker is not diffable, so every section
    sorts by an explicit key rather than trusting the order results arrived in.
    """
    a = _result(name="a_case", ok=False, outcome="CRASHED", severity="critical")
    b = _result(name="b_case", ok=False, outcome="SILENT", severity="critical")
    assert bmd.render([a, b], "synthetic", "r") == bmd.render([b, a], "synthetic", "r")


def test_findings_sort_by_severity_before_name():
    """A reader who stops after the first finding must have read the worst one."""
    warn = _result(name="aaa", ok=False, outcome="REFUSED", severity="warning")
    crit = _result(name="zzz", ok=False, outcome="CRASHED", severity="critical")
    out = bmd.render([warn, crit], "synthetic", "r")
    assert out.index("`zzz`") < out.index("`aaa`"), (
        "a warning sorted above a critical; the first finding a reader sees must be the "
        "worst one, not the alphabetically first"
    )


def test_a_backtick_in_captured_output_cannot_break_out_of_its_fence():
    """Output from a failing launcher is arbitrary bytes, and arbitrary bytes contain ```.

    A fence broken by its own contents turns the rest of the report into code, which is the
    kind of corruption that looks like a rendering quirk and hides a finding.
    """
    nasty = "before\n```\nstill inside\n````\nalso inside\nafter"
    out = bmd.render([_result(ok=False, outcome="CRASHED", stderr=nasty)], "s", "r")
    assert "still inside" in out and "also inside" in out
    fence = "`" * 5
    assert fence in out, (
        "the fence was not widened past the longest backtick run in the payload, so the "
        "captured output escapes its block"
    )


def test_a_broken_baseline_is_stated_before_anything_else():
    """A campaign whose golden run failed has not measured fault tolerance."""
    golden = _result(name="(golden run)", golden=True, ok=False, outcome="CRASHED",
                     severity="critical")
    out = bmd.render([golden], "(stacks)", "r")
    assert "baseline is broken" in out
    assert out.index("baseline is broken") < out.index("## Findings"), (
        "the broken-baseline warning must come before the findings it invalidates"
    )


def test_indeterminate_results_get_their_own_section_and_leave_the_counts_alone():
    unresolved = _result(name="u", ok=False, indeterminate=True, outcome="INDETERMINATE")
    out = bmd.render([_result(), unresolved], "synthetic", "r")
    assert "## Indeterminate (1)" in out
    assert "| findings | 0 |" in out, "an indeterminate result was counted as a finding"
    assert "1 of 1 settled" in out, "an indeterminate result was left in the denominator"


def test_test_infrastructure_findings_are_visually_separated_from_product_findings():
    out = bmd.render([_result(name="s", inert=["a_trait"])], "(stacks)", "r")
    assert "Test-infrastructure findings" in out
    assert "not about haru-pack" in out


# ---------------------------------------------------------------- replay


def test_replay_reconstructs_a_composed_stack_from_what_fired_not_what_was_selected():
    """A trait that declined to act was not part of what happened."""
    cmd = brp.command_for({"fixture": "(stack)", "seed": 42,
                           "selected": ["a", "b", "c"], "fired": ["a", "c"]})
    assert "--compose-only a,c" in cmd and "--compose-seed 42" in cmd
    assert ",b" not in cmd


def test_replay_refuses_to_invent_a_command_for_an_unreproducible_row():
    """Absence and emptiness are different facts, and conflating them was a real bug.

    `"fired": []` means nothing fired — a golden run. No `fired` key at all means nobody
    recorded it, and the stack is unrecoverable. The first draft of `command_for` printed a
    confident golden-run reproduction for the second case, on a real row in this project's
    own ledger.
    """
    unrecoverable = brp.command_for({"fixture": "(stack)", "seed": 0})
    assert "NOT REPRODUCIBLE" in unrecoverable

    golden = brp.command_for({"fixture": "(stack)", "seed": 0, "golden": True, "fired": []})
    assert "NOT REPRODUCIBLE" not in golden
    assert "golden run" in golden


def test_replay_matches_on_a_signature_prefix(tmp_path):
    """Nobody copies sixteen hex characters correctly."""
    import json

    led = tmp_path / "f.jsonl"
    led.write_text("\n".join(json.dumps(r) for r in [
        {"fingerprint": "deadbeef12345678", "at": 1.0, "name": "one"},
        {"fingerprint": "deadbeef12345678", "at": 2.0, "name": "two"},
        {"fingerprint": "0ther00000000000", "at": 3.0, "name": "three"},
    ]) + "\n")
    hits = brp.find_rows("deadbe", path=led)
    assert [h["name"] for h in hits] == ["one", "two"], "prefix match or ordering is wrong"
    assert hits[-1]["at"] == 2.0, "rows must come back oldest-first so [-1] is the newest"


# ---------------------------------------------------------------- author


def test_author_reads_journals_not_the_ledger(tmp_path):
    """The ledger holds FINDINGS, so a case that always passes is absent from it.

    Asking the ledger "what has run?" reports every healthy case as never-run, which is the
    exact inversion of the question `--author` exists to answer.
    """
    import inspect

    src = inspect.getsource(ba.coverage)
    assert "journal" in src.lower() or "_journal_records" in src
    assert "ledger_rollup" not in src


def test_author_proposes_and_never_runs():
    """`--compose` at k=3 over this catalogue is hours of somebody's machine."""
    import inspect

    src = inspect.getsource(ba)
    for forbidden in ("subprocess", "os.system", "run_stack("):
        assert forbidden not in src, (
            f"busybody_author reaches for {forbidden}. It writes a script to stdout and the "
            f"person reading it decides; a tool that closes a gap unattended spends hours on "
            f"a conclusion nobody asked for."
        )


def test_the_authored_script_is_deterministic():
    """Run twice on the same history, emit the same script, or it cannot be reviewed."""
    cov = {"runs": 2, "results": 10, "case_total": 3, "trait_total": 2, "pair_total": 1,
           "never_run_cases": ["b", "a"], "never_fired_traits": ["t2", "t1"],
           "never_paired_layers": []}
    assert ba.script_for(cov) == ba.script_for(dict(cov))


def test_the_authored_script_says_a_gap_is_not_a_defect():
    """The claim being made is that the silence is unearned, not that anything is broken."""
    cov = {"runs": 1, "results": 1, "case_total": 1, "trait_total": 0, "pair_total": 0,
           "never_run_cases": ["never_ran"], "never_fired_traits": [],
           "never_paired_layers": []}
    text = "\n".join(ba.script_for(cov))
    assert "untested opinion" in text
    assert "never_ran" in text


def test_full_coverage_says_so_rather_than_emitting_an_empty_script():
    """An empty script and a script with nothing to propose look identical to a reader."""
    cov = {"runs": 5, "results": 100, "case_total": 3, "trait_total": 2, "pair_total": 1,
           "never_run_cases": [], "never_fired_traits": [], "never_paired_layers": []}
    text = "\n".join(ba.script_for(cov))
    assert "Nothing to propose" in text
    assert "coverage, not assurance" in text

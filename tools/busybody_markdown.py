"""A deterministic markdown report. No model, no network, no clock.

Adopted from lotek's `tests/busybody/report.py` (T-015). haru-pack already writes a plain
text report a human can read on its own; this is the same content in a form a diff, a PR
comment and a static site can all use.

## What "deterministic" buys, and why it is a rule rather than a nicety

Two runs of the same sweep over the same results produce BYTE-IDENTICAL markdown. That makes
the report diffable, and a diffable report turns "what changed since last week" from an
exercise in reading two documents into `diff`. It is also the only way a report can be
committed or attached to a PR without generating noise on every regeneration.

So three things are banned in here, and each has been a bug in somebody's report generator:

  * **The wall clock.** No "generated at". The run id already carries the time the RUN
    happened, which is the time anybody cares about; a generation timestamp changes on
    every regeneration and changes nothing else.
  * **Unordered iteration.** Every group, count and table is sorted by an explicit key.
    A dict that happens to preserve insertion order is not a sort, and the day the input
    arrives in a different order the diff is the whole document.
  * **Absolute paths.** They embed the machine. `paths.relative()` or nothing.

## Why it is not a template

A template engine is a dependency, and the thing being templated is a document whose
structure IS the argument being made: counts first, then the caveat if there is one, then
findings ordered by severity. Text assembled in the order the reader needs it keeps that
argument visible in the code. This is the same reasoning as the plain-text report next door,
which is why the two share `OUTCOME_MEANING` rather than describing outcomes twice.
"""
from __future__ import annotations

from pathlib import Path

from busybody_config import FATAL
from busybody_ledger import is_finding
from busybody_report import OUTCOME_MEANING

__all__ = ["render", "write_markdown"]


def _fence(text: str, lang: str = "") -> list:
    """A fenced block that cannot be broken by its own contents.

    Output from a failing launcher is arbitrary bytes, and arbitrary bytes contain
    backticks. The fence is longer than the longest run inside it.
    """
    longest = 0
    run = 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    bar = "`" * max(3, longest + 1)
    return [f"{bar}{lang}", *text.splitlines(), bar]


def _counts(results: list) -> tuple:
    bad = [r for r in results if is_finding(r)]
    unresolved = [r for r in results if r.get("indeterminate")]
    return bad, unresolved


def _header(run_id: str, fixture: str, results: list, interrupted: bool) -> list:
    bad, unresolved = _counts(results)
    settled = len(results) - len(unresolved)
    L = [f"# busybody run `{run_id or '(unrecorded)'}`",
         "",
         "| | |",
         "|---|---|",
         f"| fixtures | {fixture} |",
         f"| cases run | {len(results)} |",
         f"| as expected | {settled - len(bad)} of {settled} settled |",
         f"| findings | {len(bad)} |",
         f"| indeterminate | {len(unresolved)} |",
         ""]
    if interrupted:
        L += ["> **This run was interrupted.** What follows is what completed before it",
              "> stopped, not the whole suite. Do not read the counts above as a result.",
              ""]
    golden = next((r for r in results if r.get("golden")), None)
    if golden is not None:
        if golden["ok"]:
            L += [f"Golden run: **{golden['outcome']}**. The un-perturbed baseline works, so "
                  f"a finding below is attributable to its faults.", ""]
        else:
            L += [f"> **The baseline is broken.** The golden run returned "
                  f"`{golden['outcome']}`.",
                  "> Every finding below is suspect: nothing in this campaign separates",
                  "> \"the fault broke it\" from \"it was already broken\". Fix this first.",
                  ""]
    return L


# Findings are ordered by severity and then by name. NOT by the order they ran: run order is
# an artefact of scheduling — it changes with --jobs — and a report that reorders itself when
# you add a worker is not diffable.
_SEVERITY_RANK = {"critical": 0, "warning": 1, "note": 2}


def _finding(r: dict, n: int) -> list:
    L = [f"### {n}. `{r['persona']}` / `{r['name']}`",
         "",
         f"**{r['outcome']}** — {OUTCOME_MEANING.get(r['outcome'], 'unknown outcome')}",
         ""]
    rows = [("severity", r.get("severity", "?")),
            ("expected", " or ".join(r.get("expect") or []) or "—"),
            ("fixture", r.get("fixture", "?")),
            ("blame", r.get("blame", "?")),
            ("exit", str(r.get("rc"))),
            ("signature", f"`{r.get('fingerprint', '')}`")]
    if r.get("inv"):
        rows.append(("invariant", r["inv"]))
    if r.get("artifacts"):
        rows.append(("artifacts", f"`{r['artifacts']}`"))
    if r["outcome"] in FATAL:
        rows.append(("note", "on the FATAL floor — a finding regardless of what was expected"))
    L += ["| | |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in rows]
    L += ["", "**What this case simulates**", "",
          " ".join((r.get("why") or "").split()) or "_(not recorded)_", ""]
    if r.get("remedy"):
        L += ["**What to do**", "", " ".join(r["remedy"].split()), ""]
    for stream in ("stderr", "stdout"):
        if r.get(stream):
            L += [f"<details><summary>{stream}</summary>", ""]
            L += _fence(r[stream])
            L += ["", "</details>", ""]
    return L


def _findings_section(results: list) -> list:
    bad, _ = _counts(results)
    if not bad:
        return ["## No findings", "",
                "Every case behaved as expected. Note what that does and does not mean:",
                "these are the faults somebody thought of. A clean run is evidence, not",
                "proof — adding a case that fails is worth more than re-running these.",
                ""]
    order = sorted(bad, key=lambda r: (_SEVERITY_RANK.get(r.get("severity"), 9), r["name"],
                                       r.get("fixture", "")))
    L = [f"## Findings ({len(bad)})", ""]
    for n, r in enumerate(order, 1):
        L += _finding(r, n)
    return L


def _indeterminate_section(results: list) -> list:
    _, unresolved = _counts(results)
    if not unresolved:
        return []
    L = [f"## Indeterminate ({len(unresolved)})", "",
         "The harness stopped observing before these resolved, so they may or may not have",
         "taken effect. Jepsen calls this `:info`. They are counted as neither a pass nor a",
         "finding, because counting them either way is a claim nobody can support.",
         "",
         "| persona | case | fixture |", "|---|---|---|"]
    L += [f"| {r['persona']} | {r['name']} | {r.get('fixture', '?')} |"
          for r in sorted(unresolved, key=lambda r: (r["persona"], r["name"]))]
    L.append("")
    return L


def _harness_section(results: list) -> list:
    """Test-infrastructure findings. Kept visually apart, because they are not about the
    product and a reader skimming for defects must not pick them up as such."""
    rows = sorted({(r["name"], t) for r in results for t in (r.get("inert") or [])})
    if not rows:
        return []
    L = [f"## Test-infrastructure findings ({len(rows)})", "",
         "**About busybody, not about haru-pack.** A fault fired and left the injection",
         "point unchanged, so it never reached the target — and whatever that run returned",
         "is not evidence about it. A swallowed fault produces silence, and silence looks",
         "exactly like the product absorbing the fault correctly.",
         "",
         "| fault | in stack |", "|---|---|"]
    L += [f"| `{trait}` | `{stack}` |" for stack, trait in rows]
    L.append("")
    return L


def _summary_table(results: list) -> list:
    L = ["## Every case", "",
         "| persona | case | fixture | outcome | verdict |", "|---|---|---|---|---|"]
    for r in sorted(results, key=lambda r: (r["persona"], r["name"], r.get("fixture", ""))):
        verdict = ("unknown" if r.get("indeterminate")
                   else "ok" if r["ok"] else "**FINDING**")
        L.append(f"| {r['persona']} | `{r['name']}` | {r.get('fixture', '?')} | "
                 f"{r['outcome']} | {verdict} |")
    L.append("")
    return L


def render(results: list, fixture: str, run_id: str = "",
           interrupted: bool = False) -> str:
    """The whole report. A pure function of its arguments — no clock, no environment.

    Pure so it can be tested by comparing two calls, which is the only check that actually
    defends determinism. Asserting "there is no timestamp" tests one way of breaking it.
    """
    L = _header(run_id, fixture, results, interrupted)
    L += _findings_section(results)
    L += _indeterminate_section(results)
    L += _harness_section(results)
    L += _summary_table(results)
    L += ["---", "",
          "Reproduce one case: `python tools/busybody.py --case <name> --keep`",
          "",
          "Group repeats of a finding across runs: `python tools/busybody.py --triage`",
          ""]
    return "\n".join(L) + "\n"


def write_markdown(results: list, fixture: str, path: Path, run_id: str = "",
                   interrupted: bool = False) -> None:
    Path(path).write_text(render(results, fixture, run_id, interrupted), encoding="utf-8")

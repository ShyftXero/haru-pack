"""Answer the questions about a busybody run, so nobody has to read the journal.

Every analysis in this file was first done by hand, with throwaway one-liners over
`journal.jsonl`. That works exactly once. It does not survive the person who wrote the
one-liner, it cannot be re-run six months later to compare, and it burns whoever repeats it
— a human reading a 900-line JSONL file, or a model ingesting it as tokens — for an answer
the machine can compute in a millisecond.

So the questions are the tool now:

    --analyze     did this sweep buy anything, and what diverged?
    --calibrate   where is the band that separates two packages?

Both print plain text with the reasoning attached. Neither needs a model, and neither needs
you to open the raw records.

## The question --analyze exists to answer

"575/575 passed" reads like 25x the assurance of a single run. It is not, if every case
answered identically 25 times. The **fingerprint census** measures that directly: runs
versus distinct results. A sweep whose ratio is 25:1 confirmed one thing 25 times.
"""
from __future__ import annotations

import collections
import statistics
from pathlib import Path

from busybody_ledger import human_bytes, read_jsonl  # noqa: F401

__all__ = ["analyze_run", "format_analysis", "RESOURCE_LADDER"]

W = 78

RESOURCE_LADDER = (256, 384, 512, 768, 1024, 1536, 2048, 3072)


def analyze_run(run_dir: Path) -> dict:
    """Everything derivable from one run's journal. No interpretation, just arithmetic."""
    recs = read_jsonl(run_dir / "journal.jsonl")
    cases = [r for r in recs if r.get("kind") == "case"]
    started = next((r for r in recs if r.get("kind") == "started"), {})
    finished = next((r for r in recs if r.get("kind") == "finished"), None)
    interrupted = next((r for r in recs if r.get("kind") == "interrupted"), None)
    setup_failure = next((r for r in recs if r.get("kind") == "setup_failure"), None)
    infra = next((r for r in recs if r.get("kind") == "infra_failure"), None)

    fixtures = sorted({c.get("fixture", "?") for c in cases})
    # outcome per (case, fixture) — the matrix everything else is derived from
    matrix: dict = collections.defaultdict(dict)
    for c in cases:
        matrix[c["name"]][c.get("fixture", "?")] = c["outcome"]

    diverged = {name: outs for name, outs in matrix.items()
                if len(set(outs.values())) > 1}

    secs = [c.get("seconds", 0) or 0 for c in cases]
    return {
        "run": run_dir.name,
        "dir": run_dir,
        "state": ("SETUP FAILURE" if setup_failure else
                  "ABORTED (environment)" if infra else
                  "INTERRUPTED" if interrupted or not finished else "complete"),
        "setup_failure": (setup_failure or {}).get("detail", ""),
        "infra_failure": (infra or {}).get("detail", ""),
        "planned": started.get("planned") or [],
        "planned_total": started.get("total"),
        "cases": cases,
        "fixtures": fixtures,
        "matrix": dict(matrix),
        "diverged": diverged,
        "findings": [c for c in cases if not c.get("ok")],
        "fingerprints": {c.get("fingerprint") for c in cases if c.get("fingerprint")},
        "by_persona": collections.Counter(c.get("persona", "?") for c in cases),
        "by_outcome": collections.Counter(c["outcome"] for c in cases),
        "by_blame": collections.Counter(c.get("blame", "?") for c in cases
                                        if c["outcome"] != "RAN"),
        "seconds": {"total": round(sum(secs), 1),
                    "mean": round(statistics.mean(secs), 2) if secs else 0,
                    "max": max(secs) if secs else 0},
        "slowest": sorted(
            ((n, round(statistics.mean([c.get("seconds", 0) or 0 for c in cases
                                        if c["name"] == n]), 1))
             for n in matrix), key=lambda kv: -kv[1])[:6],
    }


def _bar(label: str, n: int, total: int, width: int = 28) -> str:
    filled = 0 if not total else round(width * n / total)
    return f"  {label:14} {n:5}  {'#' * filled}{'.' * (width - filled)}"


def format_analysis(a: dict) -> str:
    L = ["=" * W, f"busybody analysis — {a['run']}", "=" * W, ""]

    if a["state"] == "SETUP FAILURE":
        L += ["SETUP FAILURE — the harness never reached the starting line, so there are",
              "no results. Zero findings here does not mean zero problems.", "",
              f"  {a['setup_failure'][:W - 4]}", ""]
        return "\n".join(L)

    n_cases, n_fix = len(a["cases"]), len(a["fixtures"])
    distinct = len(a["fingerprints"])
    L += [f"state        : {a['state']}",
          f"case runs    : {n_cases}",
          f"fixtures     : {n_fix}  ({', '.join(a['fixtures'][:6])}"
          + (f", +{n_fix - 6} more" if n_fix > 6 else "") + ")",
          f"wall clock   : {a['seconds']['total']:.0f}s of process time "
          f"(mean {a['seconds']['mean']}s, max {a['seconds']['max']}s)",
          f"findings     : {len(a['findings'])}", ""]

    if a["state"] == "ABORTED (environment)":
        L += ["  *** THE BOX FAILED, NOT THE PRODUCT ***",
              "",
              f"  {a['infra_failure'][:W - 4]}",
              "",
              "  Scratch space ran out mid-sweep. Every result after that point is the same",
              "  environment failure wearing a different persona's costume, so nothing below",
              "  is a verdict on haru-pack. The findings ledger was deliberately NOT written.",
              "",
              "  Re-run with --work-root DIR on a filesystem with room. Note that a per-user",
              "  quota is invisible to df: this box reported 31 GiB free on /tmp and refused",
              "  the next write at 24 GiB.",
              ""]

    if a["state"] == "INTERRUPTED":
        planned = a.get("planned_total") or len(a["planned"])
        L += ["  *** INTERRUPTED — the numbers above are what completed, not the suite ***",
              f"  {n_cases} of {planned} planned run(s) finished.", ""]

    # ---------------------------------------------------------------- the census
    L += ["-" * W,
          "FINGERPRINT CENSUS — did this sweep buy anything?",
          "-" * W, "",
          f"  {n_cases} case run(s) produced {distinct} distinct result(s).", ""]
    if n_fix > 1:
        ratio = n_cases / distinct if distinct else 0
        L += [f"  ratio: {ratio:.1f} runs per distinct result."]
        # A fingerprint folds in the diagnostic TEXT, so two runs with the same outcome and
        # different messages count as distinct results. That is the right granularity for
        # triage and the wrong one for "did the sweep buy anything" — for that, only a
        # differing OUTCOME counts. Report both rather than conflating them: an earlier
        # version branched on the fingerprint count and printed "0 case(s) DIVERGED" on a
        # sweep where nothing had.
        n_case_names = len(a["matrix"])
        if not a["diverged"]:
            L += ["",
                  "  NOTHING DIVERGED. Every case answered identically on all "
                  f"{n_fix} fixtures,",
                  "  so this sweep confirmed the same facts once per fixture. That is not",
                  f"  {n_fix}x the assurance of a single-fixture run — it is the same",
                  "  assurance at " + f"{n_fix}x the cost.",
                  "",
                  "  Launcher-level cases cannot diverge: the launcher is byte-identical in",
                  "  every binary. Only app-level personas can, and only where the package",
                  "  genuinely changes something (resource envelope, native libraries,",
                  "  startup cost)."]
            if distinct > n_case_names:
                L += ["",
                      f"  ({distinct} fingerprints against {n_case_names} case(s): same",
                      "  outcome, differing diagnostic text. Message wording varies by",
                      "  package; the verdict did not.)"]
        elif a["state"] == "ABORTED (environment)":
            L += ["",
                  f"  {len(a['diverged'])} of {n_case_names} case(s) appear to have diverged",
                  "  by fixture — but this run ABORTED on an environment failure, and that",
                  "  failure splits fixtures into 'ran before it' and 'ran after it'. That",
                  "  is not package-dependent behaviour. Discard this section.",
                  "",
                  "  The tell: the passing fixtures are the ones built first."]
        else:
            L += ["",
                  f"  {len(a['diverged'])} of {n_case_names} case(s) DIVERGED by fixture —",
                  "  the sweep earned its cost for those, and only those. The rest",
                  "  confirmed the same fact once per fixture."]
        L.append("")

    # ---------------------------------------------------------------- divergence
    if n_fix > 1:
        L += ["-" * W, "DIVERGENCE — cases whose answer depends on the package", "-" * W, ""]
        if not a["diverged"]:
            L += ["  (none)", ""]
        else:
            for name, outs in sorted(a["diverged"].items()):
                groups: dict = collections.defaultdict(list)
                for fix, out in outs.items():
                    groups[out].append(fix.replace("fixture-", ""))
                L.append(f"  {name}")
                for out, fixes in sorted(groups.items()):
                    shown = ", ".join(sorted(fixes)[:8])
                    more = f" (+{len(fixes) - 8})" if len(fixes) > 8 else ""
                    L.append(f"      {out:12} {shown}{more}")
                L.append("")

    # ---------------------------------------------------------------- distributions
    L += ["-" * W, "OUTCOMES", "-" * W, ""]
    for outcome, n in a["by_outcome"].most_common():
        L.append(_bar(outcome, n, n_cases))
    L.append("")
    if a["by_blame"]:
        L += ["  who failed, on the non-RAN runs:", ""]
        for who, n in a["by_blame"].most_common():
            L.append(_bar(who, n, sum(a["by_blame"].values())))
        L += ["",
              "  `launcher` means haru-pack reported the failure; `app` means the packaged",
              "  application did. An app-level persona starving an application is SUPPOSED",
              "  to produce `app` — that is not a haru-pack defect.", ""]

    L += ["-" * W, "SLOWEST CASES (mean seconds per run)", "-" * W, ""]
    for name, secs in a["slowest"]:
        L.append(f"  {name:44} {secs:6.1f}s")
    L.append("")

    if a["findings"]:
        L += ["-" * W, f"FINDINGS ({len(a['findings'])})", "-" * W, ""]
        for f in a["findings"]:
            L.append(f"  [{f.get('severity', '?'):8}] {f['outcome']:12} "
                     f"{f.get('fixture', '?')} {f['persona']}/{f['name']}")
            if f.get("inv"):
                L.append(f"             invariant: {f['inv']}")
        L += ["", f"  Full explanations: {(a['dir'] / 'report.txt')}", ""]

    L += ["-" * W,
          "REPRODUCE THIS",
          "-" * W, "",
          f"  python tools/busybody.py --analyze {a['run']}",
          "  python tools/busybody.py --history         # every run, interrupted ones marked",
          "  python tools/busybody.py --triage          # findings grouped across runs",
          ""]
    return "\n".join(L)

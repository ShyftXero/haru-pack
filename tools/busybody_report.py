"""What ONE sweep prints: its report, each finding's severity, and the artifacts kept.

`OUTCOME_MEANING` is the load-bearing table. A report that names an outcome without saying
what it means makes the reader guess, and a guessed verdict is worse than none.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import busybody_config as cfg  # noqa: E402

import shutil
from pathlib import Path

from busybody_config import FATAL
from busybody_ledger import is_finding


OUTCOME_MEANING = {
    "RAN": "the app ran and printed its marker",
    "REFUSED": "haru-pack stopped with a non-zero exit and a diagnostic (a guard fired)",
    "CRASHED": "a raw language-level traceback reached the user",
    "HUNG": "no exit within the timeout",
    "SILENT": "exit 0, but the app never ran",
    "APP-CRASHED": "the packaged application raised; the launcher was not at fault",
    "CASE-ERROR": "the chaos case itself failed; this is a bug in busybody, not in haru-pack",
    "INDETERMINATE": ("the harness stopped observing before the action resolved, so it may or "
                      "may not have taken effect. Jepsen calls this `:info`. NOT a verdict: "
                      "counted as neither a pass nor a finding, because counting it either "
                      "way would be a claim nobody can support"),
    "WARNED": "a contradictory config built, and the build said which side it overrode",
    "SILENT-WEDGE": ("a contradictory config built with no mention of the conflict, and the "
                     "artifact carries the damage"),
    "EXPOSED": ("a secret was recovered from a surface haru-pack DOCUMENTS as recoverable "
                "(the staged plaintext on the running user's disk). Not a defect; the honest "
                "reality the reverse_engineer persona keeps visible"),
    "LEAKED": ("a secret was recovered from a surface that is supposed to protect it — the "
               "encrypted binary at rest, or a tree readable by other users. A defect"),
    "REFUSED-UNRELATED": ("the build refused, but for something other than the wedge — the "
                          "case never reached what it meant to test"),
    "STALLED": ("every process was alive and none was progressing; declared by the herd "
                "persona's watchdog, never by a process about itself"),
    "CONTAINED": ("a hostile project was built and the attack did not land: no canary fired "
                  "and nothing of the attacker's reached the artifact"),
    "SANCTIONED": ("project-controlled code ran through a path haru-pack DOCUMENTS as "
                   "executing project-controlled code, AND the build log named it first. "
                   "Not a defect; the capability, exercised visibly"),
    "ESCAPED": ("code supplied by the PACKED PROJECT executed on the build host through a "
                "path not documented as executing anything, or without the log naming it. "
                "Every artifact built on that host afterwards is suspect"),
    "SMUGGLED": ("bytes that were never in the project reached the distributed artifact — a "
                 "credential from outside the tree, a member name that escapes on "
                 "extraction, or an argv that runs on the customer under the vendor's "
                 "signature"),
    "NO-SUITE": ("the examiner had no suite to sit: the package's sdist ships no test tree, so "
                 "there was nothing to run. Honest coverage — recorded, never faked as a pass "
                 "(INV-CHAOS-15)"),
}
W = 78


def _preamble(exe_name: str, run_id: str, results: list, bad: list,
              interrupted: bool, unresolved: int = 0) -> list:
    """Counts, the caveat if there is one, and the vocabulary the rest of the file uses.

    The outcome legend is printed VERBATIM from OUTCOME_MEANING rather than summarised: a
    report that names an outcome without saying what it means makes the reader guess, and a
    missing key degrades to "?" rather than raising, which is a silent way to ship an
    outcome nobody can look up.
    """
    L = ["=" * W,
         "busybody report \u2014 haru-pack chaos testing",
         "=" * W,
         "",
         f"run          : {run_id or '(unrecorded)'}",
         f"fixture      : {exe_name}",
         f"cases run    : {len(results)}",
         f"as expected  : {len(results) - len(bad) - unresolved}",
         f"findings     : {len(bad)}",
         f"indeterminate: {unresolved}   (neither; the harness stopped watching first)"]
    if interrupted:
        L += ["",
              "  *** THIS RUN WAS INTERRUPTED ***",
              "  The cases below are what completed before it stopped, not the whole",
              "  suite. Do not read the counts above as a result."]
    L += ["",
          "WHAT THIS TOOL CHECKS",
          "",
          "  Not whether haru-pack can be broken \u2014 anything can. Whether it breaks WELL.",
          "  A clear refusal is a pass. A traceback, a hang, or a silent success is not,",
          "  in any case, ever.",
          "",
          "OUTCOMES AND WHAT THEY MEAN",
          ""]
    L += [f"  {k:11} {v}" for k, v in OUTCOME_MEANING.items()]
    L += ["",
          f"  Always a finding, whatever the case expected: {', '.join(FATAL)}.",
          ""]
    return L


def _summary_table(results: list) -> list:
    """One line per case run, in the order they were journalled."""
    L = ["-" * W, "SUMMARY", "-" * W, "",
         f"  {'persona':14} {'case':42} {'outcome':9} {'severity':8} verdict",
         f"  {'-' * 14} {'-' * 42} {'-' * 9} {'-' * 8} -------"]
    for r in results:
        verdict = ("UNKNOWN" if r.get("indeterminate")
                   else "ok" if r["ok"] else "FINDING")
        L.append(f"  {r['persona']:14} {r['name']:42} {r['outcome']:9} "
                 f"{r.get('severity', ''):8} {verdict}")
    L.append("")
    return L


def _no_findings() -> list:
    """What a clean run is worth, said plainly so it is not over-read."""
    return ["-" * W, "NO FINDINGS", "-" * W, "",
            "  Every case behaved as expected. Note what that does and does not mean:",
            "  these are the faults somebody thought of. A clean run is evidence, not",
            "  proof. Adding a case that fails is more valuable than re-running these.",
            ""]


def _one_finding(i: int, r: dict) -> list:
    """Everything a reader needs about one finding, without opening anything else.

    What was done, what happened, what should have happened, why the case exists at all,
    the invariant that governs it, and the next step.
    """
    L = ["",
         f"[{i}] {r['persona']} / {r['name']}",
         "",
         f"    OUTCOME   {r['outcome']} \u2014 {OUTCOME_MEANING.get(r['outcome'], '?')}",
         f"    EXPECTED  {' or '.join(r['expect'])}"]
    if r["outcome"] in FATAL:
        L.append("    SEVERITY  always a finding, regardless of what was expected")
    if r.get("inv"):
        L.append(f"    INVARIANT {r['inv']}  (see INVARIANTS.md)")
    if r.get("fingerprint"):
        L.append(f"    FINGERPRINT {r['fingerprint']}  "
                 f"(`--triage` groups repeats of this)")
    if r.get("artifacts"):
        L.append(f"    ARTIFACTS {r['artifacts']}")
    L += [f"    EXIT      {r['rc']}",
          "",
          "    WHAT THIS CASE SIMULATES"]
    L += [f"        {line}" for line in _wrap(" ".join(r["why"].split()), W - 8)]
    if r.get("remedy"):
        L += ["", "    WHAT TO DO"]
        L += [f"        {line}" for line in _wrap(" ".join(r["remedy"].split()), W - 8)]
    for stream in ("stderr", "stdout"):
        if r.get(stream):
            L += ["", f"    {stream.upper()} (last {len(r[stream])} chars)"]
            L += [f"        {line[:W - 8]}" for line in r[stream].splitlines()[-8:]]
    return L


def _how_to_rerun() -> list:
    return ["-" * W, "HOW TO RE-RUN ONE CASE", "-" * W, "",
            "  python tools/busybody.py --case <case name>  --keep",
            "",
            "  --keep leaves each case's working directory under busybody/out/ so you can",
            "  inspect the binary and the cache it produced.",
            ""]


def write_report(results: list, exe_name: str, path: Path, run_id: str = "",
                 interrupted: bool = False) -> None:
    """A report a human reads on its own. No JSON, no cross-referencing, no AI.

    If you are holding this file and nothing else, that has to be enough.
    """
    bad = [r for r in results if is_finding(r)]
    L = _preamble(exe_name, run_id, results, bad, interrupted,
                  len([r for r in results if r.get("indeterminate")]))
    L += _summary_table(results)
    if not bad:
        L += _no_findings()
    else:
        L += ["-" * W, f"FINDINGS ({len(bad)})", "-" * W]
        for i, r in enumerate(bad, 1):
            L += _one_finding(i, r)
        L.append("")
    L += _how_to_rerun()
    path.write_text("\n".join(L) + "\n")




def _wrap(text: str, width: int) -> list:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines or [""]



# ---------------------------------------------------------------- severity, artifacts

def severity_for(c: dict, r: dict, ok: bool) -> str:
    """Closed vocabulary — critical / warning / note. Never "error", never "info".

    A fixed set means a reader learns three words once, and a report cannot quietly grow a
    fourth level nobody has calibrated. Taken from lotek, which uses the same three.
    """
    if ok:
        return "note"
    if r["outcome"] in FATAL:
        return "critical"      # a traceback at the user, the wrong code running, or a wedge
    if r["outcome"] == "APP-CRASHED":
        return "note"          # the app declined the box it was given; not haru-pack's doing
    if r["outcome"] == "CASE-ERROR":
        return "note"          # busybody's own bug, not haru-pack's — say so, do not inflate
    if r["outcome"] == "INDETERMINATE":
        return "note"          # not a verdict; the harness stopped watching. Never inflate
                               # an absence of evidence into evidence
    if r["outcome"] == "REFUSED-UNRELATED":
        return "note"          # the CASE missed its target; fix the case before believing it
    if r["outcome"] == "LEAKED":
        return "critical"      # a secret where it must not be
    if r["outcome"] == "EXPOSED":
        return "note"          # documented reality, kept visible, not a defect
    if r["outcome"] in ("ESCAPED", "SMUGGLED"):
        return "critical"      # the packed project reached the build host, or the artifact
    if r["outcome"] == "SANCTIONED":
        return "note"          # a documented capability, named in the log before it fired
    return "warning"           # refused where it should have run, or the reverse


def preserve(run_dir: Path, case_name: str, work: Path, light: bool = False) -> str:
    """Copy a failing case's wreckage somewhere it will still exist tomorrow.

    Unconditional for findings: `--keep` is a flag people remember only after the
    interesting run, and you cannot triage a crash you threw away.

    `light` copies the top-level files and skips the directories. A herd case's work dir
    holds one shared stage tree plus N transient staging copies of it, and copying that
    whole is hundreds of megabytes of the same bytes to say one thing.
    """
    dest = run_dir / "findings" / case_name
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    kept = []
    for child in sorted(work.iterdir()):
        try:
            # Forensic bundles are small JSON and are the first thing worth reading, so
            # they are copied whatever else the `light` rule drops.
            if child.is_file() and child.stat().st_size < 300 * 1024 * 1024:
                shutil.copy2(child, dest / child.name)
                kept.append(child.name)
            elif child.is_dir() and light:
                kept.append(child.name + "/ (skipped: light case)")
            elif child.is_dir():
                shutil.copytree(child, dest / child.name, symlinks=True,
                                ignore=shutil.ignore_patterns("*.tar.gz", "*.whl", "*.so"),
                                dirs_exist_ok=True)
                kept.append(child.name + "/")
        except (OSError, shutil.Error):
            continue
    (dest / "WHAT-IS-THIS.txt").write_text(
        f"Preserved automatically because case {case_name!r} produced a finding.\n"
        f"--keep is a flag people remember only after the interesting run, so preserving a\n"
        f"finding's artifacts is unconditional.\n\n"
        f"Contents: {', '.join(kept) or '(nothing copyable)'}\n\n"
        f"Re-run just this case:\n"
        f"    python tools/busybody.py --case {case_name} --keep\n")
    return str(dest.relative_to(cfg.REPO))



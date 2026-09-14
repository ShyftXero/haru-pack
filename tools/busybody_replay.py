"""`--replay SIGNATURE` — reconstruct the run that produced a finding.

Adopted from lotek's `tests/busybody/replay.py` (T-015), which reconstructs a failing k-set.
The haru-pack equivalent is the same question asked of a smaller space: given a signature
from the ledger, what is the exact command that puts that finding back on the screen?

## Why this is not just printing `remedy`

`remedy` is written by whoever wrote the case, at the time they wrote it, and it says what to
DO about a failure. It is prose aimed at a person who has already decided the finding is
real. This answers the earlier question — "is it still there?" — and it has to be answered
from the LEDGER, because by the time anyone asks, the run directory has been pruned (ten
runs, by default) and the only surviving record of the finding is one row.

The distinction that makes it worth a module: a composed finding's reproduction is not the
case name. It is the set of traits that FIRED plus the seed plus the run index, and none of
those is guessable from the fingerprint. They are in the ledger row because somebody thought
to put them there, and this is the thing that reads them back out.

## What it can and cannot promise

It reconstructs the INVOCATION, not the outcome. A reproduction line is a claim about what
was run, never a claim that running it again fails — the whole reason a seed exists is that
without one, the second claim is not available at all, and with one it is still conditional
on the fixture, the box and the version of haru-pack under test. Saying so is the difference
between a reproduction and a promise.
"""
from __future__ import annotations

from busybody_ledger import ledger_path, ledger_rollup, read_jsonl

__all__ = ["find_rows", "command_for", "print_replay"]


def find_rows(signature: str, path=None) -> list:
    """Ledger rows whose fingerprint starts with `signature`, newest last.

    A prefix, because a 16-hex signature is unreadable aloud and every tool that prints one
    truncates it somewhere different. Six characters is unambiguous in a ledger of thousands
    and is what a person will actually copy.
    """
    rows = read_jsonl(path or ledger_path())
    sig = signature.strip().lower()
    hits = [r for r in rows if str(r.get("fingerprint", "")).lower().startswith(sig)]
    return sorted(hits, key=lambda r: r.get("at") or 0)


def command_for(row: dict) -> str:
    """The command that re-runs what produced this row.

    Three shapes, because a finding arrives through three different doors and a line that
    works for one is wrong for the others:

      * a COMPOSED finding reproduces from the traits that FIRED, not the ones selected —
        a trait that declined to act was not part of what happened;
      * a case that builds its own artifact takes no fixture;
      * everything else is a case name plus the fixture it ran against.
    """
    if row.get("golden"):
        # The golden run is prepended to every campaign, so any compose invocation produces
        # one. There is no "reproduce the control" command distinct from "run a campaign".
        return ("python tools/busybody.py --compose 1 --compose-runs 1"
                f" --compose-seed {row.get('seed', 0)}"
                "   # the golden run is the first stack of any campaign")

    fired = row.get("fired") or []
    if fired:
        return ("python tools/busybody.py --compose-only "
                + ",".join(fired)
                + f" --compose-seed {row.get('seed', 0)} --compose-runs 1")

    if row.get("fixture") == "(stack)":
        # A composed row with no `fired` list. This is NOT a golden run and must not be
        # printed as one — the first draft did exactly that, on a real row, and produced a
        # confident reproduction line for a run that never happened. `fired` entered the
        # ledger subset after some of these rows were written, so the honest answer is that
        # the row does not carry what a reproduction needs.
        #
        # Absence and emptiness are different facts and the distinction is the whole point:
        # `"fired": []` means nothing fired, no key at all means nobody recorded it.
        return ("# NOT REPRODUCIBLE from this row: it is a composed finding whose `fired` "
                "list\n#   was never recorded (the field entered the ledger after this row "
                "was written).\n#   The stack that produced it is unrecoverable. Re-run a "
                "campaign and see if it\n#   returns:\n"
                f"python tools/busybody.py --compose 2 --compose-seed {row.get('seed', 0)}")

    parts = ["python tools/busybody.py", f"--case {row.get('name', '?')}"]
    fixture = row.get("fixture") or ""
    if fixture and fixture not in ("(config)", "(stack)", "none", "?"):
        # `synthetic` is the fixture's NAME, not a path; anything else was a built binary
        # and the sweep that produced it is what has to be re-run.
        parts.append("--fixtures synthetic" if fixture == "synthetic"
                     else f"--fixtures top25   # this row ran against {fixture!r}")
    if row.get("seed"):
        parts.append(f"--seed {row['seed']}")
    parts.append("--keep")
    return " ".join(parts)


def _describe(row: dict) -> list:
    L = [f"  run        : {row.get('run', '?')}",
         f"  outcome    : {row.get('outcome', '?')}   severity: {row.get('severity', '?')}",
         f"  fixture    : {row.get('fixture', '?')}",
         f"  seed       : {row.get('seed', 0)}"]
    if row.get("fired"):
        selected = row.get("selected") or []
        L.append(f"  fired      : {', '.join(row['fired'])}")
        declined = [n for n in selected if n not in row["fired"]]
        if declined:
            L.append(f"  declined   : {', '.join(declined)}   "
                     f"(selected, did not act — not part of what happened)")
    if row.get("inv"):
        L.append(f"  invariant  : {row['inv']}")
    if row.get("artifacts"):
        L.append(f"  artifacts  : {row['artifacts']}   (may have been pruned)")
    if row.get("message"):
        L.append("  message    :")
        L += [f"      {ln[:72]}" for ln in row["message"].splitlines()[:4]]
    return L


def print_replay(signature: str) -> int:
    """Everything known about one signature, and the line that puts it back. Exit code."""
    rows = find_rows(signature)
    if not rows:
        groups = ledger_rollup()
        print(f"no finding in {ledger_path()} with a signature starting {signature!r}.")
        if groups:
            print("\nsignatures on record (newest occurrence last):")
            for g in groups[:20]:
                print(f"  {g['fingerprint']}  {g['count']:>4}x  {g['outcome']:12} "
                      f"{', '.join(g['cases'])[:44]}")
        return 1

    latest = rows[-1]
    print("=" * 78)
    print(f"replay {latest['fingerprint']}   — {len(rows)} occurrence(s) on record")
    print("=" * 78)
    print()
    print("MOST RECENT OCCURRENCE")
    for line in _describe(latest):
        print(line)
    if len(rows) > 1:
        runs = sorted({r.get("run", "?") for r in rows})
        print(f"\n  also seen in: {', '.join(runs[:8])}"
              + (f"  (+{len(runs) - 8} more)" if len(runs) > 8 else ""))
    print()
    print("REPRODUCE")
    print()
    print(f"    {command_for(latest)}")
    print()
    print("This reconstructs the INVOCATION, not the outcome. A seed makes the harness's own")
    print("choices repeatable — which moment a fault landed, which traits fired — and that is")
    print("all it makes repeatable. Whether the finding is still there also depends on the")
    print("fixture, the box, and the version of haru-pack under test. If it does not")
    print("reproduce, that is a result worth recording, not a failed command.")
    return 0

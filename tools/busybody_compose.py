"""Composable hostility: traits, and the sampling that combines them.

## Why this exists

A persona that runs alone is an integration test wearing a costume. `hostile_umask` on its
own asks "does staging cope with umask 077?", which is a fine question and a closed one — it
has the same answer every time, forever. Chaos engineering is the other question: **which
COMBINATION of individually-survivable conditions is not survivable?** A read-only cwd is
fine. No HOME is fine. `CI=true` with no TTY is fine. One of the eight ways of stacking three
of those is where the traceback lives, and no amount of running them separately will find it.

So hostility is expressed here as *traits* — small, orthogonal, declared mutations — and the
runner combines them. A trait is deliberately not a test: it has no expectation of its own,
because the whole point is that its effect depends on what it is stacked with.

## The pass condition for a composed run

A composed run cannot have a per-combination expectation; there are thousands of
combinations and nobody has reasoned about each one. What CAN be asserted is the floor:

    RAN          fine
    REFUSED      fine — a guard fired and said so
    APP-CRASHED  fine — the app declined the box these traits built for it
    CRASHED      NEVER fine. A language-level traceback reached the user.
    HUNG         NEVER fine.
    SILENT       NEVER fine. Exit 0 and the app never ran.

That is exactly the existing FATAL set, which is the point: composition needs no new
vocabulary, only a weaker expectation. "haru-pack refused, intelligibly, under any stack of
hostile conditions" is the property. "haru-pack always works" is not, and claiming it would
be the sort of thing INVARIANTS.md exists to prevent.

## Determinism

Combinations are sampled from a seed, and the seed is recorded in the journal and printed in
the report. A finding that cannot be reproduced is an anecdote. `--compose-only a,b,c` re-runs
one exact stack.

## Per-action perturbation probability

`fires` is the probability that a trait acts on a given run — a **per-action perturbation
probability**, cf. human error probability in the human-reliability literature. This is the
same mechanism FoundationDB calls buggification, where `BUGGIFY` fires at a 25% base rate
and `BUGGIFY_WITH_PROB(p)` sets it per site; they split frequency from magnitude into
separate mechanisms for the same reason the rate is per-trait here rather than global.

Why it exists: a persona that always misbehaves is not a person, it is a fixture. Some days
the new developer reads the flag correctly. So the stack "greenhorn fumbled AND auditor left
a .env" is not the only thing ever tested — "greenhorn got it right, auditor still left the
.env" is a different code path and it gets its turn.

Selection and firing are recorded separately, and a run's identity is the set that FIRED. A
run where nothing fired is a control, kept rather than resampled: if the baseline is broken,
that is where it shows.

## Attribution

A composed failure is only interesting if the parts are individually fine. Every trait gets an
auto-generated singleton case, so the analyzer can answer "did A alone pass? did B alone
pass? did A+B fail?" — which is the difference between "trait A is broken" and "A and B
interact", and the second is the finding worth having.
"""
from __future__ import annotations

import hashlib
import itertools
import random
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["trait", "TRAITS", "BuildCtx", "RunCtx", "sample_combos", "conflicts_in",
           "PHASES", "LAYERS", "singleton_cases", "describe_traits", "realize"]

PHASES = ("build", "run")

# A layer is what the trait perturbs. Recorded so a report can say "this stack was three
# filesystem traits" rather than listing names, and so sampling can be told to spread across
# layers instead of picking three variations of the same idea.
LAYERS = ("cli", "config", "project", "env", "fs", "proc", "cache", "payload")

TRAITS: dict = {}


def trait(name: str, phase: str, layer: str, why: str, *, conflicts=(), inv: str = "",
          degrades: bool = False, no_run: bool = False, needs: tuple = (),
          fires: float = 1.0):
    """Register a composable mutation.

    `phase`     "build" (mutates the project/CLI before building) or "run" (mutates the
                environment the binary is executed in).
    `layer`     what it perturbs; see LAYERS.
    `why`       what real situation this is. Printed in the report — a trait nobody can
                motivate is a trait nobody will maintain.
    `conflicts` traits that make this one meaningless when stacked. Not "traits that break
                together" — those are the findings. These are pairs where one silently
                cancels the other, so the combination tests less than either alone.
    `degrades`  this trait can legitimately make the APPLICATION fail. Composed runs
                containing it accept APP-CRASHED without comment.
    `no_run`    after this trait the artifact cannot be executed here (a foreign target).
                The pipeline stops after the build and runs static checks instead.
    `needs`     external requirements ("docker", "wine"). Skipped, loudly, when absent.
    `fires`     the PER-ACTION PERTURBATION PROBABILITY: how often this trait actually
                acts. (cf. human error probability; the identifier stays `fires` because
                that is what it does, not what it models.) THE POINT: a persona that always
                misbehaves is not a person, it is a fixture. Some days the new developer
                reads the flag correctly. If greenhorn always fumbles, the stack "greenhorn
                fumbled AND auditor left a .env lying around" is the only thing ever tested,
                and "greenhorn got it right, auditor still left the .env" — a different code
                path — never runs at all.

                Set below 1.0 only where real-world presence is genuinely intermittent: a
                developer's mistake, a stale cache that may or may not be there. A CI
                runner's missing TTY is not intermittent, so foreman's traits fire always.

                Selection and firing are separate, and both are recorded. A run's identity
                is the set that FIRED, not the set that was selected.
    """
    if not 0.0 < fires <= 1.0:
        raise ValueError(f"trait {name}: fires must be in (0, 1], got {fires}")
    if phase not in PHASES:
        raise ValueError(f"trait {name}: phase {phase!r} not in {PHASES}")
    if layer not in LAYERS:
        raise ValueError(f"trait {name}: layer {layer!r} not in {LAYERS}")

    def deco(fn):
        if name in TRAITS:
            raise ValueError(f"duplicate trait {name!r}")
        TRAITS[name] = {"name": name, "phase": phase, "layer": layer, "why": why,
                        "conflicts": frozenset(conflicts), "inv": inv,
                        "degrades": degrades, "no_run": no_run, "needs": tuple(needs),
                        "fires": float(fires), "fn": fn}
        return fn
    return deco


@dataclass
class BuildCtx:
    """What a build-phase trait may change."""
    proj: Path
    decl: dict = field(default_factory=dict)        # -> haru_pack.toml
    files: dict = field(default_factory=dict)       # relpath -> contents
    cli: list = field(default_factory=list)         # extra argv for `haru-pack build`
    tier: str = "thick"
    env: dict = field(default_factory=dict)         # environment for the BUILD process
    out_name: str = "composed"
    entry: str = "app.py"                           # what the build is pointed at
    runnable: bool = True                           # False once a foreign target is chosen
    target: str = ""                                # recorded for static verification
    post: list = field(default_factory=list)        # callables(proj) after files are written
    # Ordering is load-bearing. A trait that makes the project read-only must run after every
    # trait that writes to it, or it silently cancels them and the stack tests less than it
    # claims. Two lists rather than a priority number: there are exactly two groups, and a
    # number invites someone to invent a third.
    post_late: list = field(default_factory=list)


@dataclass
class RunCtx:
    """What a run-phase trait may change."""
    env: dict = field(default_factory=dict)
    cwd: Path | None = None
    args: tuple = ()
    argv0: str | None = None
    rlimits: dict = field(default_factory=dict)
    stdin_closed: bool = False
    timeout: int = 180
    pre: list = field(default_factory=list)         # callables(work, exe) before exec
    pre_late: list = field(default_factory=list)    # ...and these after those; see post_late
    degrades: bool = False


def conflicts_in(names) -> tuple:
    """The first conflicting pair in `names`, or ()."""
    for a, b in itertools.combinations(sorted(names), 2):
        if b in TRAITS[a]["conflicts"] or a in TRAITS[b]["conflicts"]:
            return (a, b)
    return ()


def sample_combos(names, k: int, runs: int, seed: int, *, spread_layers: bool = True) -> list:
    """`runs` combinations of `k` traits, chosen deterministically from `seed`.

    Enumerates exhaustively when the whole space is smaller than the budget — asking for 200
    samples of a 35-combination space should give 35 distinct combinations, not 200 draws
    with repeats. Above that it samples without replacement.

    `spread_layers` prefers stacks that touch different layers. Three filesystem traits is a
    weaker test than one filesystem, one env and one process trait, because the interesting
    interactions are between mechanisms rather than between variations of one mechanism.
    """
    names = sorted(names)
    if k < 1 or k > len(names):
        return []
    space = [c for c in itertools.combinations(names, k) if not conflicts_in(c)]
    if spread_layers:
        # Diversity computed ONCE per combination. The first draft called
        # max(layers(x) for x in space) inside a comprehension over space, which is O(n^2)
        # and hung outright at k=3 over 40 traits — 9,880 combinations, ~97M evaluations.
        # Worth the comment: `packrat_many_tiny_files` exists to catch this exact shape in
        # haru-pack, and the harness had it first.
        scored = [(len({TRAITS[n]["layer"] for n in c}), c) for c in space]
        best = max((d for d, _ in scored), default=0)
        head = [c for d, c in scored if d == best]
        rest = [c for d, c in scored if d != best]
        rng = random.Random(seed)
        rng.shuffle(head)
        rng.shuffle(rest)
        ordered = head + rest
    else:
        rng = random.Random(seed)
        ordered = list(space)
        rng.shuffle(ordered)
    return ordered[:runs]


def realize(combo, seed: int, run_index: int, force: bool = False) -> tuple:
    """Which of `combo` actually acts on this run. Deterministic in (seed, run_index).

    Derived per trait from a hash of (seed, run_index, name) rather than from a single
    sequential RNG, so adding a trait to the catalogue does not reshuffle the firing
    decisions of every other trait in every other run. A seed has to keep meaning the same
    thing across a change to the catalogue, or "reproduce with --compose-seed 7" is a lie.

    sha256 rather than `random.Random(triple)`: seeding Random with a tuple raises on
    Python 3.14, and even where it works its mapping from seed to stream is an
    implementation detail. A digest of the triple is stable across Python versions and
    machines, which is the property actually needed for a reproduction line in a report.

    An empty result is legitimate and is kept rather than resampled: nobody misbehaved today.
    That run is a control, and a control arriving naturally through the same machinery is
    worth more than one bolted on beside it — if the baseline is broken, this is where it
    shows.

    `force` sets every per-action perturbation probability to 1, and there are exactly two
    callers that need it:

      * the k=1 pass, which IS the attribution baseline. "Does trait A fail alone?" cannot
        be answered by a run where A did not fire, and a baseline with holes in it makes
        every composed finding unattributable.
      * --compose-only, where someone asked for one specific stack. Handing them a control
        run instead would be answering a different question than the one they typed.

    Everywhere else the probability IS the point, so it stays as declared.
    """
    if force:
        return tuple(combo)
    fired = []
    for name in combo:
        t = TRAITS[name]
        if t["fires"] >= 1.0:
            fired.append(name)
            continue
        digest = hashlib.sha256(f"{seed}:{run_index}:{name}".encode()).digest()
        draw = int.from_bytes(digest[:8], "big") / float(1 << 64)
        if draw < t["fires"]:
            fired.append(name)
    return tuple(fired)


def singleton_cases(only_phase: str = "") -> list:
    """One combination per trait.

    Composition is only meaningful against these. If A+B fails, the question is immediately
    "does A alone fail?" — and without the singletons that question costs another run and a
    guess. With them the analyzer answers it from the journal.
    """
    return [(n,) for n in sorted(TRAITS)
            if not only_phase or TRAITS[n]["phase"] == only_phase]


def describe_traits() -> str:
    """The trait table, for `--list-traits`. Grouped by phase then layer."""
    out = []
    for phase in PHASES:
        rows = [t for t in TRAITS.values() if t["phase"] == phase]
        if not rows:
            continue
        out.append(f"\n{phase.upper()} PHASE ({len(rows)} trait(s))")
        out.append("-" * 78)
        for layer in LAYERS:
            here = sorted((t for t in rows if t["layer"] == layer), key=lambda t: t["name"])
            if not here:
                continue
            out.append(f"  [{layer}]")
            for t in here:
                flags = "".join([
                    f" (fires {t['fires']:.0%})" if t["fires"] < 1.0 else "",
                    " (degrades)" if t["degrades"] else "",
                    " (no-run)" if t["no_run"] else "",
                    f" (needs {', '.join(t['needs'])})" if t["needs"] else "",
                ])
                out.append(f"    {t['name']:34}{flags}")
                out.append(f"        {t['why']}")
                if t["conflicts"]:
                    out.append(f"        cancels-with: {', '.join(sorted(t['conflicts']))}")
    out.append("")
    out.append(f"{len(TRAITS)} trait(s). Combinations of k=2 without conflicts: "
               f"{len([c for c in itertools.combinations(sorted(TRAITS), 2) if not conflicts_in(c)])}")
    return "\n".join(out)

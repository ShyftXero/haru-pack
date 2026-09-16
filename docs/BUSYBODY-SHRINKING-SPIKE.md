# Shrinking: a time-boxed spike, and why it is not landing here

**Date:** 2026-09-14. **Status:** spike only. Nothing from this is in `tools/`, by design.

Shrinking is the largest capability gap busybody has against every peer tool — QuickCheck,
Hypothesis, AFL's `tmin`, Jepsen's history reduction all have it and neither busybody does.
haru-pack looked like the better of the two repos to try it in, because a case here is a
function over a fixture rather than a long action sequence against a live stateful app, so
the search space is much smaller. Both prerequisites were already present: seeded determinism,
and `--compose-only` to replay an exact stack.

**The finding is that the small search space is the problem, not the opportunity.** For the
stack sizes haru-pack actually runs, ddmin costs *more* than exhaustive search and returns
the same answer. The axis worth shrinking in this repo is a different one.

---

## What was measured

`ddmin` (Zeller & Hildebrandt's delta debugging, the classic formulation) implemented against
simulated oracles, so the algorithm could be characterised without spending a day building
binaries. Three oracle shapes, chosen because each corresponds to something this catalogue
actually contains:

- **monotone** — a fixed subset causes the failure and adding traits never hides it;
- **non-monotone** — a further trait *suppresses* the failure. haru-pack has these by
  construction: `conflicts` declares pairs where one trait silently cancels another, and
  `post_late` exists because a read-only-project trait applied after a writer cancels it;
- **flaky** — the failure only reproduces some of the time. Directly relevant, because traits
  carry per-action perturbation probabilities as low as 0.5.

One real number, measured rather than assumed: **a composed build is 54 s**, cold and warm
(`haru-pack build` on a two-line PEP 723 script at the default tier, this box, two runs,
identical to the second). That is the unit cost of one oracle call, because a composed run
rebuilds its artifact.

---

## Result 1 — ddmin is correct, and at haru-pack's sizes it is slower than brute force

Exact minimal subset recovered in every monotone trial. Call counts against exhaustive search
over subsets (smallest first), one to three culprits:

| k | ddmin calls | brute-force calls | ddmin @54s | brute @54s |
|---:|---:|---:|---:|---:|
| 2 | 4 | 3 | 4 min | 3 min |
| 3 | 10 | 4 | 9 min | 4 min |
| 4 | 20 | 6 | 18 min | 5 min |
| 5 | 26 | 7 | 23 min | 6 min |
| 8 | 36 | 12 | 32 min | 11 min |
| 12 | 25 | 15 | 22 min | 14 min |
| 20 | 71 | 68 | 64 min | 61 min |

ddmin does not win anywhere in this table. It is asymptotically better — at k=20 with three
culprits in an earlier run it took 105 calls against brute force's 598 — but that crossover
is past the point where either is affordable at 54 s a call, and it is far past the stack
sizes this project runs.

**And this project runs k=1, 2 and 3.** `docs/BUSYBODY.md` documents exactly three composed
invocations: `--compose 1` (the attribution baseline), `--compose 2` (pairs) and
`--compose 3`. At k=2 there is nothing to shrink — the singleton baseline already tells you
whether either trait fails alone. At k=3 the entire subset lattice is six proper subsets, and
enumerating them costs four calls where ddmin costs ten.

A spike that concludes "write the four-line loop instead" is a cheap spike.

---

## Result 2 — the flaky oracle is the real hazard, and `--compose-only` already fixes it

200 trials per row, k=8, two culprits, failure reproducing with probability *p*:

| p | exact | over-approximated | under-approximated | mean calls |
|---:|---:|---:|---:|---:|
| 1.0 | 200 | 0 | 0 | 6.0 |
| 0.9 | 200 | 0 | 0 | 6.6 |
| 0.7 | 195 | 5 | 0 | 8.3 |
| 0.5 | 179 | 21 | 0 | 12.3 |
| 0.3 | 111 | 89 | 0 | 21.4 |

Two things worth keeping:

**It never under-approximates.** Not once in 1,000 trials did it drop a real culprit. That is
structural rather than lucky: a false "this subset does not fail" makes ddmin keep the larger
set, so unreliability inflates the answer instead of corrupting it. A shrinker whose failure
mode is "returns a superset" is one you can trust the output of; one that could silently drop
the cause would be worse than none.

**The cost of flakiness is bloat and time**, and at p=0.3 more than half the answers are
supersets and the call count nearly quadruples — 21 calls is 19 minutes here.

The good news is that haru-pack's flakiness is not environmental, it is the harness's own
firing draw — and `--compose-only` **already forces every named trait to fire**. So a
shrinking oracle built on `--compose-only` runs at p=1 with respect to trait firing, which is
the top row. The residual is genuine environmental nondeterminism, and `--compose-only`
plus a fixed `--compose-seed` is the strongest handle available on that too. This was a
latent property of a flag that exists for a different reason; it is worth writing down,
because a future shrinker built on `--compose` rather than `--compose-only` would silently
land in the p=0.5 row.

---

## Result 3 — the non-monotone case never reaches a shrinker at all

If trait C suppresses the failure that A+B cause, then the stack {A, B, C} does not fail —
so it is never reported, and there is nothing to shrink. Shrinking is only ever invoked on a
stack that *did* fail, and interference makes stacks fail *less*.

This is not a shrinker problem; it is a sampling problem, and it is one this harness already
half-addresses. `conflicts` prunes pairs where one trait cancels another, which raises the
odds that a sampled stack is a meaningful test. Undeclared interference remains invisible by
construction, and no amount of shrinking will surface it — only a run that happens not to
include the suppressor. Worth stating because "we have shrinking now" is exactly the kind of
sentence that gets read as covering this.

---

## What I would build instead, if anything

**The shrinking axis worth having in haru-pack is the fixture set, not the trait stack.**

`--fixtures top25` runs every case against 25 real packages. When an app-level case fails on
some of them, the question a human then asks by hand is *which* packages are needed to
reproduce — and that is a k=25 problem, which is precisely where ddmin's advantage over
exhaustive search becomes real (105 calls against 598 in the trial above). It is also far
cheaper per call than the trait axis, because the fixtures are built once and reused: an
oracle call is running an existing binary, not a 54-second build.

The same argument applies to the case set for a cross-cutting regression ("which of the 80
cases still fails after this change?"), for the same reason: big enough for ddmin to pay,
cheap enough per call to run.

That is a different feature from the one this spike was asked to try, so it is recorded here
and in `docs/BUSYBODY-TRANSFER.md` as a proposal rather than built.

---

## Honest limits of this spike

- **The oracles are simulated.** Nothing was shrunk against a real failing stack, because
  reproducing one costs 54 s per call and none was to hand. The call COUNTS are exact — they
  are a property of the algorithm and the oracle shape, not of the target — and the wall-clock
  column is those counts times one measured build. What is not established is whether real
  composed failures are monotone; the non-monotone section argues most of them have to be,
  since a non-monotone one would not have been reported, but that is an argument and not a
  measurement.
- **One box, one tier.** 54 s is the default tier on this machine. The thick tier stages a
  real interpreter and is slower, which moves every number in the wrong direction.
- **`ddmin` here is the classic formulation**, not `ddmin+` or any of the caching variants. A
  cache of already-tested subsets would cut repeated calls; at k≤3 it would save perhaps one
  call, which does not change the conclusion.
- **The spike script is not in the repository.** It is forty lines of algorithm and three
  oracles, and the numbers above are its whole output. Keeping a throwaway that nothing
  imports and no test covers is how a repo acquires code that looks maintained.

## Verified

The measurements in this document — the 54 s composed build, the call counts, the flaky-oracle
distribution — were produced on 2026-09-14 on this host and are reproducible from the
descriptions above. This section claims no invariant and defends none; shrinking is not
implemented, so there is nothing for `INV-CHAOS-08` or any other entry to govern. See
`docs/BUSYBODY-TRANSFER.md` T-020, which stays `proposed`.

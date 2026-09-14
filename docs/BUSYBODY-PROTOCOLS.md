# What haru-pack's busybody would need from a shared core

Written independently, without reading lotek's sketch and without coordinating on it. Two
sketches diffed afterwards are a better specification than one negotiated document: the parts
that match are genuinely essential, and the parts that differ are exactly the design
decisions somebody has to make consciously. A negotiated document hides both.

Nothing here is a proposal to extract anything. It is the input to that decision.

---

## The thing to say first, because it reframes everything below

**haru-pack's cases do not decompose into steps, and the four protocols assume they do.**

A case here is one function:

```python
def staged_file_modified_after_success(exe: Path, work: Path) -> dict:
    cache, first = warm(exe, work)              # run it once so a stage exists
    victim = next(stage_root(cache).rglob("*.py"))
    victim.write_text("import os; os._exit(0)") # the perturbation
    return run_exe(exe, work, env=clean_env(cache))
```

That single function builds or warms the target, chooses and applies the fault, runs the
thing, and hands back a result to be classified. There is no loop, no action sequence, no
`driver.apply(step)`. A `TargetDriver` that "applies an action and returns a result" can
only be given the whole case as one opaque action, at which point the protocol is a function
call with extra ceremony.

This is not an accident and I do not think it is a defect. It follows from what the target
is. lotek drives a live stateful web application, where "the action sequence against shared
mutable state" is the actual object of study, so steps are real. haru-pack's target is a
**build→stage→run pipeline that terminates**: you produce an artifact, you perturb it, you
execute it once, it exits, you read the exit status. The interesting structure is in *which
perturbation*, not in *what order actions arrived*. Composing traits is haru-pack's answer to
the same question steps answer in lotek — a stack of traits is the sequence, flattened,
because for a pipeline that runs once the order of the mutations mostly does not matter and
the SET of them entirely does.

So the honest answer to "what would haru-pack need from a shared core" starts with: a core
that mandates a step-wise `TargetDriver` would make haru-pack's harness worse, and a core
that makes step-wise driving optional gets a `TargetDriver` implementation here with exactly
one method that is barely worth the indirection. **The four protocols are not equally load
bearing for this repo.** `FaultCatalogue` and `OracleSet` are real and I would use them
tomorrow. `PersonaSource` is real with one caveat. `TargetDriver` is where the two projects
genuinely differ, and pretending otherwise in a shared API is how the abstraction ends up
fitting neither.

---

## Common step representation

I will describe it, then say why haru-pack barely uses it.

```python
@dataclass(frozen=True)
class Step:
    """One thing done to the target, and enough to reproduce it."""
    seq: int                    # position within the run; 0-based, dense
    actor: str                  # which persona did it
    action: str                 # what was done, from a closed per-driver vocabulary
    args: Mapping[str, JSON]    # the parameters, JSON-serialisable, no objects
    at: float                   # unix seconds, when it was INVOKED
    provenance: Provenance      # why this step, and whether the harness chose it

@dataclass(frozen=True)
class Provenance:
    """Was this us? The first question anyone asks of a chaos finding."""
    seed: int
    draw: str                   # the salt: (seed, case, fixture, draw) determines the value
    deliberate: bool            # True = nemesis, False = buggification
    fired: bool                 # a perturbation may be selected and decline to act
```

Three things in that shape are load-bearing, and I would fight for all three:

1. **`args` is JSON, not objects.** A step crosses a process boundary here — cases run in
   `mpire` workers — and it is written to a file before the fault so it survives the worker
   being killed BY the fault. Anything that cannot be serialised cannot be evidence.

2. **`at` is when the step was invoked, not when it completed.** A fault whose moment was
   drawn from a seed is unattributable if recorded afterwards: a kill at 0.4 s and a kill at
   4.0 s leave the same case name with different outcomes and nothing says which was chosen.
   Announce, then act.

3. **`fired` is separate from "selected".** A perturbation with a per-action probability may
   decline. The run's identity is the set that FIRED, and a run where nothing fired is a
   control that arrived through the same machinery, which is worth more than one bolted on
   beside it.

**What haru-pack actually produces:** one `Step` per fault, typically one to three per case,
with no ordering relationship worth modelling between them. `seq` would be dense and
uninteresting. I would emit them because the evidence is valuable, and I would never dispatch
on them.

**The assumption a core must allow:** that a run has *zero* steps and is still a legitimate
run. Most haru-pack cases inject nothing through this channel at all — they mutate a file and
execute a binary — and a core that treats an empty step list as a degenerate or failed run
would reject the majority of this catalogue.

---

## `PersonaSource` — yields actors/cases to run

```python
class PersonaSource(Protocol):
    def personas(self) -> Sequence[Persona]:
        """Every actor this source knows about. Cheap; no I/O."""

    def cases(self, *, personas: Collection[str] = (),
              names: Collection[str] = ()) -> Sequence[Case]:
        """The units of work, filtered. An unmatched filter value is an ERROR."""

    def resolve(self, name: str) -> Case:
        """One case by name. Must work in a fresh process that never saw the parent."""

@dataclass(frozen=True)
class Persona:
    name: str
    description: str            # "an actor with an identity and a capability set"

@dataclass(frozen=True)
class Case:
    name: str                   # unique across the whole catalogue
    persona: str
    expect: frozenset[str]      # outcome names this case accepts
    why: str                    # what real situation this is
    inv: str                    # the invariant ids that govern it, or ""
    remedy: str                 # what to do when it fails
    needs_target: bool          # False for a case that builds its own artifact
    exclusive: bool             # this case measures TIME and must not share the machine
    run: Callable[[Target, WorkDir], RawResult]
```

### Assumptions this implementation makes that the protocol would have to allow

- **`resolve(name)` must work by NAME in a process that never saw the parent.** Cases run in
  worker processes. A work item is `(fixture, exe, case_name, run_dir, …)` — strings, not
  references — and the worker re-imports the catalogue and looks the case up. Any core that
  hands a `Case` object across the boundary is assuming pickling of a closure, which fails
  the moment a case captures anything interesting.

- **Registration is by import side effect.** `@case(...)` appends to a module-level registry
  when its module is imported. There is no manifest, no discovery, no entry points. This has
  a known hazard — a catalogue module imported only for its decorators looks like an unused
  import, and deleting one removes a whole persona with no error anywhere — and the
  protection is a test asserting the roster, not the mechanism. A core that wants declarative
  registration would be an improvement, and would also be a migration of 80 cases.

- **An unmatched filter is fatal, not empty.** `personas=["forger", "typo"]` must fail loudly
  rather than silently running only `forger`, because a run that skipped what you asked for
  reads exactly like a healthy one. If the core's filtering returns an empty sequence and
  lets the caller decide, every caller has to remember to check, and one will not.

- **`exclusive` is about wall-clock measurement, not about locking.** A case that sleeps 0.7 s
  and then signals is asking "where had the process got to?", and the answer changes when
  seven other cases are competing for CPU. The core must let a source mark work as
  *must-not-share-the-machine*, which is stronger than *must-not-share-a-resource*, and it
  must schedule those in a separate pass rather than interleaving them.

- **`needs_target=False` is not an edge case.** haru-pack's `wedge` persona attacks a
  *declaration* and builds its own artifact, so running it once per fixture would repeat one
  answer 25 times and inflate the census — which is precisely what the analysis exists to
  expose. A core whose iteration model is "for target in targets: for case in cases" cannot
  express this without a special case.

- **`expect` is per-case and is overridden by a global floor.** A case declaring `expect=
  {"REFUSED"}` that yields `CRASHED` is a finding, but so is a case that *declared*
  `CRASHED` acceptable. The FATAL set wins over the declaration. A core that treats `expect`
  as the whole pass condition loses the one rule the whole harness is built on.

---

## `TargetDriver` — applies an action to the thing under test

This is the one I am least able to write honestly, for the reason in the preamble. Here is
the shape that would actually fit:

```python
class TargetDriver(Protocol):
    def provision(self, spec: TargetSpec) -> Target:
        """Produce something to attack. EXPENSIVE. Cached and shared read-only."""

    def workspace(self) -> WorkDir:
        """Fresh, isolated, destroyable scratch for one unit of work."""

    def invoke(self, target: Target, work: WorkDir, *,
               env: Mapping[str, str], args: Sequence[str] = (),
               limits: Mapping[int, tuple[int, int]] | None = None,
               timeout: float, argv0: str | None = None) -> RawResult:
        """Run it ONCE, to completion or to the timeout. The whole interaction."""

    def teardown(self, work: WorkDir, *, keep: bool) -> int:
        """Destroy the workspace. Returns bytes freed. Must never raise."""

@dataclass(frozen=True)
class RawResult:
    rc: int | None              # None = never exited, or never started
    stdout: str
    stderr: str
    timed_out: bool
    seconds: float

@dataclass(frozen=True)
class Target:
    name: str
    path: Path                  # a FILE. See the assumptions.
    spec: TargetSpec
```

### Assumptions this implementation makes that the protocol would have to allow

- **`invoke` is the entire interaction, and it is called once.** No session, no connection,
  no sequence. The target starts, does everything it is going to do, and exits. Everything
  interesting happened before `invoke` (to the artifact, to the filesystem, to the
  environment) or is read from `RawResult` afterwards. A protocol built around repeated
  `apply(step)` against live state would have exactly one step here.

- **The target is a FILE, and perturbing it means editing bytes.** Cases flip payload bytes
  and recompute the footer digest, `chmod 000` it, rename it, invoke it through a symlink,
  override `argv[0]` without renaming it, truncate it mid-download. `Target.path` is not a
  handle or an address; it is a path on a filesystem the harness owns and may corrupt. A core
  whose `Target` is an opaque connection cannot express most of this catalogue.

- **`provision` is expensive enough to dominate everything.** A thick-tier fixture stages a
  real CPython; a top-25 sweep builds 25 real binaries. Peak measured work directory is
  452 MB, and a 37-case × 25-fixture sweep tracking them all needs roughly 100 GB — which is
  how a real sweep died at case 168 on a 24 GiB quota and then reported the quota failure as
  470 chaos findings. The core must let provisioning be hoisted out of the per-case loop and
  shared read-only across processes, and it must let the driver enforce a *scratch ceiling*
  the operator chose rather than dying at whatever the filesystem happens to allow.

- **`teardown` is per-case and unconditional, and the two halves are both required.** Freeing
  each workspace the moment its case finishes is what keeps a long sweep's live footprint at
  one case's worth; a final sweep in a `finally` is what survives a raise or a Ctrl-C. Having
  only the second is a leak with a delayed fuse. Having only the first loses everything when a
  case raises. And a worker process cannot share the parent's bookkeeping, so the *same*
  free-one-directory function has to be callable from both, or the two copies drift and the
  drift is a leak that only appears at one `--jobs` setting.

- **`limits` are POSIX rlimits applied in the child between fork and exec.** Address space,
  file descriptors. This is how an app-level persona starves an application without touching
  the host. A portable core will want to abstract this; whatever it abstracts to must still
  let a case say "768 MB of address space, and I have calibrated that number against two
  specific packages so that it discriminates between them".

- **`timeout` must never be `None`.** Not "the default" — no ceiling at all, which turns a
  hung launcher into a hung sweep. The core must not have a no-timeout mode that is reachable
  by omission.

- **The environment must be scrubbable, and the scrub list is target-specific.** haru-pack's
  binaries run `uv`, which honours `VIRTUAL_ENV`, `PYTHONHOME`, `UV_CACHE_DIR` and friends —
  so a chaos case can reach back out and modify the environment the harness itself is running
  from. This is not hypothetical: one case rebuilt this repository's own `.venv` against a
  staged interpreter and left `.venv/bin/python` a dangling symlink into a work directory that
  was then deleted. A chaos harness that damages the checkout it is testing is worse than no
  harness. The core cannot own that list; the driver must.

- **Some observations are only available from outside every process.** The stall watchdog is a
  thread in the parent sampling liveness, CPU and I/O of a whole process tree. It cannot be a
  driver method that returns a value, because the fact it establishes is emergent: from inside
  a child the only available fact is "I am waiting", and waiting is what a healthy child does
  too. The core must allow an observer attached to a *run*, not to an invocation.

---

## `OracleSet` — judges a result

```python
class OracleSet(Protocol):
    def classify(self, raw: RawResult, ctx: JudgementCtx) -> Outcome:
        """RawResult -> ONE outcome name from a closed vocabulary."""

    def attribute(self, raw: RawResult, outcome: Outcome) -> Blame:
        """Whose failure was it: the tool, the payload, the OS, or the harness?"""

    def verdict(self, case: Case, outcome: Outcome, blame: Blame) -> Verdict:
        """ok / finding, and at what severity. Applies the global floor."""

@dataclass(frozen=True)
class Verdict:
    ok: bool
    severity: Literal["critical", "warning", "note"]
    fatal_floor: bool           # True = a finding regardless of what the case expected
```

### Assumptions this implementation makes that the protocol would have to allow

- **Classification is by string matching on stdout and stderr, and I am not embarrassed by
  it.** A `haru-pack:` prefix means the launcher spoke; a known traceback marker means
  something crashed; a magic marker in stdout means the app actually ran. It is crude and it
  is *correct*, because the surface under test is a command-line tool whose entire contract
  with a human is the text it prints. A core that insists on structured results from the
  target is assuming a target that can be modified to produce them, and haru-pack's target is
  a binary a customer runs.

- **Exactly one outcome per result, from a closed set.** Not a list of matched predicates, not
  a score. Seventeen names, each with a sentence of meaning printed verbatim in every report.
  A core that lets oracles return overlapping judgements makes the report a set-union nobody
  can act on. If two oracles disagree, that is a bug in the vocabulary, and it should be
  impossible to express rather than reconciled at render time.

- **`blame` has five values and only two are derivable from output.** `launcher` and `app` can
  be read from the text; `os`, `harness` and `builder` must be set by whoever knows, at the
  point where they know. A protocol that makes attribution a pure function of the result
  cannot express "the kernel refused to exec this because a case chmod'd it to 000" — and
  calling that `app` is a lie in the direction that hides defects.

- **A global FATAL floor overrides every local expectation.** Seven outcomes are never
  acceptable whatever a case declared. This lives above the oracle set and below the report,
  and it is the sentence the whole harness is built on: not "can it be broken", but "does it
  break WELL".

- **Severity is three values, chosen once, closed.** Not "error"/"info". A fixed set means a
  reader learns three words once and a report cannot quietly grow a fourth level nobody has
  calibrated.

- **The oracle must be able to say "this is not a verdict at all".** Two of these are already
  load bearing and a third is missing:
  - `CASE-ERROR` — the harness itself broke. Never a statement about the product.
  - An *environment* failure aborts the whole sweep rather than scoring it. Once scratch space
    is exhausted, every later result is the same failure wearing a different persona's costume,
    and a ledger full of those is worse than an empty one.
  - **Missing: an indeterminate outcome.** Every outcome here assumes the action resolved.
    Jepsen's `:info` — timed out, may or may not have applied — has nowhere to go. `HUNG` is
    not it: `HUNG` is a verdict, and the honest answer is the absence of one. A shared core
    should have this from the start, because retrofitting a fourth value into a closed
    vocabulary means revisiting every `if outcome ==` in both repos.

---

## `FaultCatalogue` — supplies perturbations and environmental modifiers

The one I would adopt with no reservations.

```python
class FaultCatalogue(Protocol):
    def faults(self) -> Mapping[str, Fault]:
        """Everything registerable. Registration is by import side effect."""

    def sample(self, *, k: int, budget: int, seed: int,
               spread: str = "layer") -> Sequence[tuple[str, ...]]:
        """`budget` conflict-free stacks of `k`, deterministic in `seed`."""

    def realize(self, stack: Sequence[str], *, seed: int, index: int,
                force: bool = False) -> tuple[str, ...]:
        """Which of `stack` actually FIRES on this draw."""

    def conflicts(self, stack: Sequence[str]) -> tuple[str, str] | None:
        """The first pair where one silently cancels the other."""

@dataclass(frozen=True)
class Fault:
    name: str
    phase: str                  # when it can act: "build" | "run"
    layer: str                  # what it perturbs: cli/config/env/fs/proc/cache/payload/...
    why: str                    # the real situation this is
    probability: float          # per-action perturbation probability, (0, 1]
    conflicts: frozenset[str]
    degrades: bool              # may legitimately make the PAYLOAD fail
    terminal: bool              # after this the artifact cannot be executed here
    needs: tuple[str, ...]      # external requirements; skipped LOUDLY when absent
    inv: str
```

### Assumptions this implementation makes that the protocol would have to allow

- **`realize` must be deterministic per fault, not per sequence.** The firing decision is a
  hash of `(seed, index, name)`, not a draw from one sequential RNG. This matters more than it
  looks: with a shared RNG, adding one fault to the catalogue reshuffles the firing decisions
  of every other fault in every other run, and "reproduce with `--seed 7`" becomes a lie
  across a catalogue change. A seed has to keep meaning the same thing.

- **And the hash, not `Random(tuple)`.** Seeding `random.Random` with a tuple raises on Python
  3.14, and even where it works the mapping from seed to stream is an implementation detail. A
  digest of the triple is stable across Python versions and machines, which is the property a
  reproduction line in a report actually needs.

- **Faults have PHASES, and the phases are not symmetric.** A build-phase fault mutates the
  project and the command line before an artifact exists; a run-phase fault mutates the
  environment an existing artifact is executed in. They are not interchangeable and a stack
  may contain both. A core modelling faults as "things done to a running system" has no place
  to put the first kind — which for haru-pack is the more valuable kind, because the human
  fumbling that matters here happens at build time.

- **Ordering within a phase is load bearing in exactly one way.** A fault that makes the
  project read-only must run after every fault that writes to it, or it silently cancels them
  and the stack tests less than it claims. Two ordered lists, not a priority number: there are
  exactly two groups, and a number invites someone to invent a third.

- **`conflicts` means "one cancels the other", not "these break together".** Things that break
  together are the findings — the entire point. The core must not conflate a *don't-bother*
  relation with a *dangerous* one, or it will prune the interesting stacks.

- **A stack has no expectation, only the floor.** There are thousands of combinations and
  nobody has reasoned about each one. What can be asserted is that the tool refuses
  intelligibly under any stack of hostile conditions — never that it works. The core must let
  composed work be judged against the global floor alone, without inventing a per-stack
  expectation nobody wrote.

- **Sampling must prefer diversity across `layer`, and must enumerate exhaustively when the
  space is smaller than the budget.** Asking for 200 samples of a 35-combination space should
  give 35 distinct combinations, not 200 draws with repeats. And the diversity scoring has to
  be computed once per combination: the obvious comprehension is O(n²) and hung outright at
  k=3 over 40 faults — 9,880 combinations, ~97M evaluations. Worth saying in a protocol
  document because the naive implementation looks correct and is not.

- **Singletons are not an optimisation, they are the baseline.** Every fault gets an
  auto-generated `k=1` run with its probability forced to 1. Without those, "A+B failed"
  cannot be distinguished from "A was already broken", and the difference is the whole value
  of composing. A core that treats `k=1` as just another value of k will let someone skip it.

- **Missing from both, and I would put it in the core rather than in either repo: the golden
  run.** One un-perturbed control per campaign — rate 0, nothing fired, recorded AS the
  control. It makes findings attributable, it detects nondeterminism in the thing under test
  rather than in the harness, and it gives `fault window` something to be defined against.
  haru-pack gets one by accident today, when a probabilistic draw happens to fire nothing,
  and an accident is not a control.

---

## What I would need if the target were neither a web app nor a build artifact

The four protocols above are, read honestly, a description of two points rather than a shape:
lotek drives a long-lived stateful service through a network surface, haru-pack drives a
terminating pipeline through a filesystem and a process exit. Almost everything I have
asserted as essential — that `invoke` runs once, that the target is a file whose bytes can be
edited, that teardown is `rm -rf`, that classification reads text a human was meant to read —
is a fact about a *batch* target, and the corresponding lotek assumptions will be facts about
a *session* target. A third project that is another of either kind will confirm the union
without testing it, which is the failure mode worth naming before anyone picks one. What
would genuinely test this design is a target where **the thing under test cannot be
destroyed and recreated between units of work** — an embedded device, a long-running daemon
with expensive warm state, a piece of physical or third-party infrastructure, anything with a
real reset cost. Every convenience I have leaned on dies there at once: provisioning stops
being a cache-it-and-share-it problem and becomes a scheduling problem; teardown stops being
free and becomes a *restore-to-known-state* obligation that can itself fail and must itself be
judged; parallelism stops being "give each worker its own directory" and becomes genuine
contention; the `CASE-ERROR` / environment-abort distinction has to grow a third branch for
"the harness left the target in a state the next case cannot trust"; and the indeterminate
outcome stops being a nice-to-have from Jepsen and becomes the common case, because when you
cannot restart the world you cannot resolve an ambiguous action by trying again. If a core
survives that, the two current consumers are easy. If we source a third batch-shaped or
session-shaped target instead, we will get a shared library that fits three things and
generalises to nothing — and we will not find out for a year.

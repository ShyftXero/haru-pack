# busybody transfer log

haru-pack's busybody and lotek's are two independent implementations of the same idea. Ideas
move between them. Until now that happened when a human read one codebase and wrote a prose
list into the other's `docs/BRAINSTORM.md` — which works, and does not scale past two.

This is the log. **Append-only, newest last.** One row per item, whichever direction it went.

- `id` is `T-NNN`, allocated in this repo, never reused. lotek allocates its own; the two
  numbering spaces are independent and a row here does not imply a row there.
- `direction` is `lotek→haru` or `haru→lotek`.
- `status` is `proposed` / `landed` / `declined`.
- A `declined` row **must** carry a reason in `note`. Declining is a legitimate and valuable
  outcome: it records that somebody looked, which is the thing that otherwise gets
  re-litigated every six months by someone who cannot tell "rejected" from "never noticed".
- Dates are when the item LANDED, or when it was proposed if it has not. Backfilled rows say
  `unknown` rather than guessing; a fabricated date is worse than an absent one, because it
  reads as evidence.

| id | date | direction | item | status | note |
|---|---|---|---|---|---|
| T-001 | 2026-09-14 | lotek→haru | journal/heartbeat/ledger adoption | landed | the original port |
| T-002 | 2026-09-09 | lotek→haru | severity vocabulary: `critical`/`warning`/`note`, closed, three levels | landed | landed with T-001. A fixed set means a reader learns three words once and a report cannot quietly grow a fourth level nobody has calibrated |
| T-003 | 2026-09-09 | lotek→haru | fingerprinting + volatile-substring normalization (now: bucketing by signature, signature normalization) | landed | landed with T-001. The `_VOLATILE` table came over almost verbatim |
| T-004 | 2026-09-09 | lotek→haru | exit-code contract: 0 clean / 1 findings / 130 interrupted, interrupt WINS over findings | landed | encodes a judgement worth keeping: a run the operator killed did not finish, and reporting its partial findings as a completed verdict is the same lie facing the other way |
| T-005 | 2026-09-09 | lotek→haru | "SETUP FAILURE" as a distinct state from "no findings" | landed | the harness never reached the starting line, so there are no results, and reporting zero findings would be a lie |
| T-006 | 2026-09-09 | lotek→haru | `reap_orphans` guarded by the heartbeat rule (from lotek's `cleanup.py`) | landed | if ANY run has a fresh heartbeat, touch nothing |
| T-007 | 2026-09-11 | lotek→haru | composed concurrency + an external watchdog → the `herd` persona and `STALLED` | landed | re-aimed on landing. lotek composes N personas against a shared board; haru-pack has no board, but has exactly one shared mutable resource under a lock — the stage cache keyed by digest. Renamed from `WEDGED` because `wedge` already meant a config contradiction here (BRAINSTORM §1b) |
| T-008 | 2026-09-11 | lotek→haru | cascade tagging (`post_stall`) so one stall is not N findings | landed | arrived with T-007 and was the half easiest to miss. One stall would otherwise have entered the ledger as N fingerprints and ranked a single bug N times |
| T-009 | 2026-09-11 | lotek→haru | a seed, and announcing a perturbation BEFORE performing it | landed | the rule worth copying verbatim: journal it first, or the harness's own jitter reads as a product defect. lotek's framing — "a persona that executes its script perfectly was too competent" — applies here only halfway; haru-pack's runtime operator is a shell invoking `./myapp`, and a perfect executor really is realistic there. The fumbling that matters happens at BUILD time |
| T-010 | 2026-09-11 | lotek→haru | the "eager admin" / settings-tinkerer persona | landed | merged into the existing `wedge` persona on landing rather than kept separate: `wedge` had been built independently in the meantime with a better classifier (`sides`/`damage`, and a `REFUSED-UNRELATED` guard) and already solved once-per-run via `per_fixture=False`. Seven cases kept, the parallel machinery dropped |
| T-011 | 2026-09-11 | lotek→haru | WebUI-first: drive the surface through a browser | **declined** | **there is no web UI.** haru-pack is a CLI and a Nim launcher, and building one in order to have something to drive is the tail wagging the dog. The transferable half — *drive the surface a human actually touches* — became one `mute` case comparing a pty against a pipe against the rich output (INV-UI-01). Not a new harness |
| T-012 | 2026-09-12 | lotek→haru | single-instance run control (lotek BusyBody #738) | landed | a sweep registers itself and REFUSES to start while another is genuinely live, reaping a dead run's registry rather than trusting it. A bare pid is not proof; the heartbeat it owns is (INV-CHAOS-13) |
| T-013 | 2026-09-12 | lotek→haru | fail-loud selection: an unmatched `--persona`/`--case` is fatal, not dropped (lotek BusyBody #558) | landed | `--persona forger,typo` must not quietly run only forger and print a clean verdict, because a run that silently skipped what you asked for reads exactly like a healthy one (INV-CHAOS-12) |
| T-014 | 2026-09-14 | haru→lotek | **stall attribution: whose starvation was it?** | proposed | the reciprocal recorded in BRAINSTORM §1b and never routed. A composed run with a watchdog must attribute a stall to the harness or to the product; that is what `blame` and `APP-CRASHED` exist for here. A watchdog that calls its own scheduling starvation a product stall is the `tight_address_space` mistake — a threshold that looks thorough and discriminates nothing |
| T-015 | 2026-09-14 | lotek→haru | deterministic markdown report + `replay` + `author` | proposed | `tests/busybody/report.py`, `replay.py`, `author.py`. haru-pack's `report.txt` is flat text; lotek's is a no-LLM deterministic markdown report, plus a `replay` that reconstructs a failing k-set and an `author` that generates a corpus script covering what prior runs missed |
| T-016 | 2026-09-14 | lotek→haru | forensic bundles: collect the state that EXPLAINS a finding, not only the record | proposed | `tests/busybody/bundle.py`. lotek collects py-spy, `pg_stat_activity`, screenshots. The haru-pack analogue is process tree, open FDs, staged-dir listing, scratch usage |
| T-017 | 2026-09-14 | (neither) | the indeterminate outcome — Jepsen's `:info` | landed | a JOINT gap, taken from Jepsen rather than from either repo. Both harnesses assume every action resolved; Jepsen's model is `:invoke / :ok / :fail / :info`, where `:info` means "timed out, may or may not have applied". A harness against a real system generates these constantly and neither repo has anywhere to put them |
| T-018 | 2026-09-14 | (neither) | a golden run: one un-perturbed control per campaign | landed | standard in the fault-injection literature, absent from both. Makes findings attributable, detects nondeterminism in the thing under test rather than in the harness, and gives `fault window` something to be defined against |
| T-019 | 2026-09-14 | (neither) | "did the fault land?" — a test-infrastructure finding when a fault window opens and closes with no observable effect | landed | absent from both. AWS FIS allocates one of its five stop-condition alarms to exactly this distinction. A deliberately injected fault that is silently swallowed before reaching the target produces silence, which currently reads identically to "the system absorbed it correctly" |
| T-020 | 2026-09-14 | (neither) | shrinking (`ddmin`) over the fired trait stack | proposed | the largest capability gap against every peer tool, absent from both. haru-pack is the better repo to spike it in: a case here is a function over a fixture rather than a long action sequence against a live stateful app, so the search space is much smaller. Both repos already have the hard prerequisite — seeded determinism and replay |
| T-021 | 2026-09-14 | (neither) | `rate x severity` is independently validated by FoundationDB's `BUGGIFY` | landed | not a transfer, recorded because it changes how much the design should be trusted. `BUGGIFY` has a 25% base rate, `BUGGIFY_WITH_PROB(p)` for frequency and knob buggification for magnitude, split into separate mechanisms in their PR #7358. Both harnesses arrived at the same decomposition independently. Landed as vocabulary (S2), not as code |

## Direction, honestly

Fourteen of the first fifteen rows run lotek→haru. That is not modesty, it is the record:
haru-pack's busybody was a deliberate reimplementation of lotek's, from lessons learned, with
a mandate to send optimizations back — and **as of 2026-09-14 the return trip is not
evidenced anywhere in lotek.** The string `haru` appears nowhere in that repo. The second
round documented in `docs/BRAINSTORM.md` §1b went lotek→haru as well; its "reciprocal, if
anyone is routing it back" section (now T-014) was written and never routed.

This file exists so that stops being invisible. A `haru→lotek` row with `status: proposed`
and no landing date is a debt, and it is supposed to look like one.

## How to add a row

Append. Do not renumber, do not reorder, do not edit a landed row's `item` — if the thing
changed after landing, that is a new row citing the old one. The point of an append-only log
is that a claim about what was transferred, and when, cannot be quietly revised later; this
repo's documented AI failure mode is over-claiming verification (`THREAT_MODEL.md`,
`INV-DOC-01/02`), and a rewritable transfer log is that failure mode with a table around it.

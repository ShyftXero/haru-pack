# busybody record schemas

`schema_version: 1`

The on-disk contract for the three record types busybody writes. This document is the
contract; the code is an implementation of it. If the two disagree, that is a bug in one of
them and this file says which one you are allowed to change without telling anyone (neither).

It exists because there is a second, independent implementation of busybody in `lotek`, and
a shared core — if one is ever extracted — will inherit these schemas whether or not anybody
designs them deliberately. Writing them down is the cheapest moment to notice that the two
projects spell the same thing differently.

Every record carries `schema_version`. It starts at `1` and goes up when a field changes
meaning or disappears; adding a field does not bump it, because a reader that ignores
unknown keys is unaffected. A record without the key predates this document and is version
`1` by definition.

**Everything here is JSON Lines.** One object per line, UTF-8, no trailing commas, written
with `sort_keys=True` so two runs of the same sweep produce byte-comparable files. A torn
final line is expected — it is what `kill -9` mid-write looks like — and every reader skips
an unparseable line rather than refusing the file.

---

## 1. Journal line

**Where:** `busybody/out/runs/<run-id>/journal.jsonl`, one file per run, append-only, one
`fsync` per line.

**Why a line at a time:** a run that is interrupted used to lose everything, because results
were serialised after the last case. Every record is now flushed as it happens, so a `kill
-9` costs at most the case in flight.

### Fields on every journal line

| field | type | required | meaning |
|---|---|---|---|
| `schema_version` | int | yes | the version of this document the writer implemented |
| `run` | string | yes | the run id, `bbYYYYMMDD-HHMMSS`. Also the run directory's name |
| `at` | float | yes | unix seconds, 3dp, when the record was written |
| `kind` | string | yes | which record this is; see below |

### `kind` values

| kind | when | additional fields |
|---|---|---|
| `started` | once, before any case runs | `planned` (list of string), `tier` (string), `fixtures` (list of string), `cases` (int), `total` (int). A compose run adds `mode` (`"compose"`), `compose_k` (int\|null), `compose_seed` (int), `forced` (bool) |
| `case` | once per completed (case, fixture) pair | the whole finding record below, minus `why` |
| `perturb` | before a fault the harness is about to inject | `case`, `fixture` (string), `seed` (int), `action` (string), plus per-action fields |
| `stall` | when the watchdog declares no progress | `case`, `fixture`, `seed`, `stall_id` (string), `quiet_s` (float), and the watchdog's evidence |
| `finished` | once, only on a complete run | `cases` (int), `findings` (int), `peak_scratch_bytes` (int) |
| `interrupted` | on Ctrl-C | `completed` (int), `planned` (int) |
| `setup_failure` | the harness never reached the starting line | `detail` (string, ≤400 chars) |
| `infra_failure` | the BOX failed, not the product | `detail` (string, ≤400 chars), `completed` (int) |

Three things are load-bearing about this list rather than incidental:

- **A journal with no `finished` record and a stale heartbeat means INTERRUPTED**, which is a
  different fact from "no results" and a much more interesting one. Absence is the signal;
  there is no `state` field and adding one would let a killed process lie.
- **`perturb` and `stall` are different kinds on purpose.** A perturbation is a fault this
  harness INJECTED; a stall is a fact it OBSERVED about the product. Filing an observation
  as a perturbation would make the seeded records untrustworthy, because a reader could no
  longer tell which entries the harness caused.
- **`perturb` is written BEFORE the fault, never after.** A fault whose moment was drawn
  from a seed is unattributable if recorded afterwards: a kill at 0.4s and a kill at 4.0s
  leave the same case name with different outcomes and nothing says which moment was chosen.

### The heartbeat

Not JSON, and deliberately so: `busybody/out/runs/<run-id>/heartbeat` holds a bare unix
timestamp as text, rewritten as the run proceeds. Freshness is the only thing the file
means, so last-writer-wins is correct and a worker rewriting it is not a second log writer.
Older than 120 s = not live.

---

## 2. Finding record

**Where:** two places, with different subsets, which is itself worth knowing.

- In the journal as a `case` line — the FULL record minus `why`.
- In the findings ledger — a SUBSET, only for records where `ok` is false.

**Why the ledger is outside the repository:** a file inside the tree is caught by `git
stash`, by worktree switches and by branch changes, losing history exactly when you are
moving between branches to investigate something. It lives at
`<parent-of-main-checkout>/haru-pack-busybody-findings.jsonl`, resolved through
`git rev-parse --git-common-dir` so a linked worktree reaches the MAIN checkout's neighbour
rather than its own doomed directory.

| field | type | required | meaning |
|---|---|---|---|
| `schema_version` | int | yes | as above |
| `name` | string | yes | the case function's name. Unique across the catalogue |
| `persona` | string | yes | the mindset the case belongs to — an actor with an identity and a capability set |
| `fixture` | string | yes | which binary was attacked. `"(config)"` for a case that builds its own, `"(stack)"` for a composed run |
| `outcome` | string | yes | one of the closed outcome vocabulary; see below |
| `expect` | list of string | yes | the outcomes this case declared acceptable |
| `ok` | bool | yes | `outcome in expect` AND `outcome not in FATAL`. The FATAL floor overrides what the case declared |
| `severity` | string | yes | `critical` \| `warning` \| `note`. Closed, three levels, chosen once |
| `fingerprint` | string | yes | 16 hex chars. The bucketing signature; see below |
| `rc` | int \| null | yes | the process exit status. `null` means it never exited (timeout) or never started |
| `seconds` | float | yes | wall clock for the run, 1dp |
| `blame` | string | yes | `launcher` \| `app` \| `os` \| `harness` \| `builder` \| `none` \| `unknown` |
| `seed` | int | yes | the run seed. With `name` and `fixture` it determines every drawn moment |
| `post_stall` | bool | yes | this result resolved AFTER a stall was already declared, so it failed for the stall rather than for itself |
| `stall_id` | string | yes | which stall, `""` if none |
| `inv` | string | yes | the `INV-` ids governing this case, or `""`. Every non-empty value resolves to a declaration (INV-DOC-01) |
| `remedy` | string | yes | what to do when it fails. Printed in the report so the reader does not have to work it out |
| `why` | string | yes in the journal's source record, **stripped from the `case` line** | what this case simulates. Static per case; the report reads it from the catalogue |
| `stdout` | string | yes | last 400 chars, stripped |
| `stderr` | string | yes | last 400 chars, stripped |
| `scratch_bytes` | int | yes | apparent size of the case's work directory at the end |
| `artifacts` | string | no | repo-relative path to the preserved wreckage. Present whenever `ok` is false |
| `message` | string | ledger only | `stderr or stdout`, first 500 chars. The fingerprint basis |
| `run` | string | ledger only | the run id, so a ledger row can be traced back to its journal |
| `at` | float | ledger only | unix seconds when the row was appended |
| `selected` | list of string | compose only | traits chosen for this stack |
| `fired` | list of string | compose only | traits that actually acted. **The run's identity is the set that FIRED** |
| `run_index` | int | compose only | which draw this was, part of the firing decision's basis |

### The outcome vocabulary

Closed. `RAN`, `REFUSED`, `CRASHED`, `HUNG`, `SILENT`, `APP-CRASHED`, `CASE-ERROR`,
`WARNED`, `SILENT-WEDGE`, `EXPOSED`, `LEAKED`, `REFUSED-UNRELATED`, `STALLED`, `CONTAINED`,
`SANCTIONED`, `ESCAPED`, `SMUGGLED`.

`CRASHED`, `HUNG`, `SILENT`, `SILENT-WEDGE`, `STALLED`, `ESCAPED` and `SMUGGLED` are the
**FATAL floor** — never acceptable, whatever the case declared. `ok` is false for any of
them even when `expect` names one.

### Bucketing by signature

`fingerprint` is the universal fuzzing idea: `sha256(persona|case|outcome|normalized
message)[:16]`. Three cases failing for one reason should read as one problem, so the
volatile parts of the message — uuids, hex, timestamps, addresses, paths, ports, bare
numbers, run ids — are replaced with placeholders before hashing. That replacement is
**signature normalization**; without it, one root cause splits into as many groups as there
are runs.

Keyed on the case as well as the message on purpose: the same underlying fault reached
through a different persona is worth seeing separately, because the route matters when you
are deciding what to fix.

`post_stall` is deliberately **not** in the fingerprint basis. A cascade of a real fault
would fingerprint differently from the same fault seen cleanly, splitting that fault's
history in two — and the basis is written into every row already on disk, so changing it
would orphan every fingerprint ever recorded.

### Fault window and injection provenance

A **fault window** is the interval between a `perturb` record and the `case` record that
resolves it — the span during which the harness had deliberately perturbed the system.
There is no crisp standard term for this and we are keeping ours.

It is defined against the **golden run**: the un-perturbed control, rate 0, no traits fired,
recorded as such. Without a golden run the window has nothing to be a window *from* — you
can say a fault was injected but not what the system was doing when it was not.

The per-finding tag naming which perturbations were open when a finding landed is its
**injection provenance**: `seed`, `fired`, and the `perturb` records that precede it in the
journal. It answers "was this us?", which is the first question anyone asks of a chaos
finding.

---

## 3. Ledger rollup entry

**Where:** not on disk. `ledger_rollup()` produces these in memory from the ledger, and
`--triage` prints them. Documented because a shared core would expose it as an API and
because the grouping key encodes a judgement worth stating.

One entry per **(fingerprint, post_stall)** pair.

| field | type | required | meaning |
|---|---|---|---|
| `fingerprint` | string | yes | the group's identity |
| `post_stall` | bool | yes | part of the grouping key, not of the fingerprint |
| `count` | int | yes | rows in this group |
| `first_seen` | float \| null | yes | earliest `at` in the group. `null` is possible and renders as `unknown`, never as a fabricated 1970 |
| `last_seen` | float \| null | yes | latest `at` |
| `runs` | list of string | yes | run ids, sorted, empties dropped |
| `cases` | list of string | yes | case names, sorted |
| `personas` | list of string | yes | personas, sorted |
| `outcome` | string | yes | from the first row seen in the group |
| `severity` | string | yes | from the first row seen in the group |
| `inv` | string | yes | from the first row seen in the group |
| `remedy` | string | yes | from the first row seen in the group |
| `sample` | string | yes | one `message`, verbatim, for recognising the group |

**Ordering is part of the contract**, not a display choice: `(post_stall, -count,
fingerprint)`. Every cascade group sorts below every fresh one *whatever the counts*. When
the watchdog declares a stall, every child that resolves afterwards also fails — sixteen of
them share a persona, a case and an outcome, so they land in one group, and ranking by count
alone put that group above a genuine one-off finding. One bug, ranked sixteen times, at the
top of triage.

`post_stall` joins the grouping key rather than the fingerprint for the same reason it is
excluded from the basis, plus one more: a fault seen both cleanly and as a cascade must not
merge, or the group's remedy and sample come from whichever row happened to be read first.

---

## Known divergences

Places where haru-pack and lotek name the same thing differently. **Neither repo renames
unilaterally.** Recorded here and left alone; Eli arbitrates.

*(Nothing recorded yet. This section is filled by diffing this file against lotek's, which
is written independently and to the same instructions. Populating it from memory of the
other codebase would defeat the exercise — the whole value is that two people wrote down
what they actually emit and the diff is the answer.)*

The one collision that was NOT left alone is **divergence**, because the two repos used the
same word for unrelated mechanisms and a collision cannot survive into a shared API:

- lotek's means the UI surface disagreeing with the API surface → **surface-divergence**.
- haru-pack's means one case answering differently across fixtures → **fixture-divergence**.

Neither keeps the bare word.

---

## Smells

Things writing this down exposed. Recorded rather than fixed, per the instruction that S1 is
a documentation pass over what already exists.

- **`why` is on the record and stripped on the way to the journal.** It is static per case —
  the same string every time the case runs — so it is catalogue data that has been riding
  along inside per-run data. The strip is a workaround for that, and it means the journal's
  `case` line and the in-memory record are not the same shape despite sharing a name.

- **The ledger subset is defined by a literal key list in two places.** `_finalize` and
  `_finish_compose` each carry their own tuple of field names, and the compose one has three
  extra entries (`selected`, `fired`, `run_index`). Two lists that must agree, in two files,
  with no check — and they already do not agree, which is a feature nobody declared.

- **A ledger row has fields a journal `case` line does not (`run`, `at`, `message`) and vice
  versa.** They are the same record type in the code's mind and two different types on disk.

- **`expect` on a composed stack is a string describing a negation** — `"not
  CRASHED/HUNG/SILENT/..."` — sitting in a field whose type is elsewhere a list of outcome
  names. A consumer that treats `expect` as a set of outcomes gets nonsense from a stack.

- **`blame` can be `unknown`, and that is a hole rather than a value.** It surfaces in
  `--analyze` as a `?` bucket; there were 25 of them in the 2026-09-10 sweep, all from one
  early-return path. The schema cannot say the field is meaningful because sometimes it is
  not.

- **There is no outcome for "we do not know whether it applied".** Every outcome here
  assumes the action resolved. Jepsen's model has `:info` for exactly this — timed out, may
  or may not have taken effect — and a harness against a real system generates them
  constantly. `HUNG` is not it: `HUNG` is a verdict, and the honest answer is an absence of
  one.

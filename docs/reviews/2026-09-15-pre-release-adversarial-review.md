# Pre-release adversarial review — 2026-09-15

Subject: `origin/main` @ `265c963`. Scope: whole repo (~36.5k LOC), read as **public-release
readiness**. Three hostile auditors (crypto/licensing, supply-chain/sandbox, invariant
honesty) plus a direct pass. Findings below were spot-verified against the tree; anything an
auditor asserted that is not reproduced here was either unverified or reframed.

**Verdict: BLOCK** — not for any single exploit, for a pattern.

## The pattern

Nearly every finding has the same shape: **a prose claim broader than the code directly
below it.** Three shipped documents contradict each other on the headline security claims,
and several "machine-checked" guards are satisfiable without the property holding.

The code is consistently *stronger* than the documentation. That is the good news: most
criticals are documentation-truth problems, not vulnerabilities. It is also the bad news,
because auditability is this project's differentiator, and a reader cannot tell which
document to believe.

---

## Critical

### C1 — The invariant gate is green on tests that never ran
`.github/workflows/ci.yml` contains **zero** mentions of `nim` (verified: `grep -c` → 0).
Every test that compiles `cryptbox.nim` calls `pytest.skip`. Skips are not failures, so
`pytest -m invariant` exits 0. And `tests/_invariants.py:collect_markers` proves linkage with
a **regex over test file text** — never a pytest outcome.

So an `active` invariant can be "claimed" by a test that has never executed on the machine
that gates merges. Measured by the auditor via AST: **100% of claimant test functions are
nim-gated** for INV-CRYPTO-06 (4/4), INV-GATE-01 (5/5), INV-GEO-01 (4/4), INV-REMOTE-01
(6/6), INV-EPHEMERAL-03 (6/6).

A commented-out marker, a marker inside a docstring, an `xfail`, or a module that fails at
import all satisfy the contract identically.

This is the flagship anti-hallucination control failing in exactly the manner it was written
to prevent, one level up. **Fix this first** — it is cheap, and it is what makes every other
claim in the repo checkable.

### C2 — `INV-SECRET-02` is declared twice; the machinery silently drops one
113 `### INV-` headings, **112** parsed entries. `load_invariants` returns a dict, so the
second `INV-SECRET-02` (`INVARIANTS.md:1752`, about build receipts) silently replaces the
first (`:1651`, about secrets at rest in the binary). The dropped entry's `Status`,
`Territory` and required fields are never validated, it is never checked for a claiming test,
and ten markers are credited to a claim they do not test. Every guard-of-guards test is blind
to it.

### C3 — Three shipped documents disagree on the headline claims
`THREAT_MODEL.md` "Known gaps, ranked" states:
- *"1. The launcher does not verify its payload before executing it."* — `INV-LAUNCH-01` is
  `active`; `README.md:335` says it does.
- *"2. Nothing downloaded is digest-checked, on the build host or the target."* —
  `INV-SUPPLY-01` is `active`; `README.md:149` says everything is pinned.

The same staleness recurs at `THREAT_MODEL.md:73` (B9 claims header unauthenticated + fix
`proposed`; `crypto.py:119` authenticates it and the invariant is `active`), `:179` (claims a
`HARUPACK_DEV_STAGE` licensing bypass in release builds; `main.nim:200` guards it behind
`when defined(haruDev)`), `:185` (claims Nim deps unpinned; `bootstrap.py:32` pins four), and
`docs/ENCRYPTION_LICENSING.md:69` + `README.md:282` (both still document the `HARUPACK_GEO`
env bypass, which was deleted and is now actively scanned for by `tests/test_canary.py`).

**Three of these carry a `[V]` marker**, in a file whose own preamble defines `[V]` as
"verified in this repo, by a test or by direct observation of the code." `INV-DOC-02` only
checks that a "Verified" section cites *some* INV- id — never that the prose matches it.

Shipping this `THREAT_MODEL.md` publicly would be worse than shipping no threat model.

### C4 — "Machine and user binding are cryptographic"
`cryptbox.nim:83`: `currentUser()` is `getEnv("USER")`, falling back to `USERNAME`. The value
is folded into the KDF, so the binding is genuinely cryptographic — but it binds to a string
the licensee types, not to a person.

The problem is asymmetric hedging. `README.md:334`, `ENCRYPTION_LICENSING.md:63` and
`THREAT_MODEL.md:80` all carefully hedge the machine case ("`/etc/machine-id` is a writable
file"), and give the **weaker** binding no hedge at all — so a reader concludes the unhedged
one is solid. `cryptbox.nim:111` goes further: "strictly stronger than a checked rule".

### C5 — `INV-SUPPLY-01` lists the Nim toolchain as digest-verified; it is not
Statement: *"Every artifact haru-pack downloads **directly** — **the Nim toolchain**, the `uv`
release asset, and the python-build-standalone interpreter — is verified against a digest…"*

`toolchain.py:433` verifies the **choosenim installer**, then `:440` executes it, and
choosenim fetches the entire Nim compiler from nim-lang.org unverified by this repository.
The word "directly" excludes precisely the artifact the sentence lists first. That compiler
builds the launcher embedded in every customer binary. `README.md:149`
("**Everything downloaded is pinned.**") is false as a heading.

### C6 — Geo-gated binaries call a third party on every launch, undocumented
`execgate.nim:23` → `DefaultGeoEndpoint = "https://ipwho.is/"`, on every run.
`docs/ENCRYPTION_LICENSING.md` has no execgate section and says online lookup is "future
work". Two undisclosed consequences for a commercial product: every customer's IP goes to an
unaffiliated free API (a privacy/DPA question the vendor will be asked), and the gate **fails
closed** — if ipwho.is rate-limits or disappears, every geo-gated binary in the field stops
running. A free third-party endpoint is a hard availability dependency of the customer's
application, documented nowhere the customer reads.

---

## Warnings

**The "policy decision" test shape.** The auditor named a failure mode this repo has no
defence against. Predicates are tested well, often by compiled Nim. Call sites are tested by
`str.index()` ordering over source text. But the *decision that selects the safe mode* is
tested by the test handing itself the safe mode as an argument:

```python
argv = argv_for(cmd=["/w/numpy"], network=False, cache=sandbox.CACHE_COLD)
assert flag_value(argv, "--network") == "none"
```

The real decision is `tools/flex-run.py:225` (`network=not offline`). No test reads it.
`tests/test_stage_callsites.py` exists because someone found the second shape; nothing exists
for the third. This affects INV-SANDBOX-01, INV-SANDBOX-02 and INV-SUPPLY-11 — **all written
in the last two days, all mine.** The red-paths I recorded as walked were walked against
`docker_argv`, not against the call site, and the Statements do not say so.

Others, abridged:

- `tools/exam_fetch.py:59` downloads and extracts arbitrary PyPI sdists **on the host, outside
  any container, with no digest**, into the repo working tree — while `tools/exam.py:22` claims
  "both happen inside a throwaway container".
- `tools/sandbox.py:157` splices `extra` **after** every security flag. Docker is last-wins, so
  `extra=("--network","host")` or `("-u","0:0")` silently defeats the containment. No test
  passes `extra`.
- `tools/sandbox.py:23` claims "the cache is read-only while stranger code runs";
  `tools/sandbox.py:70` says "There is deliberately no read-only mode." Same file.
- `tools/sandbox.py:229` — `image_tag` hashes 2 of the image's 6 inputs. Editing `src/` or any
  `docker/` digest-verifier does not change the tag, so `ensure_image` reuses a stale image
  while `flex.Dockerfile:5` claims the opposite.
- `README.md:147` — "there is no archive fallback and no build-from-source fallback"; both
  shipped earlier the same day.
- Zip extraction has no guard (`bundle.py:58`, `toolchain.py:310`) while `archives.py` states
  the rule absolutely. `docker/install-nim-*.py` permit symlink members without checking
  `linkname`, weaker than `archives._reject_unsafe_members`.
- `cryptbox.nim:52` — attacker-chosen unbounded PBKDF2 `iters` (footer is not a MAC and is
  recomputable, per README). Set `0xFFFFFFFF` and every customer binary pins a core forever,
  with tamper-detection only *after* the work.
- `main.nim:113` — `runChild` passes no `env`, so `HARU_SECRET` (the documented trust anchor)
  is inherited by the packed app and by project-controlled `[[bundle]]`/`post_install` steps,
  while `THREAT_MODEL.md:47` lists the packed project as a hostile actor.
- No `NOTICE`/`THIRD_PARTY` file, yet zippy/puppy/parsetoml/nimcrypto are statically linked
  into every binary an operator signs and ships.
- `.github/workflows/publish.yml` — bare `workflow_dispatch` + tag-pinned (mutable) third-party
  actions + `id-token: write` against a PyPI trusted publisher; nothing asserts the ref is a
  reviewed tag matching `pyproject.toml`.
- No `.dockerignore` — `sandbox.py:241` uploads the whole repo as build context, including
  `.git/` and `flex/out/` (extracted third-party sdists).
- No resource limits on any container running stranger code (no `--pids-limit`, `--memory`,
  `--cpus`). `tools/busybody_docker.py` already passes `--read-only` and `-m 512m`, so the
  capability exists and the top-25 matrix does not use it.

## Notes

- `docs/adr/0003` still lists `BASE_PATH` as "wired, TODO consumer"; ADR 0004 implemented it
  (`main.nim:174`). No supersession note.
- `crypto.py:30` — PBKDF2-SHA256 at 200k iterations, not CLI-exposed. OWASP's current floor is
  600k, and the attacker here holds the container forever with no rate limit.
- `cryptbox.nim:119` grants an undocumented one-day expiry grace that `build/validate.py:67`
  does not know about; a licence sold to a date ends on a different one, favouring the
  licensee.
- `crypto.py:91` — `--machine ""` silently ships with no machine binding, no receipt line.
- `tests/test_sandbox.py:370` hardcodes `/home/shyft`.

---

## What is genuinely good

Worth recording, because the findings above are unrepresentative of the average line:

- `README.md` "Status" is the most honest security writing in the repo: it says
  `/etc/machine-id` is writable, that `--expires`/`--geo` are **not** enforcement, that the
  payload digest is **not a MAC**, and that `INV-TRUST-01..07` are all `proposed` and
  undefended.
- `src/haru_pack/launcher/xz/PROVENANCE.md` is an exemplary vendoring record: upstream, tag,
  tarball digest, 0BSD license, and why the alternatives were rejected.
- `--shake` is opt-in, refuses without a declared test command, verifies after pruning, and
  explicitly disclaims that a passing suite proves runtime safety.
- No secrets in git history; `haru-pack` is available on PyPI; the arm64 bootstrap failure
  message names the constraint and gives the cross-compile workaround.

## Suggested order

1. **C1** — install nim in CI, or fail the invariant gate when a claiming test skips. Cheapest
   fix, and every other claim becomes checkable behind it.
2. **C2** — dedupe `INV-SECRET-02`; make `load_invariants` refuse duplicate ids.
3. **C3** — reconcile `THREAT_MODEL.md` against `INVARIANTS.md`, or delete the ranked-gaps list
   until it can be regenerated. Consider a test that fails when a `[V]` claim cites an
   invariant whose `Status` contradicts it.
4. **C4/C5/C6** — three sentences of honest hedging each; no code change required.
5. The "policy decision" test shape — one new call-site test per affected invariant.

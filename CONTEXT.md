# haru-pack glossary

The precise vocabulary for the launcher stub's runtime configuration, plus any term that
has come to mean more than one thing. Glossary only — no implementation, no decisions (those
live in INVARIANTS.md and docs/adr/).

## canary
An env-var **prefix token the stub intentionally watches for** at runtime. The name is
deliberate (offsec sense): the stub is *looking* for it. Matching is **per-knob**: every knob
has exactly one canary, so the stub reads exactly one env name per knob. The default canary
for all knobs is `HARU` (or the `--env-canary` value, or a random token from
`--env-canary-random`); `--stub-env-<knob>-canary=X` overrides one knob's canary and *only*
that knob's. So after `--stub-env-uv-ver-canary=MARK`: `MARK_UV_VER` is read for uv_ver,
`HARU_SECRET`/`HARU_SOURCE_URL`/`HARU_BASE_PATH` for the rest — and `HARU_UV_VER` and
`MARK_SECRET` are both **invalid**. A canary raises the cost of guessing knob names; it is
**not** secrecy (an unencrypted stub-config reveals the map).

## knob
A single stub-input setting, read at runtime as `<canary>_<KNOB>`. The catalogue is closed:
`SECRET` (decryption key), `UV_VER` (uv version to fetch), `SOURCE_URL` (remote-fetch payload
URL), `BASE_PATH` (where the stub stages uv/python and the payload tree). The **license
policy is NOT a knob** — expiry/machine/user/geo can never be set or overridden by the end
user, by design.

## inject (env-append)
Literal `KEY=VALUE` pairs, chosen by the packager at build time, that the stub sets in the
child environment **before invoking uv or the app** — so both see them (licensing, API keys).
"Inject", never "project": *Project* is the packaged application. An injected value is
recoverable from the binary unless the payload is encrypted.

## stub
The Nim launcher. The **delivery vehicle**, invisible to haru-pack's own users: they never
write Nim or reason about it. Its job is to carry a payload to an end-user and run it —
flexibly, securely, off-road.

## RAM-backed staging (ephemeral)
Staging the payload into memory-backed storage (`/dev/shm` or `memfd` on Linux; Windows TBD)
so nothing the payload contains is written to persistent disk. For packagers concerned about
disk-based artifacts. Distinct from the normal **cache**, which is persistent and reused.

## detached reap
The stub's fire-and-forget final act when `--reap` is baked in: after the app exits it spawns
a **separate, detached process** to delete the exact subtree it created this run, then exits
immediately. Cleanup of many gigabytes continues after the stub has died. Independent of
`--ram-only` (either, both, or neither): `--reap` alone deletes a subtree of the *persistent*
cache; with `--ram-only` it deletes the RAM-backed one. It only ever removes the
stub-created `<root>/<key>-<digest>` subtree — never a raw `BASE_PATH`, and never a refused
root (`/`, a drive/UNC root, or a home directory).

## remote-fetch
A **delivery modifier**, orthogonal to the bundling tier: the payload is fetched over HTTP at
runtime instead of being appended to the binary. Default delivery is **appended**; remote is
opt-in but first-class. Like `--thin`, a remote binary needs network to work. The fetched
blob is an ordinary payload run through the **one** payload pipeline (verify → decrypt →
license → stage) — the byte *source* is the only difference, so no step can be side-stepped
by choosing a delivery mode.

## payload pipeline
The single code path that turns payload bytes into a running app: digest-verify → decrypt (if
encrypted) → license-check → stage. It runs identically whether the bytes come from the
appended overlay or from a remote fetch. The trust anchor is a **build-time-baked expected
digest**: whatever the source, only bytes matching it are accepted.

## execution gate
A pre-run condition the stub evaluates before handing control to the app. All gates share
**one shape** — resolve a current value, match it against an allow-policy, **fail closed** —
and all live **inside the encrypted policy** (post-decrypt, hidden from a reverse-engineer)
and are **non-overridable by env**. Designing one gate means designing them all the same way;
a bespoke mechanism for a single gate is drift. The rule-checked gates are `date` (expiry),
`geo`, and `ip`. `machine` and `user` are additionally **cryptographically bound** (a wrong
value means the payload will not decrypt) — strictly stronger than a checked rule, but
declared in the same policy for uniformity.

## geo / ip (execution gates)
Location and address gates, "similarly shaped": resolve a value from a **consensus of online
sources**, then match an allow-policy. A single bare TLS request to a resolver (default
`https://ipwho.is/`) returns both the caller's IP and its geo — no second request needed. The
packager may list **N resolver endpoints** and require a **consensus** of `K` (default 1) to
be reachable and agree the user is allowed, so one endpoint being down or lying does not
decide the gate. **Fail-closed:** if fewer than `K` endpoints resolve (TLS failure,
unparseable body, `success != true`), the app does not run. The policy is a list of **allow
rules**; a rule is a set of `field=value` assertions against the resolver JSON (e.g.
`country_code=US, region=California`) — AND within a rule, OR across rules. The old
`HARUPACK_GEO` env bypass is removed.

## reap (build-time)
A packager choice, fixed at build with `--reap`, that bakes an always-on on-target action:
after the app exits, the stub spawns a **detached reap** of the staged subtree. Defined at
build, not toggled at runtime. Reaping an unencrypted thin build is the packager's call.

## wedge

**One word, three senses.** Two of them are code, one is how Eli says it out loud. Worth
disambiguating before acting, because "find me a wedge" and "create a wedge" can mean either
mechanism and they are tested by different personas.

**1. A config wedge — `wedge` the persona, `SILENT-WEDGE` the outcome.** A *declaration*
where two directives cannot both be honoured: an entrypoint the payload builder deliberately
excludes, an `app_subdir` containing `..`, `--thin --thick`, a licence that expires before it
is built. Governed by `INV-CHAOS-07`. The persona attacks the declaration rather than a built
binary, and its findings are graded by what the *artifact* carries: `REFUSED` (the build
stopped and named both sides), `WARNED` (it built and said which side lost), or
`SILENT-WEDGE` (it built, said nothing, and shipped the damage). The last is the one the
persona exists for.

**2. A stalled herd — `STALLED` the outcome, `herd` the persona.** Several processes alive
and none of them progressing: a stampede or a convoy on the stage cache, or N processes
waiting on a claim whose owner is dead. Governed by `INV-CHAOS-09`. **This sense was called
`WEDGED` until 2026-09-11** and was renamed precisely because sense 1 already owned the word
in this repo. It is the sense lotek meant when it described the failure mode as "the wedge" —
a whole-system stall, emergent from concurrency, that no single case observes.

**3. "The program is wedged" — the colloquial sense.** Stuck, jammed, not coming back.
Usually sense 2, because that is what a wedged *program* looks like from outside, but not
always: a build that silently shipped a contradictory config has also wedged something, one
stage earlier.

**Which to reach for.** If the complaint is about a binary that will not make progress at
runtime, that is `herd` / `STALLED`. If it is about a declaration that cannot be honoured as
written, that is the `wedge` persona. Both live in `tools/busybody.py`; see
`docs/BUSYBODY.md`. When it is genuinely ambiguous, the runtime sense is the likelier ask —
and a stall can only be *observed*, never injected, so "create a wedge" almost always means
sense 1, which is a file you can write.

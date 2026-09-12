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
URL), `BASE_PATH` (where the stub stages uv/python and the payload tree), and `EPHEMERAL` (the
RAM/disk staging toggle: `0` disk, `1` RAM, unset auto — docs/adr/0005). Adding a knob is a
deliberate format change on both halves (INV-CANARY-02); `EPHEMERAL` is **additive** (its
`[canary]` key is emitted only when non-default, so the v1 corpus is unchanged). The **license
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

## RAM-backed staging (ephemeral) — `--ephemeral`
Staging the payload into memory-backed storage so nothing the payload contains is written to
persistent disk. Baked at build with **`--ephemeral`** (the honest name; `--ram-only` is a
deprecated alias kept for one release). Truly RAM-only ONLY on **Linux**, via `/dev/shm` (a
tmpfs with real paths the interpreter can import from — `memfd` is unusable because it has no
path). **Windows/macOS have no unprivileged RAM disk** (Windows has no tmpfs, and a RAM disk is
a block device needing a signed kernel-mode storage driver + admin; macOS has no tmpfs either),
so there `--ephemeral` is best-effort and falls back to the persistent cache with an honest note
(docs/adr/0004 §4). The **stub-config wire key stays `ram_only`** — the surface renamed, the key
did not (ADR 0004 §2.2 pins the v1 byte-corpus). For packagers concerned about disk-based
artifacts. Distinct from the normal **cache**, which is persistent and reused.

**Phase 3 (docs/adr/0005) makes it safe and controllable.** `--ephemeral` now **implies
`--reap`** (opt out with `--no-reap`) — not permanent means it cleans up. On the auto path the
stub runs a **RAM-fit check** before committing to `/dev/shm`: it stages to RAM only when the
baked `unpacked_bytes × 1.2` fits BOTH the tmpfs free space and `MemAvailable`, else it falls back
to the cache with a note — so a 512 MB CI runner or small VPS never fills RAM and dies mid-extract
(fail-safe: an unknown/unmeasurable size stays on disk). The target gets the final say through the
`EPHEMERAL` **knob**: `<canary>_EPHEMERAL=0` forces disk, `=1` forces RAM and skips the fit-check
(and turns RAM on even for a binary NOT built `--ephemeral` — target autonomy).

## detached reap
The stub's fire-and-forget final act when `--reap` is baked in: after the app exits it spawns
a **separate, detached process** to delete the exact subtree it created this run, then exits
immediately. Cleanup of many gigabytes continues after the stub has died. Independent of
`--ephemeral` (either, both, or neither): `--reap` alone deletes a subtree of the *persistent*
cache; with `--ephemeral` it deletes the RAM-backed one. It only ever removes the
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
packager may list **N distinct resolver endpoints** and require a **consensus** of `K` (default
1) to be reachable and agree the user is allowed, so (at `K`≥2) a *minority* of external
endpoints being down or lying does not decide the gate. **Fail-closed:** if fewer than `K`
endpoints resolve (TLS failure, unparseable body, `success != true`) — or if an allow-list is
present but unreadable — the app does not run. The policy is a list of **allow rules**; a rule
is a set of `field=value` assertions against the resolver JSON (e.g. `country_code=US,
region=California`) — AND within a rule, OR across rules. The old `HARUPACK_GEO` env bypass is
removed and haru-pack reads no env for the location. **Honest caveat:** the check runs on the
user's own machine, so a determined local user can MITM their own resolver traffic
(proxy/CA/DNS) — consensus can't beat one on-path position, and it's an IP check, not a presence
check (a VPN exit passes). Real against casual use and honest faults; **advisory** against a
determined local adversary (INV-GEO-01, ADR 0006).

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
## shred-on-reap (`--overwrite`)
A packager choice, fixed at build with **`--overwrite`** (requires `--reap`), that makes the
detached reaper **shred before it unlinks**: for every staged file it overwrites the whole
logical extent with matching-length random bytes and `fsync`s BEFORE removing the file. Native
Nim on both platforms — a POSIX inline shred in the double-forked reaper, a Windows re-exec of
the launcher as a guarded `--haru-shred <subtree>` worker — with **no shell, no PowerShell**
(often locked on hardened targets) and **no shipped secure-erase binary**. It defeats SIMPLE
logical file-undelete (Recuva/PhotoRec/TestDisk) on a non-CoW filesystem, and NOTHING more: it
is **not a secure erase**. SSD FTL/wear-leveling (LBA ≠ PBA), copy-on-write filesystems,
snapshots/VSS, journals, and swap can all retain the original bytes. The durable defense for
"don't leave my model recoverable" is **`--encrypt` + `--ephemeral`** (decrypt only to RAM —
nothing plaintext ever reaches the block device, so there is nothing to shred). `--overwrite` is
belt-and-suspenders for plaintext that unavoidably touches disk on Windows/macOS
(THREAT_MODEL.md, docs/adr/0004 §5b, INV-SHRED-01).

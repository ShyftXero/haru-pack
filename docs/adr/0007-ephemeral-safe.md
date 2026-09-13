# ADR 0007 — ephemeral is safe on a small machine and controllable at runtime (launcher, Phase 3)

- Status: accepted (contract)
- Date: 2026-09-12
- Scope: makes `--ephemeral` safe to lean on. Three changes, one theme — *ephemeral should not
  hurt you on a machine that can't afford it, and the target gets the final say*:
  1. **`--ephemeral` implies `--reap`** (opt out with `--no-reap`). "Ephemeral" means "not
     permanent", so a RAM/ephemeral stage cleans itself up by default.
  2. **RAM-fit detection.** Before auto-staging to `/dev/shm`, the launcher checks whether the
     payload provably fits free memory; if not, it falls back to the persistent cache with an
     honest note instead of filling RAM and dying mid-extract (the 512 MB CI runner / small VPS
     case).
  3. **Runtime override — a fifth canary knob, `EPHEMERAL`.** The target reads
     `<canary>_EPHEMERAL`: it is 2-state, not 3 — `1` forces RAM (and skips the fit-check),
     unset (or any other value, including `0`) is auto (fit-detection as in §2). There is
     deliberately **no value that forces disk.** `1` works even on a binary not built
     `--ephemeral` (target autonomy).
- Builds ON TOP of ADR 0003 (stub-config section, versioned footer, per-knob canary map) and
  ADR 0004 (the `reap`/`ram_only`/`base_path` staging keys). It adds **no new footer version and
  no new `stub_config_version`** — see §back-compat.
- Vocabulary: `CONTEXT.md` is authoritative for *RAM-backed staging (ephemeral)*, *reap*, *knob*,
  *canary*. This ADR specifies the coupling, the detection, and the override.
- Invariants: `INV-EPHEMERAL-01` (fail-safe RAM-fit + honest fallback), `INV-EPHEMERAL-02`
  (`--ephemeral` implies `--reap`; receipt reports the effective value), `INV-EPHEMERAL-03`
  (the `EPHEMERAL` knob is honored, canary-guarded, and additive). Each is claimed by a test in
  `tests/test_ephemeral_safe.py` whose Red-path was walked.

This is a two-sided contract: the Nim launcher and the Python build must agree without further
coordination, exactly as in ADR 0003 / 0004. Read the whole thing before touching either half.

---

## 1. `--ephemeral` implies `--reap` (§coupling)

`--ephemeral` bakes both `ram_only = true` and `reap = true` into the cleartext stub-config.
`--no-reap` opts out of *only* the implied reap (for a restart-heavy service that wants to reuse
the RAM stage across runs). `--reap` together with `--no-reap` is a contradiction and is refused
at build time. The coupling runs BEFORE the `overwrite requires reap` check (ADR 0004 §5b), so
`--ephemeral --overwrite` is accepted without a separate `--reap`.

The build receipt's `staging.reap` reports the EFFECTIVE value after the coupling, so it never
claims a cleanup the binary will not perform (INV-BUILD-01).

## 2. RAM-fit detection (§detection)

On the auto path (`ram_only` baked, no runtime override), the launcher stages to `/dev/shm` only
when the payload provably fits:

```
need = unpacked_bytes × 1.2
fit  = /dev/shm free bytes ≥ need  AND  /proc/meminfo MemAvailable ≥ need
```

- `unpacked_bytes` is the size of the tree the launcher will actually STAGE, baked into the
  stub-config (emitted only alongside `ram_only`). It is **not** `du` of the payload dir: `uv`
  ships XZ-compressed (`uv.xz`, ~14 MB) and the launcher **expands** it on stage (~56 MB). The
  build therefore sums **expanded** sizes — for every `.xz` member it reads the `.xz.size` sidecar
  `bundle.compress_uv` writes (the raw byte count) instead of the compressed size, and drops the
  `.xz`/`.size`/`.sha256` sidecars from the count (they are removed before the launcher records
  the tree). Summing the *compressed* bytes would under-count by ~40 MB and could hand the gate a
  "fits" verdict for a tree that then OOMs the box it protects (this was adversarial review C1).
  The ×1.2 headroom sits on top of the real staged size, so the gate errs toward the disk
  fallback, not toward RAM.
- **Fail-safe.** An unknown size (`unpacked_bytes` absent / 0), an unmeasurable host (non-Linux,
  unreadable `/proc/meminfo`, `statvfs` failure), or an over-large size whose ×1.2 would overflow
  `int64` all answer "does not fit". The overflow guard is a DIVISION test (`unpackedBytes >
  (int64.high div 6) * 5`) computed BEFORE the multiply, because under `-d:release` forming the
  overflowing sum raises an uncatchable `OverflowDefect` and would crash instead of failing safe
  (adversarial review W2). The launcher never stages to RAM it cannot account for.
- **cgroup-aware.** A container or CI runner caps memory in a cgroup while `/proc/meminfo` still
  reports the HOST's RAM. The gate also reads the cgroup budget — v2 `memory.max` − `memory.current`,
  v1 `memory.limit_in_bytes` − `memory.usage_in_bytes` — and requires `need` to clear it too
  (adversarial review W3). A genuinely ABSENT limit file, or v2's explicit `max`, falls through to
  `MemAvailable` (no cgroup limit in effect). A limit file that EXISTS but does not parse fails
  CLOSED at the cgroup layer itself ("does not fit"), never falls through as if unlimited — the
  same fail-safe posture as `shmFreeBytes`/`memAvailableBytes` (adversarial re-review: the earlier
  version conflated "absent" and "corrupt" into the same not-gated answer).
- On a non-Linux host there is no guaranteed RAM filesystem, so the auto path defers to the
  existing best-effort `ramBackedRoot()` (which itself notes the fallback to disk).

The fit check is small, flat Nim (`stage.shmFreeBytes` / `memAvailableBytes` / `ramWouldFit`), no
deep nesting — one early-returning helper per source of truth.

## 3. Runtime override: the `EPHEMERAL` knob (§override)

The target reads the staging toggle from `<canary.ephemeral>_EPHEMERAL` (default
`HARU_EPHEMERAL`), resolved by the one canary rule (`stubconfig.envForKnob`). It is **2-state**:

| Value | Effect |
|---|---|
| `1` | force the RAM-backed root **and skip the fit-check** (the target asserts it fits) — works even on a binary NOT built `--ephemeral` (target-autonomy enable) |
| unset / anything else (incl. `0`) | auto (fit-detection as in §2) |

There is **deliberately no force-disk value.** An env toggle that pushed an `--encrypt --ephemeral`
payload onto disk would be a confidentiality downgrade an attacker who can set an env var could
trigger, so the knob can only ever *enable* RAM, never *force* disk (user decision, 2026-09-12). A
target that genuinely needs disk simply does not set the knob (auto handles the low-RAM case).

### Precedence (§precedence)

Highest first, computed before staging in `main.resolveStagingRoot`:

```
BASE_PATH env (explicit path)
  > EPHEMERAL env =1 → RAM, skip fit          (no force-disk value)
  > stub-config base_path (build-time default)
  > ram_only ? (auto: RAM if it fits, else the cache) : the per-user cache
```

An explicit `BASE_PATH` names a concrete directory, so it wins over the RAM enable; the `=1` enable
wins over the baked defaults, which is what "target autonomy" means.

## 4. Back-compat — why no version bump (§back-compat)

`EPHEMERAL` is the fifth entry in the closed canary catalogue (INV-CANARY-02), but it is
**additive**:

- Its `[canary]` key is **emitted only when non-default** (its token differs from `HARU`), and the
  launcher **defaults a missing key to `HARU`**. So a build that does not customise the ephemeral
  canary produces the exact four-key stub-config the v1 corpus pins — byte-for-byte.
- `unpacked_bytes` is a new optional top-level key, emitted only alongside `ram_only`, so a
  non-ephemeral binary's stub-config is unchanged. Unknown top-level keys were already reserved
  and ignored (ADR 0003 §2.3).
- The launcher and its stub-config are always emitted by the **same** `haru-pack` build, so a
  version-skew read (old launcher, new stub) never happens on a real artifact — a mismatch is
  corruption, not a compatibility case. That is why neither the footer version nor
  `stub_config_version` moves.

The parser keeps the original four canary keys **mandatory** and treats only `ephemeral` as
optional, so a genuinely truncated three-key stub is still rejected.

## 5. What this does NOT do (residual limits — stated so nothing over-claims)

- It does not promise RAM on Windows/macOS — there is no unprivileged RAM filesystem there, so
  `--ephemeral` stays best-effort (ADR 0004 §4), and the fit check is Linux-only.
- It does not control the packed application's OWN disk writes — only where the STUB stages.
- **Not "never OOM" in the absolute.** The fit check is a **size** gate, not a memory reservation:
  another process can consume RAM between the check and the extract, and a memory budget the
  launcher cannot read (an exotic cgroup layout, a hypervisor balloon) is not gated. It removes the
  PREDICTABLE failure — a tree that never had room in the knowable budget — not every conceivable
  OOM. INV-EPHEMERAL-01 is worded to that bounded claim.
- **`--encrypt` + `--ephemeral` is not an absolute "nothing plaintext reaches disk".** On a
  low-RAM target the RAM stage FALLS BACK to the persistent cache (the fit check above), and the
  decrypted tree then lands on disk. This is an availability fallback, not an attacker-controlled
  one — there is no env value that forces disk (§3). The fallback IS reaped, but a plain unlink is
  recoverable, so `--overwrite` shreds it (still not a secure erase; INV-SHRED-01, THREAT_MODEL.md).
  The build says this out loud when `--encrypt` and `--ephemeral` are combined (W1).

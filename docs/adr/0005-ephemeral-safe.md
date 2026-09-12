# ADR 0005 — ephemeral is safe on a small machine and controllable at runtime (launcher, Phase 3)

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
     `<canary>_EPHEMERAL`: `0` forces disk, `1` forces RAM (and skips the fit-check), unset is
     auto. `1` works even on a binary not built `--ephemeral` (target autonomy).
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

- `unpacked_bytes` is the size of the staged tree, measured by the build from the assembled
  payload directory and baked into the stub-config (emitted only alongside `ram_only`). It is a
  close over-estimate of the tree the launcher extracts; the ×1.2 headroom absorbs the imprecision
  (a `uv` binary is XZ-compressed in the payload and expands on stage) and leaves the app room to
  run. Over-estimating is the safe direction — it biases toward the disk fallback.
- **Fail-safe.** An unknown size (`unpacked_bytes` absent / 0), an unmeasurable host (non-Linux,
  unreadable `/proc/meminfo`, `statvfs` failure), or an arithmetic overflow all answer "does not
  fit". The launcher never stages to RAM it cannot account for.
- On a non-Linux host there is no guaranteed RAM filesystem, so the auto path defers to the
  existing best-effort `ramBackedRoot()` (which itself notes the fallback to disk).

The fit check is small, flat Nim (`stage.shmFreeBytes` / `memAvailableBytes` / `ramWouldFit`), no
deep nesting — one early-returning helper per source of truth.

## 3. Runtime override: the `EPHEMERAL` knob (§override)

The target reads the staging toggle from `<canary.ephemeral>_EPHEMERAL` (default
`HARU_EPHEMERAL`), resolved by the one canary rule (`stubconfig.envForKnob`):

| Value | Effect |
|---|---|
| `0` | force the disk cache (a baked `base_path` if present, else the per-user cache) |
| `1` | force the RAM-backed root **and skip the fit-check** (the target asserts it fits) — works even on a binary NOT built `--ephemeral` |
| unset / other | auto (fit-detection as in §2) |

### Precedence (§precedence)

Highest first, computed before staging in `main.resolveStagingRoot`:

```
BASE_PATH env (explicit path)
  > EPHEMERAL env  (0 → disk / 1 → RAM, skip fit)
  > stub-config base_path (build-time default)
  > ram_only ? (auto: RAM if it fits, else the cache) : the per-user cache
```

An explicit `BASE_PATH` names a concrete directory, so it wins over the RAM/disk toggle; the
`EPHEMERAL` toggle wins over the baked defaults, which is what "target autonomy" means.

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

## 5. What this does NOT do

- It does not promise RAM on Windows/macOS — there is no unprivileged RAM filesystem there, so
  `--ephemeral` stays best-effort (ADR 0004 §4), and the fit check is Linux-only.
- It does not control the packed application's OWN disk writes — only where the STUB stages.
- The fit check is a best-effort **size** gate, not a memory reservation: another process can
  still consume RAM between the check and the extract. It removes the common, predictable failure
  (a payload that never had a chance of fitting), not every possible OOM.

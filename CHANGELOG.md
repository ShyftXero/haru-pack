# Changelog

Stuff worth knowing about, newest first. Dates are when it landed on `main`. The precise
version of any security claim lives in `INVARIANTS.md`; this file is the human-readable trail.

## 2026-09-12

### Added

- **`--ephemeral` is now safe on small machines and controllable at runtime (docs/adr/0005).**
  Three changes, one theme — RAM-backed staging shouldn't hurt you on a box that can't afford it,
  and the target gets the final say:
  - **`--ephemeral` implies `--reap`** (opt out with `--no-reap`). "Ephemeral" means "not
    permanent", so the stage cleans itself up after the app exits by default; `--no-reap` keeps it
    for a restart-heavy service that wants to reuse the RAM tree. The build receipt reports the
    effective `reap` (INV-EPHEMERAL-02).
  - **RAM-fit detection (INV-EPHEMERAL-01).** Before auto-staging to `/dev/shm` the launcher checks
    that the payload (`unpacked_bytes × 1.2`, baked into the stub-config) fits BOTH the tmpfs free
    space and `/proc/meminfo` MemAvailable; if not, it falls back to the persistent cache with an
    honest note instead of filling RAM and dying mid-extract on a 512 MB CI runner or small VPS.
    Fail-safe: an unknown or unmeasurable size stays on disk rather than gambling RAM.
  - **Runtime override via a fifth canary knob, `EPHEMERAL` (INV-EPHEMERAL-03).** The target reads
    `<canary>_EPHEMERAL`: `0` forces disk, `1` forces RAM and skips the fit-check (and turns RAM on
    even for a binary not built `--ephemeral` — target autonomy), unset is auto. The knob is
    additive: its `[canary]` key is emitted only when non-default, so the v1 stub-config corpus is
    byte-identical and neither the footer nor `stub_config_version` moves.

### Security

- **Launcher: symlink bypass of the staging-root refusal — fixed (INV-BASE-01).**
  `--reap` / `--base-path` refuse a staging root that is `/`, a drive/UNC root, or `$HOME`, so
  the on-exit reaper can never be pointed at somewhere catastrophic. Trouble is, that refusal
  was *lexical* — it compared strings. So a `BASE_PATH` that pointed at a forbidden root
  *through a symlink* (`/tmp/x -> $HOME`, say) presented a benign-looking string, sailed past
  every check, and staged — and with `--reap`, reaped — a subtree at the forbidden location.
  The blast radius was bounded (it only ever creates/deletes its own `<key>-<digest>` subtree,
  never `rm -rf $HOME` wholesale), but it defeated the guard's whole point and left a TOCTOU
  window on the detached delete. `refuseUnsafeRoot` now resolves the existing part of the path
  now hardens both platforms with the right primitive: **POSIX** resolves the existing prefix to
  its physical location (`physicalPrefix` → `realpath`) before the root/drive/home checks — a
  benign symlink is allowed, one resolving to `/` or `$HOME` is refused; **Windows** fails
  *closed*, refusing a staging root whose existing prefix passes through **any** reparse point
  (symlink *or* junction), because `getFullPathNameW` (what `expandFilename` uses there) does
  not follow reparse points and untested `GetFinalPathNameByHandleW` FFI has no place inside a
  delete-primitive guard. The reaper also refuses a target that has since become a symlink /
  reparse point — cross-platform. Found by a "what about smuggling in path traversals or
  symlinks?" question during review; proven bypassable on POSIX (`/tmp/link -> $HOME` returned
  ACCEPTED), fixed with a claiming test whose red-path was walked. Compiles on release / haruDev
  / `nim check --os:windows`.

### Added

- **Launcher Phase 2: `--reap` + `--ram-only` + `--base-path`** (INV-REAP-01 / INV-RAM-01 /
  INV-BASE-01, ADR 0004). `--reap` bakes a detached, fire-and-forget cleanup of the staged
  subtree on exit; `--ram-only` best-effort stages under `/dev/shm` on Linux (honest fallback +
  the disclaimer that we can't govern the packed app's own disk writes); `--base-path`
  relocates staging. Two orthogonal flags. The reaper only ever removes the stub-created
  subtree.
- **Launcher Phase 1: stub-config section + per-knob env canary + `--env-append`** (INV-STUB-01
  / INV-CANARY-01/02 / INV-LAUNCH-08/09, ADR 0003). A cleartext, signature-covered config the
  stub reads before it decrypts; per-knob env prefixes (`HARU_SECRET`, …, default `HARU`,
  overridable / randomizable); `--env-append K=V` injected into the child env, plaintext unless
  `--encrypt` with a loud warning otherwise.

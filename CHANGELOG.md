# Changelog

Stuff worth knowing about, newest first. Dates are when it landed on `main`. The precise
version of any security claim lives in `INVARIANTS.md`; this file is the human-readable trail.

## 2026-09-11

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

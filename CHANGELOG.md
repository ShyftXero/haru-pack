# Changelog

Stuff worth knowing about, newest first. Dates are when it landed on `main`. The precise
version of any security claim lives in `INVARIANTS.md`; this file is the human-readable trail.

## 2026-09-13

### Fixes — the build refuses degenerate inputs instead of crashing with a traceback

- A project directory with **no `pyproject.toml` and no `.py` files** (e.g. only compiled
  `.pyc` files, or an empty directory) now refuses cleanly with an actionable message
  (`discovery.EmptyProject`) instead of a bare `ValueError` traceback. Unlike an *ambiguous*
  project, `--entry-point` cannot rescue one with no source, so it refuses outright.
- An **`-o` path whose parent directory does not exist** now has that directory created (or,
  if it cannot be, a clean `BuildError`) instead of dying with a raw `FileNotFoundError` when
  the final binary is written.
- Both were surfaced by busybody's composed `greenhorn` cases (`greenhorn_source_is_a_pyc`,
  `greenhorn_output_into_missing_dir`), which graded them `CRASHED` — the FATAL class — because
  the compose contract is "refuse intelligibly under any stack of hostile conditions". They are
  build-side (upstream of Nim), so they reproduced identically on x86 and aarch64
  (INV-BUILD-01 / INV-BUILD-03).

## 2026-09-12

### Features — `--emit-nim` and `--emit-c`: reproduction kits for the launcher stub

- **`haru-pack build … --emit-nim DIR`** writes a kit alongside the finished binary so you can
  inspect, modify, and manually recompile the launcher stub. The packed binary is still
  produced; `DIR` gets the launcher's Nim source (byte-identical to what haru-pack compiles),
  this build's `payload.bin` and `stubconfig.bin`, a portable `zig-cc` shim, a stdlib-only
  `assemble.py`, and a `compile.sh` that recompiles the stub and reassembles the binary.
- **`haru-pack build … --emit-c DIR`** writes the same kind of kit built instead from the Nim C
  backend's own output for your `--target`: the stub as plain `.c`/`.h` files, `nimbase.h` +
  the xz headers vendored so it needs **no Nim toolchain** — only a `zig` (on `PATH`, or via
  `HARU_ZIG`). `compile.sh` is derived from Nim's own build manifest (per-file flags and all),
  never a hand-written approximation, so nimcrypto's SHA-2 fast paths (`-mssse3`/`-mavx2`)
  survive the translation to zig.
- **The stub is generic; the config is data**, for both kits. Encryption, licence policy,
  reap/ephemeral, remote-fetch and injects are not compiled into the Nim/C — they live in
  `payload.bin` (policy inside it) and `stubconfig.bin`, which the always-present stub
  functions read at runtime. So each kit is source + those two blobs + a reassembler.
  `--emit-nim` and `--emit-c` share the SAME reassembler (`assemble.py` + `kit.json`) — one
  implementation, so the two flags cannot drift on what "reassemble" means.
- **Faithful, and honest about the limit (INV-EMIT-01 / INV-EMIT-02).** A real recompile of the
  emitted stub/C yields a WORKING binary — its overlay verifies and its payload + stub-config
  are this build's exact bytes — proven by actually running the emitted `compile.sh` with
  nim(+zig) in the tests. Byte-for-byte identity of the launcher is **not** claimed (a Nim/C
  recompile is not reproducible in general). The `nim c` flag set is defined once
  (`emit.nim_target_flags`) and shared with the real build, so `--emit-nim`'s recipe cannot
  silently drift; `--emit-c`'s recipe comes from Nim's own build manifest for the same reason.
  Emitting `payload.bin` exposes exactly what the binary already exposes (encrypted stays
  encrypted, and a remote build's kit gets the same `<out>.haru-payload` sidecar the real build
  ships); the build secret is never written to any kit file (INV-SECRET-02).
- **Assumes zig, no build-host paths baked in.** Both kits' `compile.sh` drive
  `${HARU_ZIG:-zig} cc` through a relocatable shim (`toolchain.zig_cc_shim`); `--emit-nim`
  additionally resolves Nim via `${HARU_NIM:-nim}`. No absolute home/username paths, so a kit
  is shareable. An unsafe emit target (symlink, or a non-empty/foreign directory) is refused up
  front (INV-BASE-01 posture), and a kit failure is a warning, never a build failure.

### Tooling — BusyBody run-control hardening (adopted from lotek)

- **Single-instance run control (INV-CHAOS-13).** Two busybody sweeps each stage a real
  interpreter per worker and thrash the box into the OOM killer (seen while running a thick
  top-50 sweep next to another). A sweep now registers itself under a project-tagged
  `/tmp/harupack-busybody/` and **refuses to start (exit 3) while another is genuinely live**
  (pid alive + fresh heartbeat), reaping a dead/wedged run's stale marker rather than trusting
  it. `HARUPACK_BUSYBODY_FORCE=1` overrides. Ported from lotek's BusyBody #738; pids are checked
  with `os.kill(pid, 0)`, so there's no ps-grep self-match trap. **Fix (same day):** the registry
  path was `tempfile.gettempdir()`-derived, so a sweep with its own `$TMPDIR` scratch registered
  somewhere private and the guard couldn't see across sweeps — found live on a top-100 run. Now a
  fixed `/tmp/harupack-busybody` (override `$HARUPACK_BUSYBODY_REGISTRY`).
- **Fail-loud selection (INV-CHAOS-12).** An unknown `--persona`/`--case` name is now a setup
  failure (exit 2) that names the typo — `--persona forger,typo` no longer quietly runs only
  forger and prints a clean verdict. Ported from lotek's BusyBody #558 (an unmatched selection
  is fatal, not dropped). *A run that silently skipped what you asked for reads exactly like a
  healthy one* — the whole reason both guards exist.
- **`--analyze` is a gate now (INV-CHAOS-14).** It used to always exit 0 — a reader, not a
  verdict — so a CI step that trusted it read a false pass on a run full of findings. It now
  exits 2 on a setup failure / environment abort, 1 on findings or an unfinished run, and 0 only
  for a clean completed run. From an audit of `--analyze` against lotek's false-clean hardening
  (#418/#682); the audit also confirmed under docker that the broad `No space left on device`
  infra marker does NOT false-abort the FS-inducing personas (the launcher wraps the OS error),
  so that stayed as-is with a documenting note rather than a needless change.

### Security

- **Launcher: the `HARUPACK_GEO` env bypass is gone (INV-GEO-01).** The old geo "check"
  compared a licence's allowed list against the `HARUPACK_GEO` *environment variable* — so
  anyone outside the region just set `HARUPACK_GEO=US` and ran. That's theatre, and it's
  removed. Location is now decided by an online resolver the user does not control (below),
  and `cryptbox.checkPolicy` reads no env for it at all. A binary built by an older haru-pack
  that still carries the array-form geo policy is *refused*, not silently waved through — a
  dropped location restriction is a breach, not a no-op.

### Added

- **Launcher Phase 4: online execution gates — geo/ip via consensus (INV-GATE-01 /
  INV-GEO-01, ADR 0006).** Every rule-checked gate now has one shape: resolve a current value,
  match an allow-policy, **fail closed**. Geo/ip resolves the caller's IP and location from a
  consensus of online resolvers (default `https://ipwho.is/` — one bare TLS request returns
  both). List N *distinct* endpoints with `--geo-restrict-api-url` and require
  `--geo-restrict-consensus=K` to resolve *and* agree, so (at K≥2) a minority of down or lying
  external resolvers doesn't decide the gate. Rules are `field=value`
  (`--geo-restrict "country_code=US,region=Texas"`, or the `--geo US,CA` shorthand) — AND within
  a rule, OR across them, and because any resolver field works, `ip=1.2.3.4` is an ip gate
  through the same code. It all lives inside the encrypted policy (needs `--encrypt`), hidden
  from a reverse-engineer. **Honest limits:** this is an IP check, not a presence check (a VPN
  exit in an allowed country passes); network-down means the app doesn't run; and because the
  check runs on the user's own machine, a determined local user can MITM their own resolver
  traffic (proxy/CA/DNS) — so it's real against casual use and honest faults, advisory against a
  determined local adversary (the shipped default K=1 trusts a single response). The durable
  control against a hostile host is not shipping to them. See INV-GEO-01 / ADR 0006.
- **Launcher Phase 3: remote-fetch delivery — `--source-url` (INV-REMOTE-01, ADR 0005).** The
  payload can be fetched over HTTP at launch instead of appended to the binary (fetched each
  run — a remote build needs network every launch, not just the first). Same
  pipeline either way — verify → decrypt → licence → stage — so the build-baked footer digest
  is the one thing trusted, no matter where the bytes came from. Tamper with the fetched bytes
  and it fails closed; point the (env-overridable) `SOURCE_URL` at a mirror and it still only
  runs bytes matching the digest. The build writes a `.haru-payload` sidecar to host, and the
  binary carries none of it. An appended build never flips to a network fetch because someone
  set an env var. Proxy-aware through the OS HTTP stack (libcurl `*_proxy` on Linux; system
  proxy on Windows/macOS).
- **`--ephemeral` is now safe on small machines and controllable at runtime (docs/adr/0007).**
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
    `<canary>_EPHEMERAL`. It is 2-state, not 3: `1` forces RAM and skips the fit-check (and turns
    RAM on even for a binary not built `--ephemeral` — target autonomy); unset, or any other value
    including `0`, is auto. There is deliberately no value that forces disk — that would let an
    env var downgrade an `--encrypt --ephemeral` payload onto disk. The knob is additive: its
    `[canary]` key is emitted only when non-default, so the v1 stub-config corpus is byte-identical
    and neither the footer nor `stub_config_version` moves. This RAM-fit check also covers a
    remotely-fetched payload (`--source-url`): the fetched bytes are staged through the same
    `resolveStagingRoot`/fit-check pipeline as an appended payload, so remote-fetch and
    `--ephemeral` compose safely together.

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

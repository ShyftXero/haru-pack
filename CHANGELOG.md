# Changelog

Stuff worth knowing about, newest first. Dates are when it landed on `main`. The precise
version of any security claim lives in `INVARIANTS.md`; this file is the human-readable trail.

## 2026-09-12

### Feature — `--emit-c`: a C reproduction kit for the launcher stub (INV-EMIT-02)

- **`haru build … --emit-c DIR`** writes, beside the binary, a kit for inspecting, modifying,
  or manually compiling the launcher stub: the stub as C (the Nim C backend's output for your
  `--target`), `nimbase.h` + the xz headers vendored so it needs **no Nim toolchain**, a
  relocatable `zig-cc` shim, this build's `payload.bin` + `stubconfig.bin`, and `assemble.py`.
  `sh compile.sh` recompiles every `.c` with **zig** and reassembles the exact binary (payload
  + stub-config + footer), remote-fetch builds included. The kit needs a `zig` on `PATH` (or
  point `HARU_ZIG` at one); no build-host absolute paths are baked in.
- The recipe is Nim's own: `compile.sh` is derived from Nim's build manifest, so it carries the
  per-file flags nimcrypto's SHA-2 fast paths need and drives the same zig compiler haru uses —
  not a hand-written approximation. `assemble.py` reproduces `overlay.attach`'s bytes exactly.
  The stub is generic — every capability (decrypt, license gates, remote-fetch, reap/shred) is
  always-present C; what varies per build is the two data blobs the functions read.
- **`payload.bin` exposes nothing the shipped binary does not** — it is byte-identical to what
  the binary carries. So an unencrypted payload is as readable here as in the binary, and under
  `--embed-secret` the obfuscated key rides inside it exactly as it rides in the binary; the kit
  directory deserves the same care as the artifact (INV-SECRET-02).
- Safe by default: the `--emit-c` directory is refused up front if it is a symlink or a
  non-empty directory (INV-BASE-01 posture), and a kit-emit failure is a warning that never
  reports an already-written binary as failed.
- Honest limit stated in the emitted README: the *overlay* is byte-identical to what haru
  writes, but the recompiled *stub* is not guaranteed byte-identical (a C compile embeds build
  paths); it is a working launcher, and you sign the reassembled binary yourself.

### Tooling — BusyBody run-control hardening (adopted from lotek)

- **Single-instance run control (INV-CHAOS-13).** Two busybody sweeps each stage a real
  interpreter per worker and thrash the box into the OOM killer (seen while running a thick
  top-50 sweep next to another). A sweep now registers itself under a project-tagged
  `/tmp/harupack-busybody/` and **refuses to start (exit 3) while another is genuinely live**
  (pid alive + fresh heartbeat), reaping a dead/wedged run's stale marker rather than trusting
  it. `HARUPACK_BUSYBODY_FORCE=1` overrides. Ported from lotek's BusyBody #738; pids are checked
  with `os.kill(pid, 0)`, so there's no ps-grep self-match trap.
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

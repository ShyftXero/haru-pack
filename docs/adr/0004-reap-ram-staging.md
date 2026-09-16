# ADR 0004 — reap + ephemeral + base-path + overwrite (launcher, Phase 2 / 2b)

- Status: accepted (contract)
- Date: 2026-09-10
- Scope: Phase 2 of the launcher rework, plus Phase 2b (`--overwrite`). Build-time-baked
  staging behaviours carried in the **cleartext stub-config**: `--reap` (detached on-exit
  cleanup), `--ephemeral` (best-effort RAM-backed staging; renamed from the shipped
  `--ram-only`, wire key unchanged — §4), `--base-path` (relocate the staging root, consuming
  the Phase-1 `BASE_PATH` knob), and `--overwrite` (shred-on-reap with an honest anti-recovery
  ceiling — §5b). Builds ON TOP of ADR 0003 (the stub-config section, the versioned footer, and
  the per-knob canary map); it reuses that machinery and adds no new footer version and no new
  `stub_config_version`.
- Vocabulary: `CONTEXT.md` is authoritative for *reap (build-time)*, *detached reap*,
  *RAM-backed staging (ephemeral)*, *knob*. This ADR specifies keys, precedence, and safety.
- Invariants: `INV-BASE-01` (precedence + unsafe-root refusal), `INV-RAM-01` (RAM staging +
  honest fallback), `INV-REAP-01` (detached, own-subtree-only cleanup), `INV-SHRED-01`
  (matching-length overwrite + fsync-before-unlink). Each is claimed by a test in
  `tests/test_reap.py` (INV-REAP-01), `tests/test_ram_only.py` (INV-RAM-01 / INV-BASE-01), or
  `tests/test_shred.py` (INV-SHRED-01) whose Red-path was walked.

This is a two-sided contract. The Nim launcher and the Python build must agree without
further coordination, exactly as in ADR 0003. Read the whole thing before touching either
half.

---

## 1. What Phase 2 adds, in one paragraph

At build time the packager may bake three staging choices into the cleartext stub-config:
reap, ram-only, and a base-path default. At runtime the launcher resolves ONE staging root
by a fixed precedence, refuses an unsafe root, stages the payload under a
`<root>/<key>-<digest>` subtree it OWNS, runs the app, and — if reap was baked — hands that
exact subtree to a detached, fire-and-forget deleter and exits without waiting. None of the
three changes any security decision by its ABSENCE, which is why neither the footer version
nor the stub-config version moves.

---

## 2. Stub-config keys — additions (no version bump)

Three OPTIONAL top-level keys are added to the same `stub_config_version = 1` schema:

```toml
stub_config_version = 1
reap = true                 # optional, default false
overwrite = true            # optional, default false (shred-on-reap; needs reap)
ram_only = true             # optional, default false  (baked by --ephemeral; key name unchanged)
base_path = "/opt/stage"    # optional, default "" (= normal per-user cache)

[canary]
secret     = "HARU"
uv_ver     = "HARU"
source_url = "HARU"
base_path  = "HARU"
```

- `reap` — bool, default `false`. Baked by `--reap`.
- `overwrite` — bool, default `false`. Baked by `--overwrite`; shred-on-reap (§5b). The build
  REFUSES `--overwrite` without `--reap` (the reaper is what runs the shred).
- `ram_only` — bool, default `false`. Baked by `--ephemeral`. **The wire key stays `ram_only`**
  even though the flag was renamed: renaming the key would force a `stub_config_version` bump
  and break the pinned v1 byte-corpus (§2.2) for zero user benefit. Rename the surface, keep
  the wire key.
- `base_path` — string, default `""`. Baked by `--base-path`; `""` means "normal cache".
- These are **top-level** keys, distinct from the `[canary]` table (whose `base_path` entry
  is only an env-name *prefix*, never a path). Do not confuse `base_path` (top-level, the
  staging directory) with `[canary].base_path` (the prefix that names the `BASE_PATH` env).

### 2.1 Why no `stub_config_version` bump (and why that is safe)

ADR 0003 §2.3 says a field whose ABSENCE would change a security decision MUST bump the
version. These three do not:

- **Absence is today's behaviour, and today's behaviour is the safe default.** No `reap` →
  the tree is left in the persistent cache (as always). No `overwrite` → the reaper unlinks
  without shredding (as always). No `ram_only` → staged to the persistent cache. No
  `base_path` → the normal per-user cache from `baseDir()`. None of these absences downgrades
  a protection that was expected to be present; they *are* the protection-neutral default.
- A Phase-1 launcher already **reserves and ignores** unknown top-level keys (ADR 0003
  §2.2). So even a Phase-1 launcher handed a Phase-2 stub-config stages the normal, safe
  way — it does not "silently downgrade" anything, it declines an *opt-in relaxation*
  (RAM/relocation) or an *opt-in cleanup* (reap). Falling back to the persistent per-user
  cache is never less safe than RAM or a relocated root.
- In practice the launcher and the stub-config are emitted by the SAME `haru-pack` build, so
  there is no real runtime version skew; this is a format-discipline argument, and the
  discipline holds.

Contrast with `expected_digest` / an encryption flag, whose absence WOULD drop a check — those
still require a bump when they land.

### 2.2 Corpus preservation

`build.stub_config_bytes` emits `reap`/`overwrite`/`ram_only`/`base_path` **only when
non-default**, so a build that uses none of them produces a byte-identical Phase-1 stub-config. The v1 stub-config
corpus and its exact-bytes test (`test_stub_config_bytes_shape_matches_the_launcher_reader`)
are unchanged. `base_path` is written as a TOML basic string with `\` and `"` escaped, so a
Windows-target path round-trips.

### 2.3 Launcher parse (`stubconfig.parseStubConfig`)

The four keys are parsed when present, type-checked (`reap`/`overwrite`/`ram_only` bool,
`base_path` string), and default to `false`/`false`/`false`/`""` when absent. A wrong type is a
clean `ExitBadStub` (ADR 0003 §4.4), like any other stub-config fault. OTHER unknown top-level
keys stay reserved/ignored.

---

## 3. Staging-root precedence (launcher, computed BEFORE staging)

`main.resolveStagingRoot(sc)` chooses ONE root, in this order:

```
1. BASE_PATH env  (canary-resolved: getEnv(sc.envForKnob(kBasePath)), default HARU_BASE_PATH)
2. stub-config base_path  (the build-time default)
3. ram_only ? ramBackedRoot() : baseDir()   (RAM-backed root, else the normal per-user cache)
```

- **(1)** consumes the Phase-1 `BASE_PATH` knob (ADR 0003 §3.4 left it wired-but-unconsumed).
  The env NAME is resolved through the canary map, so `--stub-env-base-path-canary=MARK` makes
  the launcher read `MARK_BASE_PATH` and nothing else — the exact per-knob rule `INV-CANARY-01`
  defends for `SECRET`.
- **(2)** is the packager's baked default; it loses to a runtime env override.
- **(3)** ram-only only takes effect when neither override is present — an explicit relocation
  always beats it. When ram-only is off, this is `baseDir()`, i.e. exactly today.

`stageZip(payload, key, root)` appends the `<key>-<digest>` subtree; the root default stays
`baseDir()`, so any caller that passes nothing keeps today's behaviour byte-for-byte.

---

## 4. `--ephemeral` — the /dev/shm mechanism and its fallback

`stage.ramBackedRoot()`:

- **Linux:** stage under `/dev/shm/haru-pack` when `/dev/shm` exists and is writable (probed
  by creating and removing a private subdir). `/dev/shm` is a tmpfs with **real paths** the
  staged interpreter can import from. `memfd` is deliberately NOT used: an anonymous memfd has
  no path, so a staged import tree cannot live there — `/dev/shm` is the practical mechanism,
  and the code says so in a comment. If `/dev/shm` is missing or not writable, **fall back** to
  `baseDir()` and print an honest stderr note.
- **Windows / macOS:** no guaranteed RAM filesystem, so `--ephemeral` is **best-effort only and
  not guaranteed** — fall back to the persistent cache with an honest note.

### 4.1 The rename: `--ram-only` → `--ephemeral` (surface only)

The shipped flag was `--ram-only`. That name over-promises: RAM-only staging is a HAPPY ACCIDENT
of Linux's `/dev/shm`, not a portable guarantee. `--ephemeral` is the honest name. `--ram-only`
stays a **hidden, deprecated alias for one release** (both map to the same internal path). The
**stub-config wire key stays `ram_only`** — only the user-facing surface (`--help`, the build
log, this ADR, `CONTEXT.md`) moved; ADR 0004 §2.2 pins the v1 byte-corpus, and renaming the wire
key would force a `stub_config_version` bump for no user benefit. `INV-RAM-01`'s mechanism is
unchanged; only the name moves.

### 4.2 Why there is no unprivileged RAM disk on Windows

A RAM disk is a **block device / volume backed by RAM**, exposed through the storage stack so any
process can open paths on it and the loader can `exec` images from it. Presenting a new volume on
Windows needs a **kernel-mode storage driver** (a `.sys` miniport — ImDisk / OSFMount / etc.),
which requires **`SeLoadDriverPrivilege`** (Administrator only) and a signed driver (Driver
Signature Enforcement). Windows has **no `tmpfs`**. The unprivileged alternatives do not yield an
exec-capable *path*:

- A **pagefile-backed section object** (`CreateFileMapping(INVALID_HANDLE_VALUE, …)`) is
  handle-only, not a path — the same defect as Linux `memfd`, which is exactly why `/dev/shm`
  wins on Linux and there is no `/dev/shm` equivalent here.
- `%TEMP%` is ordinary NTFS on `C:`, not RAM.

So `--ephemeral` is truly RAM-only **only on Linux** and is honestly best-effort elsewhere.
macOS has no `tmpfs` either, so the same fallback applies there.

**HONEST DISCLAIMER (build log + this doc):** `--ephemeral` governs only where the STUB stages
the payload tree. haru-pack cannot control the packed application's OWN disk writes, and it
makes no strong promise about them. On Windows/macOS it does not even promise the stage itself
is RAM-backed. The uv cache and the CPython bytecode cache stay on the persistent cache by
design (they are derived, not payload) — `--ephemeral` is about the staged import tree, nothing more.

---

## 5. `--reap` — the detached spawn (Linux and Windows)

`stage.reapDetached(target, overwrite)`, called from `main.launch` AFTER the child exits (the cleanup
path, ADR-0003-style step 7). The stub returns the child's exit code **without waiting** for
the deletion, so removing many GB continues after the stub has died.

- **Linux (POSIX):** `fork` → `setsid` → `fork` again; the grandchild `execv`s
  `/bin/sh -c 'exec rm -rf -- "$1"' haru-reap <target>` and is reparented to init, so it
  OUTLIVES the stub. The stub waits only for the FIRST child (which `_exit`s immediately after
  forking the deleter), never for the deletion. The target is passed to `sh` as a **positional
  parameter (`$1`)**, never interpolated into the script text, so a staging root containing
  shell metacharacters cannot inject a command into our own reaper. `argv` is built in the
  parent so the forked child does no Nim allocation.
- **Windows (compile + code-review only on this host):** `cmd /c start /b rmdir /s /q <target>`
  via `startProcess(..., options = {poDaemon, poUsePath})`; `start /b` launches `rmdir` without
  a window and `cmd` returns at once, so the stub does not wait. `poDaemon` (DETACHED_PROCESS)
  keeps it off our console. The empty `""` title argument after `start` prevents a quoted path
  from being taken as the window title.

Reap is **independent** of `--ephemeral` (either, both, or neither). The glossary note that a
detached reap is "only for ephemeral staging" describes the *typical* pairing; the build flag
makes them orthogonal, and reap always removes whatever subtree the launcher used this run.
`--overwrite` (§5b) is a modifier ON TOP of reap: it changes HOW the reaper removes the tree.

---

## 5b. `--overwrite` — shred-on-reap, with an honest ceiling (`INV-SHRED-01`)

`--overwrite` (baked as `overwrite = true`; **refused at build without `--reap`**) makes the
detached reaper SHRED each staged file before it unlinks, so a proprietary model blob written to
disk resists **simple** file-recovery tools. `stage.reapDetached(target, overwrite=true)` reuses
the same detach as reap:

- **Linux (POSIX):** same double-fork + `setsid`, but the grandchild redirects its std fds to
  `/dev/null` and runs `stage.shredAndRemoveTree(target)` in **native Nim** (no `sh`, no `rm`)
  before it exits. Running Nim post-`fork` is safe here: the launcher is single-threaded (it
  spawns processes, never threads), so the child holds no locked allocator/GC state.
- **Windows (compile + code-review only on this host):** the launcher **re-execs itself** as a
  hidden `--haru-shred <subtree>` subcommand via `startProcess(self, …, options = {poDaemon})`,
  rather than `cmd /c start /b rmdir`. `rmdir` can only unlink; the re-exec runs the same native
  Nim shred. **No PowerShell, no shipped SDelete, no `cipher /w`** — `cipher /w` wipes *free
  space*, not a named file, is slow, and is SSD-defeated; SDelete is not part of Windows and
  would be an extra shipped binary; PowerShell is frequently locked on hardened targets
  (Constrained Language Mode / AppLocker / ExecutionPolicy) — the very machines where model theft
  is a concern. The "a bare target needs no shell tools" property (`uvfetch`) is preserved.

**Per file** (`stage.overwriteFile`): open R/W **without truncation** → seek 0 → write
`getFileSize(file)` bytes from a **fast reused PRNG buffer** (crypto RNG is needless and slow for
multi-GB — you are occupying LBAs, not resisting cryptanalysis) → **`fsync` / `FlushFileBuffers`**
→ close → unlink. It asserts **bytes-written == file length** as an integrity check that the whole
**logical** extent was covered.

### 5b.1 The honest anti-recovery ceiling — documented, not oversold

Matching-length overwrite defeats **logical file-undelete** (Recuva / PhotoRec / TestDisk) on a
**non-CoW filesystem on a spinning disk**. It is **not anti-forensic** and must never be labelled
"secure erase" / "unrecoverable." Each caveat hits the **overwrite itself**, not just the delete:

1. **SSD FTL / wear-leveling.** In-place overwrite is a fiction: the controller writes to a fresh
   erase block and remaps the LBA; the old block (model plaintext) sits in over-provisioning
   until GC. Matching byte count occupies the **logical** address range, not the **physical**
   cells (LBA ≠ PBA). Recovery from stale cells is chip-off / vendor forensics — **not** "simple
   tools."
2. **Copy-on-write filesystems.** APFS (macOS default), Btrfs, ReFS, ZFS never overwrite a live
   block in place; the "overwrite" allocates new blocks and the original extent survives.
   **Snapshots pin the original regardless**: APFS local snapshots, **Windows VSS**, Time
   Machine, Btrfs snapshots can hand the plaintext back. macOS default APFS ⇒ largely
   ineffective; Windows with VSS on (common) ⇒ a shadow copy may retain it.
3. **May never reach disk / may reach extra places.** `fsync` between overwrite and unlink is
   mandatory or the FS may drop the dirty overwrite. Journals (ext4 `data=journal`, NTFS
   `$LogFile`) may keep fragments. Swap / hibernation may hold the decrypted model — file
   shredding cannot reach it.

### 5b.2 The stronger control (the recommended path)

The durable defense for "don't leave my model recoverable" is to **never write plaintext to the
block device**: ship the model **encrypted** (cryptbox / AES-256-GCM, already present) and use
`--ephemeral` so it decrypts only to `/dev/shm` (Linux, RAM) — then there is **nothing to shred**,
no FTL remnant, no CoW extent, no VSS snapshot. `--overwrite` is belt-and-suspenders for plaintext
that unavoidably touches disk on Windows/macOS. This doctrine is written in `THREAT_MODEL.md`.

---

## 6. Safety — this is a delete primitive (`INV-BASE-01` / `INV-REAP-01` / `INV-SHRED-01`)

Non-negotiable. The reaper removes files; a hostile input must not turn it into
arbitrary-delete.

1. **Own-subtree only.** The reaped path is ALWAYS the exact staged subtree the launcher
   CREATED/verified this run, i.e. `stageZip`'s return value `<root>/<key>-<digest>` — computed
   by the launcher from a hex key and the payload digest, NEVER a raw `base_path` and NEVER a
   raw env value. A hostile `BASE_PATH` can relocate *where* staging happens but the deleted
   path is still one directory the launcher itself just made. `create-and-delete-own-subtree`.
2. **Refused roots.** A staging root that is empty, resolves to `/`, a filesystem/drive/UNC
   root, or the home-directory root is REFUSED. This fires in two places:
   - **Build time** (`build.resolve_base_path`, cross-OS aware so a `--target windows` build on
     Linux still rejects `C:\`): refuses an obviously dangerous `--base-path` fast, before any
     compilation.
   - **Runtime** (`stage.refuseUnsafeRoot`, called from `main.launch` before staging): the
     target's real `/` and `$HOME` are only knowable here, and a `BASE_PATH` env value never
     passed through the build at all — so the launcher re-checks and exits `ExitBadStub` with
     "refusing to stage under an unsafe base path" rather than creating anything.
3. **Dev-stage is never reaped.** `HARUPACK_DEV_STAGE` points at a tree the developer owns and
   the launcher did not create; `reapTarget` is left empty on that path, so `--reap` cannot
   delete it (`INV-LAUNCH-02` territory).
4. **The shred worker is the same own-subtree, re-guarded.** `--overwrite` shreds exactly the
   subtree reap would delete. The POSIX path gets this by construction (the reaper is handed
   `stageZip`'s return value). The Windows `--haru-shred <path>` re-exec is a NEW delete surface
   available to anyone who can run the binary, so it is guarded by `stage.shredGuard`: the target
   must be an existing, **non-symlink** directory whose basename matches the `<hexkey>-<32-hex
   digest>` shape `stageZip` produces, sitting UNDER a root that is not `/`, a drive/UNC root, or
   `$HOME`, and never a `HARUPACK_DEV_STAGE` tree. Anything else is refused (exit 2), never shred.
   The subcommand is compiled `when defined(windows)` only, so a POSIX launcher does not expose it.

---

## 7. Test obligations (Linux end-to-end; Windows compile + review)

Claiming tests in `tests/test_reap.py` (INV-REAP-01), `tests/test_ram_only.py`
(INV-RAM-01 / INV-BASE-01), and `tests/test_shred.py` (INV-SHRED-01), each with its Red-path
walked (neutralize → observe red → restore):

- **`INV-BASE-01`** — precedence and refusal. A stub `base_path` relocates staging; a
  canary-resolved `BASE_PATH` env beats it; an unsafe root (`/`, home) is refused at runtime
  (`ExitBadStub`) and at build (`BuildError`). Red-path: `refuseUnsafeRoot` → `""` (runtime),
  drop the `_is_root_like` raise (build), scramble the precedence order.
- **`INV-RAM-01`** — ram-only stages under `/dev/shm/haru-pack` on Linux when available; an
  explicit base_path still wins. Red-path: `ramBackedRoot` → `return baseDir()` (staging then
  lands in the cache, not `/dev/shm`).
- **`INV-REAP-01`** — after the app exits, the staged subtree is deleted by the detached
  reaper while the base path and a sentinel beside the subtree survive (own-subtree-only), and
  the stub returned promptly. Red-path: remove the `reapDetached(reapTarget)` call (the subtree
  persists).
- **`INV-SHRED-01`** — `overwriteFile` rewrites a file's whole logical extent with random bytes,
  in place, preserving length and `fsync`ing before close; `shredAndRemoveTree` overwrites every
  file before removing the tree; `shredGuard` refuses a non-stage name / root / symlink /
  dev-stage; the build refuses `--overwrite` without `--reap`; and reap+overwrite end-to-end
  removes only its own subtree. Red-path: make `overwriteFile` `return true` before it writes —
  the harness `overwrite` check goes red with CONTENT_UNCHANGED (the file keeps its plaintext).
  Walked 2026-09-11 on this Linux host.

Linux paths are exercised end-to-end (compile the real launcher, attach a real payload +
stub-config, run) plus a compiled Nim harness that runs `overwriteFile`/`shredAndRemoveTree`/
`shredGuard` directly. Windows paths are compile + code-review only on this host: `reapDetached`'s
Windows branch (incl. the `--haru-shred` re-exec and `FlushFileBuffers`), `ramBackedRoot`'s
non-Linux branch, and the `--haru-shred` dispatch in `main` are typechecked with
`nim check --os:windows` and reviewed, not run.

---

## 8. Compact reference

- Stub-config: `stub_config_version = 1` unchanged; optional top-level `reap` (bool),
  `overwrite` (bool), `ram_only` (bool), `base_path` (string), emitted only when non-default;
  absence = today's behaviour, so no version bump and the v1 corpus is byte-identical.
- Precedence: `BASE_PATH` env (canary-resolved) > stub `base_path` > (`ram_only` ? `/dev/shm`
  else cache). Root chosen before staging; `stageZip` appends `<key>-<digest>`.
- `--ephemeral` (renamed from `--ram-only`; wire key still `ram_only`): Linux `/dev/shm/haru-pack`
  (tmpfs, real paths; memfd unusable — no path), else honest fallback to the cache. Windows/macOS
  have no unprivileged RAM disk (no tmpfs; a RAM disk needs a signed kernel driver + admin), so
  best-effort there. Governs only where the STUB stages, never the app's own writes.
- reap: Linux double-fork/setsid → `sh -c 'exec rm -rf -- "$1"' haru-reap <subtree>`; Windows
  `cmd /c start /b rmdir /s /q <subtree>`; fire-and-forget, the stub does not wait.
- `--overwrite` (shred-on-reap; needs reap): the reaper overwrites each file's full logical
  extent with matching-length random bytes + `fsync` BEFORE unlink — native Nim (POSIX inline
  shred / Windows `--haru-shred` re-exec, no PowerShell/SDelete). Defeats SIMPLE undelete on a
  non-CoW disk ONLY; NOT a secure erase (SSD FTL, CoW FS, snapshots/VSS, swap). Durable defense:
  `--encrypt` + `--ephemeral`.
- Safety: reap/shred the create-and-delete-own `<root>/<key>-<digest>` subtree ONLY; refuse a
  root/drive/UNC/home staging root at build and again at runtime; the `--haru-shred` worker is
  guarded to a stage-shaped non-symlink subtree; never reap or shred a dev-stage tree.

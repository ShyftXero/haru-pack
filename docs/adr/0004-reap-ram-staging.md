# ADR 0004 — reap + ram-only + base-path (launcher, Phase 2)

- Status: accepted (contract)
- Date: 2026-09-10
- Scope: Phase 2 of the launcher rework. Three orthogonal, build-time-baked staging
  behaviours carried in the **cleartext stub-config**: `--reap` (detached on-exit
  cleanup), `--ram-only` (best-effort RAM-backed staging), and `--base-path` (relocate the
  staging root, consuming the Phase-1 `BASE_PATH` knob). Builds ON TOP of ADR 0003 (the
  stub-config section, the versioned footer, and the per-knob canary map); it reuses that
  machinery and adds no new footer version and no new `stub_config_version`.
- Vocabulary: `CONTEXT.md` is authoritative for *reap (build-time)*, *detached reap*,
  *RAM-backed staging (ephemeral)*, *knob*. This ADR specifies keys, precedence, and safety.
- Invariants: `INV-BASE-01` (precedence + unsafe-root refusal), `INV-RAM-01` (RAM staging +
  honest fallback), `INV-REAP-01` (detached, own-subtree-only cleanup). Each is claimed by a
  test in `tests/test_reap.py` (INV-REAP-01) or `tests/test_ram_only.py` (INV-RAM-01 /
  INV-BASE-01) whose Red-path was walked.

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
ram_only = true             # optional, default false
base_path = "/opt/stage"    # optional, default "" (= normal per-user cache)

[canary]
secret     = "HARU"
uv_ver     = "HARU"
source_url = "HARU"
base_path  = "HARU"
```

- `reap` — bool, default `false`. Baked by `--reap`.
- `ram_only` — bool, default `false`. Baked by `--ram-only`.
- `base_path` — string, default `""`. Baked by `--base-path`; `""` means "normal cache".
- These are **top-level** keys, distinct from the `[canary]` table (whose `base_path` entry
  is only an env-name *prefix*, never a path). Do not confuse `base_path` (top-level, the
  staging directory) with `[canary].base_path` (the prefix that names the `BASE_PATH` env).

### 2.1 Why no `stub_config_version` bump (and why that is safe)

ADR 0003 §2.3 says a field whose ABSENCE would change a security decision MUST bump the
version. These three do not:

- **Absence is today's behaviour, and today's behaviour is the safe default.** No `reap` →
  the tree is left in the persistent cache (as always). No `ram_only` → staged to the
  persistent cache. No `base_path` → the normal per-user cache from `baseDir()`. None of
  these absences downgrades a protection that was expected to be present; they *are* the
  protection-neutral default.
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

`build.stub_config_bytes` emits `reap`/`ram_only`/`base_path` **only when non-default**, so a
build that uses none of them produces a byte-identical Phase-1 stub-config. The v1 stub-config
corpus and its exact-bytes test (`test_stub_config_bytes_shape_matches_the_launcher_reader`)
are unchanged. `base_path` is written as a TOML basic string with `\` and `"` escaped, so a
Windows-target path round-trips.

### 2.3 Launcher parse (`stubconfig.parseStubConfig`)

The three keys are parsed when present, type-checked (bool/bool/string), and default to
`false`/`false`/`""` when absent. A wrong type is a clean `ExitBadStub` (ADR 0003 §4.4), like
any other stub-config fault. OTHER unknown top-level keys stay reserved/ignored.

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

## 4. `--ram-only` — the /dev/shm mechanism and its fallback

`stage.ramBackedRoot()`:

- **Linux:** stage under `/dev/shm/haru-pack` when `/dev/shm` exists and is writable (probed
  by creating and removing a private subdir). `/dev/shm` is a tmpfs with **real paths** the
  staged interpreter can import from. `memfd` is deliberately NOT used: an anonymous memfd has
  no path, so a staged import tree cannot live there — `/dev/shm` is the practical mechanism,
  and the code says so in a comment. If `/dev/shm` is missing or not writable, **fall back** to
  `baseDir()` and print an honest stderr note.
- **Windows / macOS:** no guaranteed RAM filesystem, so ram-only is **best-effort only and not
  guaranteed** — fall back to the persistent cache with an honest note.

**HONEST DISCLAIMER (build log + this doc):** `--ram-only` governs only where the STUB stages
the payload tree. haru-pack cannot control the packed application's OWN disk writes, and it
makes no strong promise about them. On Windows/macOS it does not even promise the stage itself
is RAM-backed. The uv cache and the CPython bytecode cache stay on the persistent cache by
design (they are derived, not payload) — ram-only is about the staged import tree, nothing more.

---

## 5. `--reap` — the detached spawn (Linux and Windows)

`stage.reapDetached(target)`, called from `main.launch` AFTER the child exits (the cleanup
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

Reap is **independent** of ram-only (either, both, or neither). The glossary note that a
detached reap is "only for ephemeral staging" describes the *typical* pairing; the build flag
makes them orthogonal, and reap always removes whatever subtree the launcher used this run.

---

## 6. Safety — this is a delete primitive (`INV-BASE-01` / `INV-REAP-01`)

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

---

## 7. Test obligations (Linux end-to-end; Windows compile + review)

Claiming tests in `tests/test_reap.py` (INV-REAP-01) and `tests/test_ram_only.py`
(INV-RAM-01 / INV-BASE-01), each with its Red-path walked
(neutralize → observe red → restore):

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

Linux paths are exercised end-to-end (compile the real launcher, attach a real payload +
stub-config, run). Windows paths are compile + code-review only on this host: `reapDetached`'s
Windows branch and `ramBackedRoot`'s non-Linux branch are typechecked with
`nim check --os:windows` and reviewed, not run.

---

## 8. Compact reference

- Stub-config: `stub_config_version = 1` unchanged; optional top-level `reap` (bool),
  `ram_only` (bool), `base_path` (string), emitted only when non-default; absence = today's
  behaviour, so no version bump and the v1 corpus is byte-identical.
- Precedence: `BASE_PATH` env (canary-resolved) > stub `base_path` > (`ram_only` ? `/dev/shm`
  else cache). Root chosen before staging; `stageZip` appends `<key>-<digest>`.
- ram-only: Linux `/dev/shm/haru-pack` (tmpfs, real paths; memfd unusable — no path), else
  honest fallback to the cache. Windows/macOS best-effort, not guaranteed. Governs only where
  the STUB stages, never the app's own writes.
- reap: Linux double-fork/setsid → `sh -c 'exec rm -rf -- "$1"' haru-reap <subtree>`; Windows
  `cmd /c start /b rmdir /s /q <subtree>`; fire-and-forget, the stub does not wait.
- Safety: reap the create-and-delete-own `<root>/<key>-<digest>` subtree ONLY; refuse a
  root/drive/UNC/home staging root at build and again at runtime; never reap a dev-stage tree.

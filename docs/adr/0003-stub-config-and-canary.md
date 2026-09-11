# ADR 0003 — Stub-config section + per-knob canary (launcher rework, Phase 1)

- Status: accepted (contract; not yet implemented)
- Date: 2026-09-10
- Scope: Phase 1 ONLY — the cleartext stub-config section, the versioned footer that
  carries it, the per-knob canary map, and the payload-side `inject` (env-append). Later
  phases (`source_url`, `expected_digest`, `ram_only`, `reap`, `base_path` behaviour;
  remote-fetch; execution gates) are out of scope and are only *made room for* here.
- Vocabulary: `CONTEXT.md` (glossary) is authoritative for the terms *canary*, *knob*,
  *inject*, *stub*. This ADR does not redefine them; it specifies bytes and names.

This is a two-sided contract. The Nim launcher and the Python build are separate halves
that must agree without further coordination. Where a rule says "MUST", a one-sided change
breaks every affected build with an error that reads like something else (see the
`INV-CRYPTO-04` note in `INVARIANTS.md`). Read the whole thing before touching either half.

---

## 1. Overlay footer — versioned extension

The footer is the fixed-size record at the tail of the file body, located by a **backward
scan for the 8-byte MAGIC** so an Authenticode cert table appended after signing never
hides it. That property is `INV-LAUNCH-01`/`INV-LAUNCH-05` territory and does not change.

### 1.1 Constants (both halves)

```
MAGIC = b"HARUPACK"   # 8B start sentinel  (overlay.py MAGIC / overlay.nim FooterMagic)
TAIL  = b"KCAPURAH"   # 8B end sentinel    (overlay.py TAIL  / overlay.nim FooterTail)
FOOTER_V1_SIZE = 68
FOOTER_V2_SIZE = 116
```

### 1.2 Footer v1 (`format_ver = 1`) — 68 bytes, UNCHANGED

| off | size | field | type |
|----:|-----:|-------|------|
| 0   | 8    | MAGIC `HARUPACK`   | bytes |
| 8   | 2    | `format_ver` = 1   | u16 LE |
| 10  | 2    | `flags`            | u16 LE |
| 12  | 8    | `payload_off`      | u64 LE |
| 20  | 8    | `payload_len`      | u64 LE |
| 28  | 32   | `payload_sha256`   | bytes |
| 60  | 8    | TAIL `KCAPURAH`    | bytes |

Writer: `MAGIC + struct.pack("<HHQQ", 1, flags, off, len) + sha32 + TAIL`. Byte-identical
to today. Today's single-payload binaries and the whole v1 test corpus keep loading.

### 1.3 Footer v2 (`format_ver = 2`) — 116 bytes

| off | size | field | type |
|----:|-----:|-------|------|
| 0   | 8    | MAGIC              | bytes |
| 8   | 2    | `format_ver` = 2   | u16 LE |
| 10  | 2    | `flags`            | u16 LE |
| 12  | 8    | `payload_off`      | u64 LE |
| 20  | 8    | `payload_len`      | u64 LE |
| 28  | 32   | `payload_sha256`   | bytes |
| 60  | 8    | `stub_off`         | u64 LE |
| 68  | 8    | `stub_len`         | u64 LE |
| 76  | 32   | `stub_sha256`      | bytes |
| 108 | 8    | TAIL               | bytes |

Writer: `MAGIC + struct.pack("<HHQQ", 2, flags, payload_off, payload_len) + payload_sha32
+ struct.pack("<QQ", stub_off, stub_len) + stub_sha32 + TAIL`.

The shared prefix `[0:60]` (MAGIC..payload_sha256) is byte-identical to v1. TAIL is always
the final 8 bytes. The only difference is the three fields inserted between
`payload_sha256` and TAIL.

### 1.4 File layout (v2)

```
[ launcher PE/ELF ] [ payload ] [ stub-config ] [ footer(116) ]   (++ [cert table after signing])
```

- `payload_off = len(launcher)` — payload stays contiguous with the launcher, as in v1.
- `payload_len = len(payload-as-attached)` — the CIPHERTEXT container on an encrypted
  build (`INV-LAUNCH-01`: the digest covers the attached bytes, checked before decrypt).
- `stub_off = payload_off + payload_len` (canonical: stub-config immediately after payload).
- `stub_len = len(stub_config_bytes)`.
- footer begins at `stub_off + stub_len`.

The stub-config sits in the file body BEFORE the appended cert table, so it is covered by
the Authenticode signature (cleartext, signature-covered, as required). It is located ONLY
by the footer's `stub_off`/`stub_len` — no second scan sentinel — so there is one locating
mechanism, validated by size (§1.6), never discovered by allocating.

### 1.5 Locating the footer (both readers) — version dispatch

1. Find the last MAGIC: `data.rfind(MAGIC)` (Python) / backward scan from EOF (Nim). The
   real footer's MAGIC is the highest-indexed one; a MAGIC that happens to occur inside the
   payload or stub-config has a lower index and is not reached first.
2. Read `format_ver = u16 LE at MAGIC_index + 8`.
3. `footer_size = {1: 68, 2: 116}[format_ver]`. An unknown version is NOT a footer at this
   index — Python: raise "unsupported footer version"; Nim: treat as a false positive and
   keep scanning, then fail closed if none validates.
4. Require `MAGIC_index + footer_size` in-bounds AND `TAIL` present at
   `MAGIC_index + footer_size - 8`. Only then is it a footer.
5. Parse the version's fields.

Backward compatibility falls straight out: `format_ver == 1` → 68-byte parse, no
stub-config; `format_ver == 2` → 116-byte parse with stub locator. `overlay.attach()` gains
an optional `stub_config: bytes | None = None`; `None` emits a v1 footer (existing call
sites and v1 tests unaffected), bytes emit a v2 footer. Phase-1 `build()` always passes a
real stub-config, so every NEW binary is v2.

### 1.6 `footerFault` additions (Nim, `INV-LAUNCH-05` discipline)

All existing payload-extent checks are unchanged. When `format_ver == 2`, additionally
(comparing each term to `fileSize` BEFORE any addition, so a u64 sum cannot wrap):

- `stub_len == 0` → "footer declares a zero-length stub-config"
- `stub_off > fs` → "stub-config offset lies past the end of the file"
- `stub_len > fs` → "stub-config length exceeds the size of the file"
- `stub_off + stub_len > fs` → "stub-config extends past the end of the file"
- `payload_off + payload_len > stub_off` → "payload overlaps the stub-config"
- `stub_off + stub_len > uint64(footerAt)` → "stub-config overlaps its own footer"

`stub_off`/`stub_len` are attacker-controlled u64s read off disk, exactly like
`payload_off`/`payload_len`; they get the same up-front validation (never cast to `int` and
handed to `setPosition`/`readStr` unchecked).

### 1.7 Stub-config integrity (Nim, `INV-LAUNCH-01` analog)

After `footerFault` passes and BEFORE parsing the stub-config, the launcher reads the
`stub_len` bytes at `stub_off` and verifies `sha256(bytes) == stub_sha256`, mirroring
`verifyPayloadDigest`. Mismatch → clean one-line diagnostic + `ExitBadStub` (§4.4), never a
traceback (`INV-LAUNCH-06`). Like `payload_sha256`, this digest is self-referential (both
the bytes and the digest come from the same attacker-writable region): it detects
corruption/truncation/naive edits and is the precondition for a real signature
(`INV-LAUNCH-03`, still `proposed`) — it is NOT tamper-evidence and MUST NOT be described as
such.

`overlay.verify()` (Python, used by `haru-pack verify` and tests) parses both versions and,
for v2, additionally checks `sha256(stub bytes) == stub_sha256`, returning `stub_ok`,
`stub_off`, `stub_len`, and the decoded stub-config text alongside the existing fields.

---

## 2. Stub-config section — schema

Format: **TOML, UTF-8**. TOML because the launcher already links `parsetoml` (see
`manifest.nim`), so parsing the stub before decryption adds no dependency, and because an
unencrypted stub-config is meant to be human-auditable — the canary map is deliberately
readable (a canary raises guessing cost; it is not secrecy).

### 2.1 Phase-1 schema (`stub_config_version = 1`)

```toml
stub_config_version = 1

[canary]
secret     = "HARU"
uv_ver     = "HARU"
source_url = "HARU"
base_path  = "HARU"
```

### 2.2 Rules (launcher parse; build write)

- `stub_config_version` — integer, REQUIRED. The launcher supports exactly `{1}` in
  Phase 1; any other value → clean diagnostic + `ExitBadStub`. Later phases bump this.
- `[canary]` — table, REQUIRED. Exactly the four keys `secret`, `uv_ver`, `source_url`,
  `base_path` — the closed knob catalogue. A missing key OR an unknown key inside `[canary]`
  is an error (the catalogue is closed; a mismatch is a build/launcher version bug, not a
  thing to tolerate).
- Each canary value — non-empty string matching `^[A-Za-z_][A-Za-z0-9_]*$` (a valid env-name
  prefix). Enforced at BUILD time (§3) and re-validated at parse time.
- Unknown TOP-LEVEL keys (outside `[canary]`) at a supported version are RESERVED and
  IGNORED by the launcher. This is the forward-extensibility seam (§2.3).

### 2.3 Extensibility contract (how later phases add fields without a format break)

- Later phases carry `source_url`, `expected_digest`, `ram_only`, `reap`, `base_path`
  **values/policy** as NEW top-level keys/tables in the stub-config (these are distinct from
  the `[canary]` map, which only ever names env prefixes). A Phase-1 launcher ignores them.
- A new field whose ABSENCE would change a security decision (e.g. `expected_digest`,
  `ram_only`) MUST come with a `stub_config_version` bump, so an older launcher refuses the
  binary outright rather than silently downgrading a protection. In practice the launcher and
  the stub-config are emitted by the SAME `haru-pack` build, so version skew is a format-
  discipline concern, not a runtime one — the launcher still fails closed on an unknown
  version.
- A behaviour-preserving/optional field may be added at the same version and left to the
  ignore rule.

### 2.4 What is NOT in the stub-config (hard constraints)

- `HARUPACK_DEV_STAGE` is NOT a knob, is never written to the stub-config, and stays a
  `when defined(haruDev)` build-only path (`INV-LAUNCH-02`). It must not appear in a release
  stub in any form.
- The license policy (`expires`, `geo`, `ip`, `machine`, `user`) is NOT a knob and is never
  in the stub-config. It stays inside the encrypted policy, post-decrypt, non-overridable by
  env (`INV-CRYPTO-04` / execution gate). The stub-config is cleartext; putting policy there
  would publish it.

---

## 3. Canary — runtime resolution

### 3.1 The single mechanism (Nim, new module `stubconfig.nim`)

```nim
type Knob* = enum kSecret, kUvVer, kSourceUrl, kBasePath
proc knobToken*(k: Knob): string       # kSecret->"SECRET" kUvVer->"UV_VER"
                                        # kSourceUrl->"SOURCE_URL" kBasePath->"BASE_PATH"
type StubConfig* = object
  version*: int
  canary*: array[Knob, string]
proc defaultStubConfig*(): StubConfig   # every knob -> "HARU"
proc parseStubConfig*(raw: string): StubConfig   # §2.2 validation; raises on bad input
proc envForKnob*(sc: StubConfig, k: Knob): string = sc.canary[k] & "_" & knobToken(k)
```

`main.launch` builds `sc = (if v2 stub present: parseStubConfig(stubBytes) else:
defaultStubConfig())`. One resolution rule everywhere: knob `K` is read at runtime from the
env var `envForKnob(sc, K)`. The all-`HARU` default means the legacy env name
`HARUPACK_SECRET` is retired (§3.3).

### 3.2 The env each knob reads

| knob | `[canary]` key | env var read | default env | Phase 1 |
|------|----------------|--------------|-------------|---------|
| SECRET     | `secret`     | `<secret>_SECRET`         | `HARU_SECRET`     | **consumed** — decryption key |
| UV_VER     | `uv_ver`     | `<uv_ver>_UV_VER`         | `HARU_UV_VER`     | wired, TODO consumer |
| SOURCE_URL | `source_url` | `<source_url>_SOURCE_URL` | `HARU_SOURCE_URL` | wired, TODO consumer |
| BASE_PATH  | `base_path`  | `<base_path>_BASE_PATH`   | `HARU_BASE_PATH`  | wired, TODO consumer |

Worked example, `--stub-env-uv-ver-canary=MARK` (rest default): `uv_ver` reads `MARK_UV_VER`;
`secret`/`source_url`/`base_path` read `HARU_SECRET`/`HARU_SOURCE_URL`/`HARU_BASE_PATH`.
`HARU_UV_VER` and `MARK_SECRET` are BOTH invalid — nothing reads them.

### 3.3 SECRET consumer (Phase 1) — replaces `HARUPACK_SECRET`

`cryptbox.nim` MUST change signature (both the proc and every caller/harness together —
`INV-CRYPTO-04` note: no one-sided edits):

```nim
proc resolveSecret(box: Box, secretEnv: string): string =
  ## env <secretEnv> -> embedded (weak) -> interactive no-echo prompt
  result = getEnv(secretEnv)          # was: getEnv("HARUPACK_SECRET")
  ...                                  # embed + readPasswordFromStdin fallbacks UNCHANGED
proc openContainer*(raw: string, secretEnv: string): string =
  ...
  let secret = resolveSecret(box, secretEnv)
  if secret.len == 0:
    quit("haru-pack: this build is encrypted — set " & secretEnv &
         " (or run interactively)", 4)
```

`main.launch`: `payload = openContainer(payload, sc.envForKnob(kSecret))`. The no-echo prompt
(`INV-SECRET-01`) and the embedded-secret path are untouched. The container byte format is
UNCHANGED — only the SOURCE of the secret's env NAME changes; the Python↔Nim interop tests
must still pass.

Migrations required in the SAME change (else red or misleading):
- `tests/test_crypto_hardening.py`, `tests/test_launcher_integrity.py`: their harness calls
  `openContainer(raw)` with one arg and sets `HARUPACK_SECRET` — update to pass the env name
  and set `HARU_SECRET` (or the build's chosen canary).
- `README.md`, `docs/ENCRYPTION_LICENSING.md`: replace `HARUPACK_SECRET` with the canary
  form (default `HARU_SECRET`).

### 3.4 The three not-yet-consumed knobs — wire, don't consume

`envForKnob` is provided and unit-tested for all four knobs. Their VALUES are not read in
Phase 1. Leave an explicit TODO at each future consumer so the seam is legible:

- `UV_VER`  → `findUv`/`uvfetch.nim`: `# TODO(phase-uv): override m.uvVersion with getEnv(sc.envForKnob(kUvVer)) when set`.
- `SOURCE_URL` → the future remote-fetch delivery path: `# TODO(phase-remote): payload URL = getEnv(sc.envForKnob(kSourceUrl))`.
- `BASE_PATH` → `stage.baseDir()`/`stageZip`: `# TODO(phase-base): stage root override = getEnv(sc.envForKnob(kBasePath))`.

Do NOT `getEnv` them in Phase 1 (dead reads); the mechanism, not the consumption, is what
Phase 1 delivers.

---

## 4. Manifest addition — `inject` (env-append)

Injects live in the PAYLOAD manifest (post-decrypt), so an encrypted build hides them. They
are NOT in the cleartext stub-config. The term is **inject**, never "project".

### 4.1 `manifest.toml` field

```toml
inject = ["LICENSE_TIER=pro", "MYAPP_API_BASE=https://api.example.com"]
```

An array of `"KEY=VALUE"` strings — the exact `--env-append` spelling, order-preserving,
repeat-preserving, and free of TOML key-escaping problems for odd env keys.

### 4.2 Launcher (Nim)

- `manifest.nim`: add `inject*: seq[(string, string)]` to `Manifest`; parse
  `strSeq(t, "inject")` and split each entry on the FIRST `'='`. An entry with no `'='` →
  clean error (`INV-LAUNCH-06`). Absent/empty → no injects.
- `main.launch`: apply as the FIRST statements of the env-wiring section (step 3), i.e.
  BEFORE `putEnv("HARUPACK_EXE_DIR", ...)` and every reserved `putEnv` the launcher makes:

  ```nim
  for (k, v) in m.inject: putEnv(k, v)   # both uv and the app see these
  ```

  Placing injects first means uv AND the app inherit them, while the launcher's own reserved
  vars (the `HARUPACK_*`, the managed `UV_*`, `PYTHONPYCACHEPREFIX`, `PYTHONPATH`) are set
  afterward and WIN on any collision — an inject cannot repoint `UV_PYTHON` off the host and
  defeat the thick tier's hermeticity (`INV-LAUNCH-04`). The build refuses reserved keys
  outright (§4.3) so this is belt-and-braces, not the only guard.

### 4.3 Build (Python, `assemble_payload`) — write + refuse + warn

- Write `manifest["inject"] = [ "K=V", ... ]` from `--env-append`.
- REFUSE (non-zero exit, `BuildError`) when a `--env-append` value:
  - has no `'='`, or an empty KEY; or
  - has a reserved KEY: starts with `HARUPACK_`, or is one of the launcher-managed vars
    `UV_CACHE_DIR`, `UV_PYTHON`, `UV_PYTHON_INSTALL_DIR`, `UV_PYTHON_DOWNLOADS`, `UV_OFFLINE`,
    `UV_PROJECT_ENVIRONMENT`, `PYTHONPYCACHEPREFIX`, `PYTHONPATH`. A silently-ineffective
    inject is the class `INV-BUILD-01`/`INV-BUILD-02` exist to forbid.
- WARN loudly (via the `log` callback, `"WARNING: ..."`) — only on an UNENCRYPTED build —
  when an inject looks secret-shaped, the same honesty as `--embed-secret` (`INV-SECRET-02`).
  "Secret-shaped" is deterministic:
  - KEY.upper() contains any of `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`, `APIKEY`, `API_KEY`,
    `PRIVATE_KEY`, `ACCESS_KEY`, OR KEY.upper() ends with `_KEY`; OR
  - VALUE matches `^[A-Za-z0-9+/=_-]{20,}$` (length ≥ 20, no whitespace — base64/hex/token
    shaped).
  The warning names the KEY, states the value ships recoverable in plaintext in the binary,
  and points at `--encrypt`. An ENCRYPTED build emits no such warning (the payload hides it).

### 4.4 Launcher exit codes (unchanged plus one)

`3/4/5` cryptbox (expired / no secret / wrong-secret-or-tampered), `6` digest mismatch,
`7` internal error, `8` bad footer, `9` no uv — all unchanged. New:

```nim
ExitBadStub* = 10   ## stub-config: digest mismatch, unparseable TOML, unsupported
                    ## stub_config_version, or an invalid/missing canary. One-line
                    ## diagnostic, never a traceback (INV-LAUNCH-06).
```

---

## 5. CLI flags (exact spellings)

Options on `build` (and threaded `build` → `_run_build` → `build_exe` → `_resolve`/
`assemble_payload`, the same as every other build flag):

| purpose | flag | typer type | effect |
|---------|------|-----------|--------|
| default canary, all knobs | `--env-canary` | `str = ""` | sets the default token for ALL knobs |
| random default, all knobs | `--env-canary-random` | `bool = False` | pick one random `[A-Z][A-Z0-9]{7}` default for ALL knobs and PRINT it |
| override SECRET only    | `--stub-env-secret-canary`     | `str = ""` | overrides the `secret` knob's canary only |
| override UV_VER only    | `--stub-env-uv-ver-canary`     | `str = ""` | overrides the `uv_ver` knob's canary only |
| override SOURCE_URL only| `--stub-env-source-url-canary` | `str = ""` | overrides the `source_url` knob's canary only |
| override BASE_PATH only | `--stub-env-base-path-canary`  | `str = ""` | overrides the `base_path` knob's canary only |
| inject (env-append)     | `--env-append` | `List[str] = None` (repeatable) | one `KEY=VALUE` per occurrence → manifest `inject` |

### 5.1 Per-knob resolution precedence

For each knob independently:

```
--stub-env-<knob>-canary   >   --env-canary / --env-canary-random   >   built-in "HARU"
```

### 5.2 Build-time refusals (non-zero exit)

- `--env-canary` AND `--env-canary-random` given together → refuse (two conflicting
  all-knobs defaults; pick one).
- Any resolved canary token (default or per-knob) not matching `^[A-Za-z_][A-Za-z0-9_]*$`
  → refuse (it would form an invalid env-name prefix).
- `--env-append` failures per §4.3.

### 5.3 Build receipt / print

- `--env-canary-random`: print each knob's final canary in the build log clearly enough that
  the packager can record it ("record this — you set it at runtime as `<TOKEN>_SECRET`").
- `build()`'s returned `info` dict gains `canary` = the resolved `{secret, uv_ver,
  source_url, base_path}` token map. The canary is NOT secret (`INV-SECRET-02` covers the
  secret value only), so recording it in the receipt is correct and aids auditing. The
  secret value itself still appears in NO produced artifact.

---

## 6. Hard constraints — how this ADR satisfies them

- `HARUPACK_DEV_STAGE`: not a knob, never in the stub-config, stays `when defined(haruDev)`
  (`INV-LAUNCH-02`, §2.4).
- License policy: not a knob, never env-overridable, stays inside the encrypted policy
  (§2.4).
- Few code paths: one `CanaryMap` + one `envForKnob` for all four knobs; one
  `overlay.attach()` that emits v1 or v2 by the presence of `stub_config`; one version-
  dispatching reader on each side; injects are one `putEnv` loop. The launcher stays the
  invisible delivery vehicle — no per-knob branches, no per-delivery-mode secret path.
- Guards + tests: every new guard below ships with a claiming test whose Red-path was walked
  (neutralize → observe red → restore); dated doc claims cite an invariant id.

---

## 7. Test obligations (walk each Red-path before marking active)

Add these invariants to `INVARIANTS.md` (assign the next number in each series; shown here
with an `NN` placeholder deliberately, so this ADR does not itself cite an undeclared id):

1. **Footer versioning** — `INV-LAUNCH-NN`. Statement: the reader loads both v1 (68B) and
   v2 (116B) footers and validates the stub extent by size. Red-path: make `findFooter`/
   `verify` ignore `format_ver` (always parse 68B) and rebuild — a v2 binary misreads the
   stub extent / the TAIL check lands in the wrong place and the exe fails to load; a v1
   binary still loads. Also neutralize the new §1.6 stub checks (return `""`), set `stub_off`
   to `2**63` in a built exe, run → observe the `RangeDefect`/OOM the guard prevents. Extends
   `INV-LAUNCH-05` territory.
2. **Stub-config digest** — `INV-STUB-NN`. Statement: the launcher refuses to parse a
   stub-config whose sha256 does not match `stub_sha256`. Red-path: replace `verifyStubDigest`
   with `discard`, flip one stub byte in a built exe → the launcher parses the tampered canary
   map and proceeds; test goes red (it expects `ExitBadStub`). `INV-LAUNCH-01` analog — same
   self-referential caveat.
3. **Per-knob canary resolution** — `INV-CANARY-NN`. Statement: the SECRET knob is read from
   `<canary.secret>_SECRET` and nothing else. Red-path: hardcode `resolveSecret` back to
   `getEnv("HARUPACK_SECRET")` (ignore `secretEnv`); a build with
   `--stub-env-secret-canary=MARK`, run with `MARK_SECRET` set and `HARUPACK_SECRET` unset,
   fails to decrypt → red. Include a build+run interop case proving default `HARU_SECRET`
   decrypts and `HARUPACK_SECRET` no longer does.
4. **Inject reaches the child** (covered under the launch/manifest suite). Red-path: delete
   the §4.2 `putEnv` loop; an app that echoes an injected var sees it empty → red. Assert
   uv-side visibility too (a `[[pre_install]]` step reads it).
5. **Inject secret-shaped warning** — `INV-INJECT-NN`. Statement: an unencrypted build warns
   when an inject value is secret-shaped; an encrypted build does not. Red-path: remove the
   §4.3 warning branch; build unencrypted with `--env-append "API_TOKEN=<20+ chars>"` and
   assert the WARNING is present → red without the branch. Cite `INV-SECRET-02`.
6. **Build refusals** (reserved inject key, invalid canary token, conflicting defaults):
   claiming tests assert non-zero exit; Red-path = remove each `raise`.
7. **Secret never leaks** — extend the existing `INV-SECRET-02` manifest/receipt test: the
   resolved secret value appears in no produced file or return value; the `canary` map MAY
   appear (it is not secret).

Caution reiterated: Phase 1 does NOT touch the encrypted container byte format. Only the
secret's env-name source changes. `crypto.py` and `cryptbox.nim` container code stay in
lockstep; compile and run the Nim interop tests before believing any of it (`INV-CRYPTO-04`).

---

## 8. Compact reference

- Footer: v1 = 68B unchanged; v2 = 116B = shared `[0:60]` prefix + `stub_off` u64 +
  `stub_len` u64 + `stub_sha256` 32 + TAIL. Located by backward MAGIC scan, dispatched on
  `format_ver`, extent validated by size.
- Stub-config: cleartext TOML, `stub_config_version = 1`, `[canary]` with exactly `secret`,
  `uv_ver`, `source_url`, `base_path`; digest-checked before parse; unknown top-level keys
  reserved/ignored for later phases.
- Manifest: `inject = ["K=V", ...]`, post-decrypt, applied before uv + app, launcher vars
  win on collision.
- CLI: `--env-canary`, `--env-canary-random`, `--stub-env-secret-canary`,
  `--stub-env-uv-ver-canary`, `--stub-env-source-url-canary`, `--stub-env-base-path-canary`,
  `--env-append` (repeatable).
- Runtime: knob `K` reads `<canary[K]>_<KNOB>`; default `HARU`; only SECRET consumed
  (replaces `HARUPACK_SECRET`, default now `HARU_SECRET`); UV_VER/SOURCE_URL/BASE_PATH wired
  via `envForKnob`, consumers TODO.

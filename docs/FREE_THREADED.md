# haru-pack — free-threaded Python (PEP 703)

Plan, not implementation. Nothing in this document is built yet.

Every factual claim below was measured on **2026-09-10** against **uv 0.10.4** and
python-build-standalone releases **20260211** and **20250818**. Version-sensitive claims are
marked so a future reader knows what to re-check rather than trusting the prose — the
`INVARIANTS.md` lesson is that a paragraph costs the same to write whether or not it is true.

---

## The short answer

The premise — *"basically free as long as it's declared in the pyproject.toml"* — is **half
right, and the wrong half is load-bearing.**

Right: uv treats free-threaded as just another interpreter variant. Selecting one is a single
string (`3.14t`), the download matrix covers every target haru-pack supports, and pinning needs
no new machinery.

Wrong, in three specific places:

| # | Blocker | Why it is not free |
|---|---|---|
| 1 | **No `install_only` archive exists for free-threaded builds** | haru-pack's interpreter fetcher requires one. Free-threaded ships only `-full.tar.zst`: a different compressor (zstd, which stdlib `tarfile` cannot open before Python 3.14) and a different internal layout, at 338 MB extracted vs ~80 MB. |
| 2 | **`uv pip install --python-version 3.13t` is rejected** | This is exactly the call haru-pack makes to stage Windows wheels from a Linux host. A different flag has to carry the variant. |
| 3 | **`default` and `thin` tiers have no runtime knob for the variant** | Nothing in the manifest tells the *target machine's* uv to pick a free-threaded interpreter, so a build declared free-threaded would **silently run GIL-enabled Python on the target**. This is a correctness hole, not a missing feature. |

Also wrong in a smaller way: **`pyproject.toml` cannot express this at all.** `requires-python`
is a PEP 440 specifier; `>=3.14t` is not a valid specifier and uv rejects it. The declaration
lives in **`.python-version`** (which `uv python pin 3.14t` writes) or in haru-pack's own
config. haru-pack reads `.python-version` already — see `_dot_python_version` in
`src/haru_pack/discovery.py:17` — and then throws the variant away one line later.

---

## 1. What was verified

### 1.1 Availability — free-threaded exists for every target haru-pack ships

`uv python list --all-platforms --all-arches --all-versions`, uv 0.10.4:

| Platform | Free-threaded versions |
|---|---|
| linux-x86_64 (gnu + musl) | 3.13t 3.14t 3.15t |
| linux-aarch64 | 3.13t 3.14t 3.15t |
| linux-armv7 | 3.13t 3.14t 3.15t |
| windows-x86_64 | 3.13t 3.14t 3.15t |
| windows-aarch64, windows-x86 | 3.13t 3.14t 3.15t |
| macos-x86_64, macos-aarch64 | 3.13t 3.14t 3.15t |

Note `--all-arches` is required as well as `--all-platforms`, for the reason already documented
at `src/haru_pack/bundle.py:104`: without it aarch64 is invisible and a Pi target looks
unsupported. The same trap applies here.

Selection defaults, from uv's docs: for **3.13** a free-threaded build is *never* selected
unless explicitly requested. For **3.14+** uv may use one without explicit selection, but still
*prefers* the GIL build. Neither default gives us what we want, so haru-pack must always be
explicit — including using the `+gil` specifier if we ever need to force the GIL build.

### 1.2 The `install_only` blocker

`src/haru_pack/bundle.py:116` filters the uv catalog with:

```python
if "install_only" not in url: continue
```

Of **335** free-threaded entries in uv's catalog, **0** have an `install_only` URL. Confirmed
against upstream rather than only against uv's view — in release `20260211`, of 141
free-threaded assets, `install_only`: 0, `install_only_stripped`: 0, `full`: 141. Same shape in
`20250818` (88 free-threaded, 0/0/88). This is upstream policy, not a catalog gap, so waiting
for it is not a plan.

Measured, `cpython-3.14.3+20260211-x86_64-pc-windows-msvc`:

| Asset | Download | Extracted |
|---|---|---|
| `install_only_stripped.tar.gz` | 22.3 MB | — |
| `install_only.tar.gz` | 49.0 MB | — |
| `freethreaded+pgo-full.tar.zst` | **49.0 MB** | **338 MB** |

Download size is a wash. Extracted size is not, and extraction is what happens on the *target*.
The breakdown is what makes it tractable:

```
python/install    198M
python/build      141M     <- static libs + headers for embedders; we never use these
python/licenses   176K
python/PYTHON.json
```

Layouts differ, which is the part that silently breaks things:

```
install_only.tar.gz   ->  python/{bin,lib,include,...}
full.tar.zst          ->  python/{PYTHON.json,build,install,licenses}
                                              ^ our interpreter is under here
```

So the fix is: extract only `python/install/**`, rewritten to sit where `install_only` would
have put it. That keeps `Target.python_exe` (`targets.py:136`), `_extract_find`, and the Nim
launcher's `findBundledPython` (`launcher/main.nim:49`) **unchanged**, which is worth a lot —
`findBundledPython` is load-bearing for `INV-LAUNCH-04`.

Layout sanity, both OSes, checked:

- Windows: `python/install/python.exe` present (alongside `python3.14t.exe`, `python314t.dll`).
  The launcher looks for `python.exe`, so it resolves.
- Linux: `bin/python3 -> python3.14` symlink present, so the launcher's
  `fn == "python3" and parent == "bin"` test resolves. Note the free-threaded Linux build names
  the binary `python3.14`, **not** `python3.14t` — do not write a check that expects the `t`.

### 1.3 zstd

`.tar.zst` is not openable by stdlib `tarfile` before Python 3.14 (PEP 784 added
`compression.zstd`). haru-pack declares `requires-python = ">=3.9"`, so this cannot be assumed.
Verified on this host (Python 3.14.4): `tarfile.open('…tar.zst')` auto-detects and reads 5241
members. On 3.9–3.13 it will not.

### 1.4 The cross-compile wheel blocker, and its fix

`warm_cache_windows` (`src/haru_pack/bundle.py:225`) stages Windows wheels from a Linux host
with `--python-version <ver>`. That flag will not take a variant:

```
error: invalid value '3.13t' for '--python-version <PYTHON_VERSION>': Python version
`3.13t` could not be parsed: after parsing `3.13`, found `t`, which is not part of a
valid version
```

There is no `--abi` / `--free-threaded` flag on `uv pip install` to compensate.

**The fix that works** (verified): pass `--python <path to a host free-threaded interpreter of
the same X.Y>` *instead of* `--python-version`, keeping `--python-platform windows`. uv then
derives the tags from that interpreter:

```
$ uv pip install --python ~/.local/share/uv/python/cpython-3.14+freethreaded-linux-x86_64-gnu/bin/python3.14t \
    --python-platform windows --only-binary :all: --target out -r r.txt
+ cffi==2.1.1
$ ls out
_cffi_backend.cp314t-win_amd64.pyd        <- free-threaded Windows ABI, resolved from Linux
```

Worth stating plainly because it looks like a supply-chain regression and is not: that host
interpreter is used **only to derive wheel tags**. It is never staged into the payload and never
executed by the target, so it does not enter the signed artifact and needs no pin. `INV-SUPPLY-07`
is about what gets staged; this is not that. It does mean the build host must have a matching
free-threaded interpreter, which is a `bootstrap` concern (§3.6).

### 1.5 Pinning — genuinely free

`tools/add-pin.py` refuses locally-computed digests and takes the publisher's, from either the
`.sha256` sidecar or the release API's `digest` field. Relevant facts:

- These releases publish **zero** `.sha256` sidecars — for *any* asset, free-threaded or not. So
  all 148 existing pins already come from the API `digest` channel. Nothing new.
- The `digest` field **is** populated for free-threaded assets.
- Checked end to end: the API reports
  `sha256:dac2dc871cc9d170a9930985269b6f3e9e2fc364a6c8eb3c2e8b61f204a67f2c` for
  `cpython-3.14.3+20260211-x86_64-pc-windows-msvc-freethreaded+pgo-full.tar.zst`; downloading it
  and hashing gives the same value.

So pinning is `tools/add-pin.py python <url>` per (version × target) and no code change. The
only cost is that the pin table grows — and note `INV-SUPPLY-01` means an unpinned free-threaded
target fails *closed*, which is the correct behavior while the matrix is being filled in.

### 1.6 Wheel ecosystem — better than expected

`--python-platform windows --only-binary :all:` against cp314t:

| Result | Packages |
|---|---|
| resolves | numpy, pandas, scipy, lxml, pyzmq, cryptography, pillow, greenlet, pydantic |
| refuses | psycopg2-binary |

The refusal is precise and quotable, which is what makes the probe in §4 cheap:

```
psycopg2-binary==2.7.3.2 has no wheels with a free-threading compatible tag
```

And the resolver is not cheating with `abi3`. `cryptography` ships abi3 wheels for the GIL
build; under free-threading it selected a real variant-specific one:

```
Tag: cp314-cp314t-win_amd64      (cryptography, and pillow likewise)
```

That matters for §4: **for C extensions, resolution is a real gate, not a formality.**

---

## 2. Where the version string is handled today

| Concern | Location |
|---|---|
| Extract X.Y from any spec | `discovery.py:11` `_PYVER = re.compile(r"(\d+\.\d+)")` |
| Read `.python-version` | `discovery.py:17` |
| PEP 723 `requires-python` | `discovery.py:21` |
| Resolution order, default `"3.12"` | `build.py:91` — CLI > `haru_pack.toml` > discovery > default |
| `--python` flag | `cli.py:251` |
| Catalog lookup | `bundle.py:94` `_find_python_url` |
| Stage interpreter (thick only) | `build.py:126`, `bundle.py:125` `bundle_python` |
| Cross wheel staging | `bundle.py:225` `warm_cache_windows` |
| venv version sniff | `scaffold.py:88` `re.search(r"(\d+\.\d+)")` |
| Manifest → launcher | `build.py:187`; `launcher/manifest.nim:51`; `launcher/main.nim:175` |

Every one of the three regex/`startswith` sites drops or breaks on a `t` suffix:

- `discovery.py:11` — `(\d+\.\d+)` matches `3.14` out of `3.14t` and silently discards the
  variant. **Silent** is the problem; this is the path a user's `.python-version` takes.
- `bundle.py:114` — `e["version"].startswith(version)` with `version="3.14t"` matches nothing,
  because catalog versions are `"3.14.3"`. Fails closed, at least.
- `scaffold.py:88` — same shape as the first.

While in `_find_python_url`, note an **existing** bug, out of scope but worth an issue:
`if e["version"] > best[0]` is a *string* comparison, so `"3.9.1" > "3.14.3"`. It has not bitten
because the requested prefix is usually specific enough.

---

## 3. Design

### 3.1 Carry `3.14t` as the wire format; parse in exactly one place

uv's own spelling is `3.14t`. Adopting it means the string can be handed to uv verbatim
(`UV_PYTHON`, `--python`) with no reassembly, and users can copy what the uv docs told them.

Add one helper — suggested `haru_pack/pyver.py` — and route every existing site through it:

```python
def split_variant(spec: str) -> tuple[str, bool]:
    """'3.14t' -> ('3.14', True);  '>=3.14' -> ('3.14', False);  '' -> ('', False)"""
```

Rejected alternative: threading a `free_threaded: bool` beside the string through
`build` → `assemble_payload` → `bundle_python`. Two fields that must agree, four call sites
apart, is how they stop agreeing.

The constraint that makes the `t` suffix safe to adopt: **`requires-python` can never produce
one.** `>=3.14t` is not a valid PEP 440 specifier. So a `t` reaching `split_variant` came from
`.python-version`, `haru_pack.toml`, or `--python` — all explicit. No inference from
`pyproject.toml` is possible, and none should be attempted.

### 3.2 `_find_python_url` — the actual "one string"

```python
base, ft = split_variant(version)
want_variant = "freethreaded" if ft else "default"
...
if e.get("variant") != want_variant: continue
if not e.get("version", "").startswith(base): continue
# free-threaded publishes no install_only; require the full archive instead
marker = "-full.tar.zst" if ft else "install_only"
if marker not in url: continue
```

### 3.3 Extraction

Keep this inside `archives.py` behind `safe_extract_tar`. **Do not** add a separate zstd path
that bypasses `_reject_unsafe_members` — that check is `INV-SUPPLY-03`, and a second extraction
path is exactly how one of them ends up unguarded (the same failure `INV-SUPPLY-07` was mined
from: two paths, one unverified, and it was the default one).

Decompressor, in order, first available wins:

1. stdlib `compression.zstd` (Python ≥ 3.14)
2. the `zstandard` PyPI package
3. the `zstd` binary / `tar --zstd`

then an actionable error naming all three. Recommend declaring
`zstandard>=0.22; python_version < "3.14"` so the common case needs no host tool, and treating
(3) as the escape hatch. This is a new dependency in a tool whose whole pitch is a signable
artifact, so it wants a line in `THREAT_MODEL.md` — though note it runs on the *build* host and
its input is digest-verified before extraction, so it is not in the trusted path the way a
staged interpreter is.

Then extract **only** `python/install/**`, stripping that prefix so the result matches the
`install_only` shape. Dropping `python/build/` is not an optimization; it is 141 MB of embedder
static libs, 42% of the tree, that nothing in haru-pack reads.

### 3.4 The tier hole — highest severity item here

`launcher/main.nim:175`:

```nim
var py = if m.python.len > 0: stageRoot / m.python else: findBundledPython(stageRoot)
```

`manifest.python` is a **path**, not a version. For `thick` that is fine — the interpreter is on
disk and `UV_PYTHON` points at it, so the variant is settled at build time.

For `default` and `thin` there is no staged interpreter, and **nothing carries the variant to the
target at all.** uv on the target resolves from `requires-python`, which by §3.1 can never say
`t`. Result: `haru-pack ./app --free-threaded` (default tier) produces a binary that runs
GIL-enabled Python, reports success, and is indistinguishable from a correct build.

Fix: new manifest key `python_request` (string, e.g. `"3.14t"`), read in `manifest.nim`
alongside `python`. When there is no bundled interpreter and `python_request` is set, the
launcher sets `UV_PYTHON=3.14t`. This is additive and does not disturb `INV-LAUNCH-04`, which is
about refusing to resolve an interpreter off the host in the *thick* tier.

The cheaper alternative — refuse `--free-threaded` outside `--thick` — is worse for the operator
and does not scale, but is an acceptable first commit if `python_request` slips.

### 3.5 CLI and config surface

- `--free-threaded` / `--no-free-threaded`, tri-state, unset = infer from `.python-version` /
  config.
- `haru_pack.toml`: `free_threaded = true`, next to the existing `python = "3.12"`.
- `--python 3.14t` keeps working and **implies** `--free-threaded`.
- Conflict (`--python 3.14t --no-free-threaded`) is an error, not a precedence rule.

Why both a flag and a suffix: the suffix alone cannot express "same version, other variant" for
the A/B the probe needs, and a boolean is what `ft-probe` has to flip.

Report the variant in `haru-pack build`'s output and in whatever `--verbose` prints. An operator
should never have to unzip a payload to learn whether they shipped free-threaded — that is the
ergonomics point, and it is the only defense against §3.4 recurring.

### 3.6 bootstrap

`bootstrap` gains, on `--free-threaded` or on demand: `uv python install <X.Y>t` for the **host**
platform, needed for §1.4 tag derivation. One line, and it should say why it is doing it.

### 3.7 Cost

| Item | Size |
|---|---|
| `pyver.split_variant` + route 3 call sites | small |
| `_find_python_url` variant/marker | small |
| zstd + `python/install/**` extraction in `archives.py` | **medium — the real work** |
| `warm_cache_windows` `--python` swap | small |
| `python_request` manifest key + Nim read + `UV_PYTHON` | small, two languages |
| CLI/config/docs | small |
| Pins for the matrix | mechanical, no code |

---

## 4. The upgrade probe

> *"plan for possibly trying to 'upgrade' a project deployed if it passes its test suite when
> run in a free-threaded python environment. not a promise that it'll work but a good
> indicator."*

Taking the framing at its word — *indicator, not promise* — the design question is not how to
run the tests. It is **how to report the result without it being read as a promise.** A green
suite is the single most over-read signal in this whole feature.

### 4.1 There is no in-place upgrade

A shipped haru-pack binary is immutable: interpreter, wheels and payload digest are fixed at
build time. "Upgrading a deployed project" therefore means **rebuild with free-threading and
ship a new binary.** The probe gates that decision; it changes nothing already deployed. Worth
saying out loud in the CLI help, because "upgrade" invites the other reading.

### 4.2 Separate command, not a build mode

**Recommend `haru-pack ft-probe ./project`, and *not* `build --free-threaded=auto`.**

An `auto` mode makes the artifact a function of whether a test suite passed on the build host
that day. Two builds from the same commit could ship different interpreters, and the exe does
not obviously say which. That breaks reproducibility for the sake of saving one command.

So: `ft-probe` prints a recommendation and writes evidence; a human (or CI) then passes
`--free-threaded` to a build that stays deterministic.

### 4.3 Three gates, cheap to expensive, stop at the first failure

**Gate 1 — resolution.** Can the dependency set even be assembled for the `t` ABI, *for the
target platform*? Seconds, no code executed, and §1.6 shows the error names the offending
package. Catches the most common failure.

Must run per target, not on the host. A project that resolves free-threaded on Linux can fail
for Windows; that is precisely the case haru-pack exists to serve.

**Gate 2 — import smoke.** The flex harness already does this: `smoke_body()` at
`tools/flex-run.py:85` imports the package and prints `FLEX_OK`. Reuse it rather than growing a
second one. Catches C extensions that resolve but fault on load.

**Gate 3 — the test suite.** Detect the runner (`[tool.pytest.ini_options]`, a `tests/` dir,
`tox.ini`), then run it **twice: GIL-enabled baseline first, free-threaded second.** The
baseline is not optional — a suite that is already red, or already flaky, makes the
free-threaded run uninterpretable, and "it failed under free-threading" would be a false
accusation. Report the *delta*.

### 4.4 The probe's own red-path

The probe can pass trivially by not actually turning the GIL off. Guard it:

- Assert `sys._is_gil_enabled() is False` inside the test process, not merely that a `t`
  interpreter was selected.
- Scrub `PYTHON_GIL` from the child environment. `PYTHON_GIL=1` silently re-enables the GIL on a
  free-threaded build, and a probe that inherits it reports a green run that proves nothing.
- Record the ABI tags of the wheels actually installed (`cp314t` vs pure-Python), so a
  pure-Python project cannot look like it validated a C extension.

In `INVARIANTS.md` terms, the red-path is: force `PYTHON_GIL=1`, run the probe, and watch it
refuse to report a pass. If it still reports a pass, the probe is decorative.

### 4.5 Report evidence, not a verdict

`ft-probe.json`, plus a short human summary:

```json
{
  "target": "windows-x86_64",
  "python": "3.14t",
  "gil_disabled_observed": true,
  "resolution": {"ok": true, "wheels": {"numpy": "cp314t-win_amd64", "pydantic": "py3-none-any"}},
  "smoke": {"ok": true},
  "suite": {
    "baseline_gil":  {"passed": 214, "failed": 0, "seconds": 31.2},
    "free_threaded": {"passed": 214, "failed": 0, "seconds": 27.8}
  },
  "verdict": "no-blocker-found"
}
```

Deliberately `no-blocker-found`, not `compatible`. The honest summary line is roughly:

> 214 tests found no free-threaded blocker in 27.8 s. This is not evidence of thread safety:
> the suite ran single-threaded and exercised none of the concurrent paths free-threading
> changes.

That caveat is the whole point. Most suites are single-threaded, so they exercise approximately
none of the races that removing the GIL exposes; the probe's real power is Gate 1, which is
mechanical and reliable, not Gate 3, which is suggestive at best. If the project reports
coverage, include the number — it bounds the claim.

Optional and clearly worth it later, not first: re-run the suite under `pytest-run-parallel` or
with a thread-stress plugin. That is the only gate that would produce real thread-safety
evidence, and it should not be conflated with Gate 3.

---

## 5. Proposed invariants

Three entries are **already declared** in `INVARIANTS.md` as `Status: proposed`, which means
exactly what the file says it means: the behavior is *not implemented*, the gap is written down
so it is legible, and a `proposed` entry must have **zero** claiming tests. Each is promoted only
by walking its Red-path — neutralize, watch red, restore.

| Id | Claims | Lands with |
|---|---|---|
| `INV-TIER-03` | `--free-threaded` is not a silent no-op at `default`/`thin` | §3.4, step 5 |
| `INV-SUPPLY-11` | the `.tar.zst` path does not escape the pin + member sanitizer | §3.3, step 2 |
| `INV-BUILD-10` | `ft-probe` cannot pass without observing the GIL off | §4.4, step 7 |

Note for whoever implements: **numbering is not what you would guess.** `INV-BUILD-07`, `-08` and
`-09` already exist, so the probe invariant is `-10`. The linkage contract in
`tests/test_invariants_enforced.py` catches a citation of an undeclared id — it caught the first
draft of this document, which cited all three before they were declared. Do not cite a fourth id
here before adding it there.

---

## 6. Suggested order

1. `pyver.split_variant`, routed through `discovery.py`, `scaffold.py`, `bundle.py`. No behavior
   change yet; the `t` simply stops being silently discarded.
2. zstd + `python/install/**` extraction in `archives.py`, behind `safe_extract_tar`
   (`INV-SUPPLY-11`). The largest piece — do it before anything depends on it.
3. `_find_python_url` variant + archive marker. Pin one target. `--thick --free-threaded` for
   host Linux now works end to end.
4. `warm_cache_windows`: `--python <host ft interp>` instead of `--python-version`; bootstrap
   provisions it. Windows cross now works.
5. `python_request` + Nim + `UV_PYTHON` (`INV-TIER-03`). Until this lands, **refuse
   `--free-threaded` outside `--thick`** rather than shipping the silent no-op.
6. Fill the pin matrix.
7. `ft-probe` Gates 1–2 (`INV-BUILD-10` on the GIL assertion from the start).
8. `ft-probe` Gate 3, with the GIL baseline A/B.
9. `docs/TIERS.md` size table gets free-threaded rows; `SHARP_CORNERS.md` gets the
   `requires-python`-cannot-say-`t` trap and the `PYTHON_GIL=1` override.

Steps 1–4 are the "basically free" part, and it is genuinely small. Step 5 is the one that must
not be skipped, and step 4 is the one most likely to be underestimated.

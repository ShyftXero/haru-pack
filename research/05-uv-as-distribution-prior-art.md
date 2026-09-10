# Research 05 — `uv` as a distribution mechanism: prior art, credits, and what to steal

_Agents: Zero_Cool (Astral first-party), Acid_Burn (third-party packers), Null_Pointer (field
patterns + packaging channels), Cereal_Killer (signing & sharp edges). Date: 2026-09-09._

This document exists to **acknowledge the prior art haru-pack is built on top of** and to record,
with attribution, which ideas we are deliberately borrowing. `research/01` was written before we
had surveyed the field and overstated how much of haru-pack's design is novel. This corrects it.

> **Read this first:** haru-pack is not the first tool to stage `uv` from a native launcher.
> `ofek/pyapp` got there in April 2024 and `razorblade23/PyCrucible` independently arrived at
> *embedded uv + extract-beside-the-exe*, which is two-thirds of what `research/01` listed as our
> differentiators. Our remaining honest differentiation is narrower and is stated in Part 6.

---

## Part 1 — The pattern and its tiers

The idea under discussion: **ship a small native stub; let a package manager acquire the
interpreter and dependencies.** It trades a first-run network dependency for a ~2–10 MB artifact
and an in-field update path. The opposing tradition — freezers — resolves everything at build
time and ships the result.

The dividing line is **who resolves dependencies, and when.**

Four tiers show up across every ecosystem:

| Tier | Interpreter | Deps | Package manager | Offline |
|---|---|---|---|---|
| **Fetch-all** | fetched | fetched | fetched | no |
| **Bundled-manager** | fetched | fetched | **embedded** | no |
| **Eager/embed** | embedded | embedded | embedded or n/a | yes |
| **Freeze** | compiled/frozen in | frozen in | n/a | yes |

haru-pack's `--thin` / default / `--thick` tiers are a rediscovery of a distinction that PEX
named first (`--scie lazy` vs `--scie eager`) and that PyCrucible expresses as `--no-uv-embed`.
We should say so.

---

## Part 2 — Prior art catalogue

### A. Astral, first-party

Astral ships the substrate haru-pack stands on. Worth being precise about what they do and do
not offer.

**`uv tool install` / `uvx`** — per-tool venvs under `UV_TOOL_DIR`, executables **symlinked on
Unix and copied on Windows** into `UV_TOOL_BIN_DIR` (no trampoline binary, unlike pixi).
`@version` pins exact versions only; ranges need `--from`. `--with` layers deps without exposing
their entry points. `uv tool audit` landed in 0.12.2.
<https://docs.astral.sh/uv/concepts/tools/>

**PEP 723 + `uv run`** — PEP 723 is Final. `uv run` accepts a path **or an HTTP(S) URL**; for
URLs "the script is temporarily downloaded before execution". `uv lock --script app.py` produces
`app.py.lock`. `exclude-newer` pins resolution by artifact upload time.
Notable: the URL-execution capability appears in **one clause of the CLI reference with no
security admonition anywhere in the guides**. The trust analysis in circulation is community
work (Josh Cannon), not Astral's.
<https://docs.astral.sh/uv/guides/scripts/>, <https://docs.astral.sh/uv/reference/cli/#uv-run>

**`uv python install` / python-build-standalone** — Astral took stewardship of p-b-s from
indygreg (repo transferred 2024-12-17). Astral owns the *distributions*; it did **not** take over
PyOxidizer — charliermarsh and zanieb have corrected that assumption in-thread.
<https://astral.sh/blog/python-build-standalone>

**`uvx.sh`** — the closest thing Astral has to an end-user install channel, and it is
undocumented. Charlie Marsh, [uv#5802](https://github.com/astral-sh/uv/issues/5802):

> "For clarity: yes, I built that as an experiment. We run it and own the domain. It's a
> Cloudflare worker that emits a shell script to install uv (if not installed), then use uv to
> install the package…"

`curl -LsSf uvx.sh/ruff/install.sh | sh`, version-pinnable as `uvx.sh/ruff/0.8.3/install.sh`.
The generated script does **no checksum or signature verification of anything**. It appears
nowhere in docs.astral.sh and has no announcement blog post.

**`uv venv --relocatable`** — exists ([PR #5515](https://github.com/astral-sh/uv/pull/5515)),
makes activation scripts and wheel entry points path-independent, persists a flag in
`pyvenv.cfg`. **Not documented in the concept docs**, only the CLI reference. Directly relevant
to staging a portable venv; we should use it.

#### Astral has declined to build a bundler, on the record

| Issue | Title | State |
|---|---|---|
| [#2799](https://github.com/astral-sh/uv/issues/2799) | "shiv/pyinstaller like functionality?" | open, **wish** |
| [#5802](https://github.com/astral-sh/uv/issues/5802) | "`uv bundle`, `uv build --release`… a la pyinstaller, py2exe" — 70 comments, **411 reactions** | open, **wish** |
| [#7865](https://github.com/astral-sh/uv/issues/7865) | "Bundle Python Interpreter in virtual environments" | open |
| [#12035](https://github.com/astral-sh/uv/issues/12035) | "Production Bundling – Single File Deployment" | closed |
| [#14727](https://github.com/astral-sh/uv/issues/14727) | "Possibility of a `uv bundle` command" | closed, **wish** |
| [#10465](https://github.com/astral-sh/uv/issues/10465) | rename the `uv` binary to `mytool`, dispatch to `uv tool run` | open, **wish** |

The repo defines `wish` as **"Not on the immediate roadmap."** zanieb, 2025-07-18 on #14727:
**"It's plausible, but we're not pursuing this in the short-term."** Across #5802's full history
no maintainer has ever scoped or timelined bundling.

**`astral-sh/war`** — confirms `research/01`. 9 stars, 5 commits, SPEC v0.0.2, self-described
"Paperware". Additional finding: despite "for Python packaging" in the title, the spec contains
**zero Python-packaging semantics** — no wheel, sdist, RECORD or metadata concepts. It is a
generic indexable archive container. Nothing in uv consumes it. Any claim that `war` is Astral's
app-artifact play is speculation. Decision stands: borrow the concepts, don't wait for it.

### B. Python launchers that stage a package manager — the direct prior art

#### `ofek/pyapp` (Rust) — the reference implementation

2,031★, v0.29.0 (2025-10-15). Used by Hatch, pdm, Litestar, instawow, Datadog, EPFL.
<https://github.com/ofek/pyapp> · <https://ofek.dev/pyapp/latest/>

Read from source, and it sharpens `research/01`'s claim:

- **uv is never embedded.** `build.rs` only computes a GitHub release URL and bakes it in as a
  runtime constant. There is no `PYAPP_UV_EMBED`.
- Consequence: **`PYAPP_UV_ENABLED` and true-offline operation are mutually exclusive by
  construction.** Offline means `PYAPP_DISTRIBUTION_EMBED=1` + `PYAPP_SKIP_INSTALL=1`, i.e.
  uv is not in the picture at all.
- Install location is `data_local_dir/<project>/<distribution-id>/<version>` — versioned three
  levels deep, so upgrades install side-by-side. The uv cache is shared across pyapp apps
  (`cache_dir/uv/<version>`); the install dir is per-app. It already does both halves of the
  cache-layout question.
- **No `$ORIGIN`-style exe-dir token.** `PYAPP_INSTALL_DIR_<NAME>` is a raw `PathBuf::from`, so a
  relative value resolves against the **CWD**, not the executable's directory. Run-in-place needs
  a wrapper or a patch.
- Runtime: `execvp` on non-Windows (no lingering wrapper process), injects `PYAPP=1`, and after
  first run "only check[s] if the installation directory exists **and nothing else**".
- Management surface: `<EXE> self remove|restore|update`, opt-in `self cache|metadata|pip|python`.
- Cross-compilation via `cross` containers; `cargo install pyapp` cannot cross-compile; embedding
  + cross-compiling forces the local-repo route with repo-relative paths.
- **Verifies nothing.** `src/network.rs` is `reqwest::blocking::get(url)` checking only
  `status().is_success()` — no hash, no signature, and **`http://` sources are accepted**.
  No signing story; zero issues filed about any of it.

#### `razorblade23/PyCrucible` (Rust) — haru-pack's closest living relative

209★, v0.4.8 (2026-08-29). <https://github.com/razorblade23/PyCrucible>

Self-described: "a robust, cross-platform builder and launcher for Python apps using UV."
Two design choices that we independently arrived at, and they got there first:

- **Embeds the uv binary by default**, selectively extracting only `uv` from the upstream
  archive; `--no-uv-embed` makes fetching the opt-in. This is the exact inverse of pyapp and is
  the correct default.
- **Extracts to a permanent directory alongside the executable** by default; `--extract-to-temp`
  and `--delete-after-run` and AppData are the opt-outs.
- Also: wheel embedding, `pycrucible.toml` / `[tool.pycrucible]` config with
  `patterns.include/exclude`, `env`, and `hooks.pre_run` / `hooks.post_run`.
- v0.4.8 fixed a **zip-slip vulnerability** in payload extraction — a bug class our overlay
  unpacker must also defend against.
- No signing story; no cross-compilation flow (build per-target like any Rust project).

**This means `research/01`'s differentiator list was wrong.** "Truly embed uv" and "run-in-place
UX" are differentiators against *pyapp*, not against the field.

#### `TanixLu/pyfuze` — uv + Cosmopolitan

Three modes: `bundle` (embed everything, host platform only), `online` (uv fetches interpreter
and deps at first run), `portable` (Cosmopolitan APE Python 3.12.3, one file on every OS, but
**pure-Python deps only**). The `portable` mode is the only thing in this survey that gets a
single file across Linux/macOS/Windows with no fetch — at the cost of banning C extensions.
Explicitly: "pyfuze does **NOT** perform any kind of code encryption or obfuscation."

#### `pex --scie` and the `a-scie` project — the tier system, done first

<https://docs.pex-tool.org/scie.html> · <https://github.com/a-scie/lift>

Architecturally the same as pyapp, from the Pants side, and the closest prior art for
**haru-pack's tiers**:

- `--scie eager` — full Python distribution embedded, no network.
- `--scie lazy` — distribution fetched on demand, reused if already local.
- `--scie-busybox` — **multiple entry points as distinct commands from one binary.** haru-pack
  has no equivalent; hatch instead emits N separate executables.
- Machinery: `scie-jump` (self-executing archive format), `ptex` (lazy fetcher), `science`/`lift`
  (builder, `lift.toml`). `science` is itself a scie built with science.
- Unpacks to a **shared content-addressed `~/.cache/nce/<hash>`**, deduping interpreters across
  applications — the opposite tradeoff to pyapp's per-app versioned tree.

#### `njsmith/posy` — the dormant ancestor

299★, last push **2024-03-01**. "posy is a pure-rust single-file binary; it doesn't assume you
have anything else installed." Targeted exactly this problem; uv shipped the same idea and posy
stopped. Historical interest, but it deserves the credit for stating the goal early.

### C. Adjacent ecosystems

- **`mise generate tool-stub --bootstrap`** — the most general form of this pattern anywhere: a
  portable stub that downloads and executes a tool from an HTTP URL, optionally wrapped in a
  bootstrap script that "installs mise if not already present." Stub → package manager → tool.
  **Nothing in Python does this.** `mise generate install-script` is the committed-`bin/mise`
  variant, with `--windows` emitting a `.cmd` because Windows can't exec bash.
  <https://mise.jdx.dev/cli/generate/tool-stub.html>
- **`cashapp/hermit`** — `bin/hermit` committed into the repo, self-bootstrapping, per-project
  isolated tool sets. Purest expression of "committed stub fetches everything."
- **`pixi` trampolines** — small binaries in `$PIXI_HOME/bin` that read a per-binary JSON, fix up
  PATH and `CONDA_PREFIX`, then exec. **A shim, not a bootstrapper** — it configures an
  already-installed environment. Still the right model for exposing N entry points cheaply.
  <https://pixi.prefix.dev/latest/global_tools/trampolines/>
- **`quantco/pixi-pack --create-executable`** — packs a lockfile's resolved packages into a
  self-extracting script; **cross-platform packing supported** (pack a `win-64` env from Linux).
  Directly analogous to `--thick --target windows`.
- **`deno compile`** — the bar. Embeds the runtime (downloaded on the *build* machine), full
  **cross-compilation via `--target`**, macOS binaries **ad-hoc signed by default** and
  re-signable with `codesign`, Windows documented via `signtool`. Cross-compile + embed +
  signable, all three at once. Every Python option loses to this.
  <https://docs.deno.com/runtime/reference/cli/compile/>
- **`npx`** bootstraps packages but never the runtime; **asdf** shims but must itself be
  installed; **Nix** has no per-app stub. Half the pattern or none of it.

### D. The freezer tradition (what we are not)

| Tool | Stars | Last push | Relation |
|---|---|---|---|
| [Nuitka](https://github.com/Nuitka/Nuitka) | 15,127 | 2026-09-09 | compiles to C; no install step at all |
| [PyInstaller](https://github.com/pyinstaller/pyinstaller) | 13,090 | 2026-09-06 | freeze + self-extract; hooks exist because static dep detection is unsound |
| [PyOxidizer](https://github.com/indygreg/PyOxidizer) | 6,155 | **2024-12-24** | imports modules **from memory**; dead-but-load-bearing — its legacy is p-b-s |
| [pex](https://github.com/pex-tool/pex) | 4,225 | 2026-09-05 | zipapp + lockfiles + multi-platform resolve, with `--scie` as the escape hatch |
| [Briefcase](https://github.com/beeware/briefcase) | 3,350 | 2026-09-09 | native app bundles + the platform's real installer/signing toolchain; only mainstream route to mobile |
| [shiv](https://github.com/linkedin/shiv) | 1,945 | 2026-05-22 | zipapp unpacked to `~/.shiv`; **needs a compatible Python already present** |
| [cx_Freeze](https://github.com/marcelotduarte/cx_Freeze) | 1,560 | 2026-09-07 | freezer with the strongest **native installer** story (MSI, DMG, AppImage, deb) |
| [py2exe](https://github.com/py2exe/py2exe) | 990 | 2026-06-21 | Windows-only, still maintained |
| [conda/constructor](https://github.com/conda/constructor) | 497 | 2026-09-09 | package manager does the work, but at **install** time, and the artifact is an installer |

---

## Part 3 — Field evidence: how the pattern is actually used

**Projects whose official install line is uv-first** (all verified from their READMEs):

- **Harlequin** — "We strongly recommend using uv"; install block opens with
  `curl -LsSf https://astral.sh/uv/install.sh | sh` then `uv tool install harlequin`. pipx demoted
  to "Other Installation Methods."
- **Posting** — same shape, plus `uv tool install --python 3.13 posting` with the parenthetical
  "(will also quickly install Python 3.13 if needed)".
- **Ruff** — `uvx ruff@latest check` first, `uv tool install` second, *before* pip, pipx, and
  Astral's own standalone installer.
- **The MCP server ecosystem** is the largest emergent uvx channel:
  `{"command": "uvx", "args": ["mcp-server-git", …]}` is the canonical config.

**Aider is the best-documented instance of the two-step bootstrap**, and its stated motive is
haru-pack's thesis verbatim:

> "It's hard to reliably package and distribute python command line tools to end users. Users
> frequently encounter challenges: dependency version conflicts, virtual environment management,
> needing to install python or a specific version of python, etc."
> — <https://aider.chat/2025/01/15/uv.html>

They forked Astral's `install.sh` and appended
`uv tool install --force --python python3.12 --with pip aider-chat@latest`, and additionally ship
a two-package PyPI shim (`aider-install`) whose only dependency is `uv`. Simon Willison called it
"quite a tasteful way of getting everything working with minimal risk of breaking the user's
system."

**The boundary of the pattern is sharp, and every source agrees on where it is.**
The most telling data point: **Datasette — by the person who evangelizes uv hardest — does not
mention uv, uvx or `uv tool install` anywhere in its install docs.** It leads with *Datasette
Desktop for Mac* ("bundles Datasette together with Python"), then Homebrew, then pip.

> "uvx feels like a temporary hack on which I can't rely for a permanent deployment… I really
> want a **a single artifact users could freely share without any pre-configuration**"
> — HN [49077743](https://news.ycombinator.com/item?id=49077743)

That comment is haru-pack's user, stated by a stranger.

---

## Part 4 — Where the pattern breaks (why haru-pack exists)

Every item below is a documented failure of "just tell them to run `uvx`". These belong in our
README as the case for bundling.

1. **Unpinned `uvx` resolves by wall-clock time and cache state.** `uvx` takes the *latest*
   version on first invocation, then the *cached* one. The version a user gets depends on when
   they first ran it and whether their cache was touched — neither observable from a README.
   Live breakage: a working MCP server broke between 2026-07-28 and 07-31 with no config change.
2. **The package name is the entire trust anchor, and it's copy-pasted.** "With pip you only need
   to be careful on install — with uvx you need to be careful forever" (HN 46400327). Praetorian
   on MCP: `mcp-server-sqllite` vs `mcp-server-sqlite` is "a zero-click attack vector that
   bypasses tool approval mechanisms entirely." `uv audit` and `UV_MALWARE_CHECK=1` are both
   **opt-in**.
3. **No offline path.** `uv pip download` does not exist ([#4809], [#9345], [#12009], [#16410] —
   open since Jul 2024). `--offline` is a network kill-switch, not a bundler. Air-gapped users
   report `--offline --no-deps --no-index --find-links` *still* reaching for PyPI ([#13587]).
   Cache portability across machines is undocumented.
4. **Interpreters come from GitHub, not PyPI.** In regions where github.com is blocked, uv is
   reported "unusable" ([#11974]). Mirroring the interpreter matrix is ~14 GB per uv version, and
   the asset URL suffixes are compiled into the uv binary — closed as **wish** ([#10203]).
5. **Corporate TLS interception is a standing sore.** [#1474] (founding report), [#10724]
   (Zscaler; `--native-tls` and `SSL_CERT_FILE` both failed while plain `python3` worked),
   [#13672] (the installer itself fails behind MITM, before uv exists). uv defaults to bundled
   Mozilla roots where pip uses the OS store, and has **no Kerberos/NTLM proxy auth at all**.
6. **Windows PATH and shims.** `uv tool update-shell` writes the registry but never broadcasts
   `WM_SETTINGCHANGE`, so a fresh `cmd.exe` still can't find the tool ([#17331]). [#8470] (Barry
   Warsaw, open): `uvx world` runs but `world` is `command not found`.
7. **AV and SmartScreen on unsigned binaries** — years-long, labelled `external`. Defender
   quarantining `uvw.exe` as `Trojan:Script/Phonzy.A!ml` ([#15011]); install failing with "the
   file contains a virus or potentially unwanted software" ([#17344]).
8. **The cache has no size limit, by design.** [#5731] is `needs-design` and two years open;
   20–40 GB reported. An end user who ran your `uvx` line once will never run `uv cache prune`.
9. **Linux distros mostly don't have uv.** Debian's ITP [#1069776] has been open since 2024-04;
   only `python3-uv-build` shipped — ~15 of 80+ crates vendored, and several uv deps
   (`async_zip`, `tl`, `pubgrub`) **aren't on crates.io at all**, so there is no Debian-policy
   path. **No supported Ubuntu LTS has uv.** Fedora ships it only because FESCo's bundling policy
   permits `Provides: bundled(...)`. NixOS wrote the objection into the package description —
   uv's "(over)eager fetching of dynamically-linked Python executables" — and *rejected* the
   nix-ld auto-enable PR on philosophy.
   **Conclusion: "the target may already have uv" is a bad bet. Bundling uv is the right default.**
10. **Non-technical users are simply out of scope** for the whole pattern. pydevtools scopes it
    honestly: it fits "audiences that are comfortable running a shell command."

---

## Part 5 — Ideas to steal, ranked, with attribution

**Adopt now**

1. **Embed uv by default; make fetching the opt-in.** *(credit: PyCrucible — this is exactly its
   `--no-uv-embed` default-on-embed choice, and the inverse of pyapp's hard limitation.)*
   Already how haru-pack's default tier behaves; say where the idea is proven.
2. **PE resources, not a tail overlay, on Windows.** *(credit: uv itself, the hard way.)* uv's
   Windows trampoline appended a magic trailer and **signtool broke it** —
   `"Magic number 'UVSC' or 'UVPY' not found at the end of the file"`
   ([uv#15022](https://github.com/astral-sh/uv/issues/15022) →
   [PR #15068](https://github.com/astral-sh/uv/pull/15068), fixed by moving the payload into
   `.rcdata`). Chrome's `mini_installer` and Go's `embed` do the same. **This is the closest
   possible upstream failing at precisely the trick `research/04` recommends.** If we keep the
   overlay, parse the footer relative to the certificate-table offset (PE32 132 / PE32+ 148) and
   tolerate ≤7 bytes of osslsigncode alignment padding.
3. **Pin a SHA256 per artifact at build time, in resources, before signing; fail closed; delete
   the extracted tree on mismatch.** *(credit: Chrome/Omaha's CRX₃ + hardcoded key; the
   counter-example is pyapp, which verifies nothing and accepts `http://`.)* Near-zero cost, and
   it puts us strictly ahead of every incumbent. Note uv itself **skips hash verification when a
   metadata entry has no sha256** — supply our own table (vendor
   `crates/uv-python/download-metadata.json`).
4. **Never ship advisory-only verification.** *(credit: rustup 1.26.0, which deleted its GPG
   validation precisely because "validating the integrity of downloaded binaries did not rely on
   it, and there was no option to abort".)* Fail closed on day one or don't ship it.
5. **macOS: keep the launcher pure-exec — never `dlopen` libpython.** *(credit: Cereal_Killer's
   read of Apple's library-validation docs; the contrast is Briefcase/PyInstaller/Electron, which
   need `disable-library-validation` because they host Python in-process.)* Library validation is
   **in-process only**, so an exec-only launcher needs **no hardened-runtime exception
   entitlements at all** — and Apple runs *extra* Gatekeeper checks on programs that disable it.
   This is the single biggest architectural advantage available to us, and it's free.
6. **Ad-hoc `codesign --force --sign -` over the extracted tree on arm64**, mandatory after any
   Mach-O mutation. *(credit: uv, which merged exactly this in
   [PR #17123](https://github.com/astral-sh/uv/pull/17123) after uv#16003/#16726 — "simply
   removing the `com.apple.provenance` xattr is NOT sufficient".)* Failure mode is a bare
   `killed: 9` with no diagnostic.
7. **Keep the launcher's bytes stable across app versions and customers.** *(credit: Eric
   Lawrence, ex-MSFT/Chrome security.)* "Stub installers rarely need to be updated. That means a
   positive reputation on the Installer executable will persist for a long time (potentially
   years) even as you release new versions of the app being installed." A launcher rebuilt per
   project or per release earns **zero** hash reputation, every time. This argues for **one stable
   stub + external config**, and it cuts against baking per-project data into the stub.
8. **Download and extract synchronously inside the launcher process.** *(credit: Windows App
   Control / managed-installer docs.)* Origin claims propagate down a process tree and end when
   the tree breaks. A detached helper or post-exit extraction forfeits the inherited trust.
9. **Zip-slip defence in the unpacker.** *(credit: PyCrucible v0.4.8's CVE fix — the same bug
   class, in the same position, in the closest comparable tool.)*
10. **`uv venv --relocatable`** for the staged venv. *(credit: uv PR #5515 — undocumented outside
    the CLI reference.)*

**Adopt soon**

11. **Busybox mode — multiple entry points from one binary.** *(credit: `pex --scie-busybox`.)*
    Strictly better than hatch's N-separate-executables approach, and it composes with #7 (one
    stable stub).
12. **Content-addressed shared stage dir**, so two haru-pack apps on the same machine share one
    CPython. *(credit: `pex --scie`'s `~/.cache/nce/<hash>`; pyapp does the opposite for the
    install dir and the same for the uv cache.)* `research/04` already chose content-addressing —
    the open question is shared-across-apps vs per-app, and scie is the argument for shared.
13. **`hooks.pre_run` / `hooks.post_run` in the config.** *(credit: PyCrucible's
    `pycrucible.toml`.)* Cheap, and it generalizes our `post_install` steps.
14. **Pin a *list* of keys/publisher names from v1, with the flag-day migration designed up
    front.** *(credit: electron-updater's `publisherName: string | Array<string>` — "useful when
    rotating certificates" — and the six-issue graveyard behind it.)*
15. **A `.dmg`/`.pkg` container for macOS.** *(credit: Apple's own notarization docs.)* Bare
    Mach-O binaries can be notarized but **cannot be stapled**, so a quarantined copy on an
    offline Mac is blocked on first launch. This is a container decision to make now.
16. **CI must run `spctl --assess --type exec` *and* an actual smoke launch.** Those are the only
    two checks that catch a signed binary that cannot start, and notarization that didn't take.

**Consider / watch**

17. **A `uvx.sh`-style hosted one-liner** as haru-pack's *own* install path (`pip install
    haru-pack` today). *(credit: Astral's uvx.sh, and aider's `aider-install` shim.)*
18. **Anti-rollback, not just authenticity.** *(credit: Chrome's CUP threat model — "an attacker
    should not be able to trick a client into upgrading to an authentic but stale and vulnerable
    version".)* A pinned SHA256 does not stop replay of an older, validly-signed CPython with a
    known CVE.
19. **`mise generate tool-stub --bootstrap`'s two-stage shape** — a stub that installs uv
    system-wide and then delegates permanently. Nothing in Python does this; uv#10465 is the
    closest request and it's parked as a wish.
20. **`pixi-pack --create-executable`** as the reference for cross-platform packing of a resolved
    lockfile into a self-extracting artifact.
21. **Microsoft Store MSI/EXE submission path** — the only non-MSIX route to a genuinely
    warning-free first run.

**Non-negotiable invariants** *(detail and sources in Part 9)*

- **`--only-binary :all:` / `no-build = true` in every cross build.** uv's `--python-platform`
  selects *target* wheels but **silently builds any sdist for the *host***. pip refuses to start
  in this situation; uv just proceeds. Without this flag a Linux-built `.so` lands in a Windows
  bundle and the failure surfaces at the user's first run. **This is the highest-severity finding
  in the survey.**
- **Pin an exact python-build-standalone release tag; never track latest.** Release 20260320
  shipped `libpython3.14.so` with the executable-stack flag set (rejected on SELinux/hardened
  kernels); 20260310 was clean.
- **Never use a pbs release from before 2023** — those may link `readline`/GDBM and are therefore
  **GPLv3**. 2023+ builds use libedit and disable `_gdbm` specifically to avoid this.
- **Default to the baseline `x86_64` triple.** pbs's own docs: `x86_64_v3`/`v4` binaries "will
  crash if you attempt to run them on an older CPU."
- **Default uv to `--system-certs`** and propagate `SSL_CERT_FILE`. uv uses bundled Mozilla roots
  where pip 24.2+ uses the OS store — so on a TLS-intercepting corporate box `pip install` works
  and `uv` fails from the same shell. "But pip works" will be the top bug report.
- **Never emit `--index-strategy unsafe-best-match`**, and warn loudly on any generated
  `--extra-index-url`. uv's `first-index` default is what makes it dependency-confusion-safe;
  `unsafe-best-match` is pip's behaviour and is named "unsafe" for the `torchtriton` reason.
- **Ship `certifi`/`truststore` and set `SSL_CERT_FILE` for the staged interpreter.** pbs's
  compiled-in OpenSSL defaults are wrong on RHEL/UBI and NixOS in opposite directions.

**Explicitly reject**

- PyInstaller onefile's re-extract-every-launch (already rejected in `research/04`).
- UPX (invalidates signatures, trips heuristics).
- Advisory-only or fail-open verification (rustup, electron-updater pre-v28, dotnet-install's
  **file-size comparison**).
- Building on `war` (no binary encoding, no implementation).

---

## Part 6 — Honest differentiation, restated

`research/01` claimed three differentiators against pyapp. Two of them are also PyCrucible's.
What actually remains unique to haru-pack, as of 2026-09-09:

1. **Code signing as a designed-for property.** **Nobody in the Python-uv space has a signing
   story** — zero signing issues on pyapp, nothing in hatch's binary builder, nothing in
   PyCrucible, nothing in pyfuze. deno is the only comparable that treats it as a first-class
   concern. This is the strongest remaining differentiator and it should lead the README.
2. **Payload integrity.** pyapp verifies nothing and accepts `http://`; uv's own `install.ps1`
   verifies nothing. A pinned, fail-closed manifest is a real, cheap advantage.
3. **Cross-compilation from Linux to Windows, including `--thick`.** pyapp reaches parity only
   through `cross` containers, with the repo-relative-path constraint; PyCrucible has no
   documented cross flow. Our wheel-only thick cross plus `--wine` for exec-required steps is,
   as far as this survey found, unmatched in the Python space.
4. **An explicit tier model as a user-facing choice.** PEX has eager/lazy and PyCrucible has
   `--no-uv-embed`, but neither presents a three-tier ladder with cross-compile support stated
   per tier.
5. **Native PEP 723 ingestion.** Still holds — pyapp and PyCrucible are project/wheel oriented.
6. **Licensing / expiry / machine binding.** Out of scope for every tool surveyed.

**Not differentiators (drop these claims):** embedding uv, run-in-place extraction, staging a
standalone Python, content-addressed caching.

---

## Part 7 — Corrections to existing docs

- **`research/01`** — the pyapp gap list is right about pyapp but wrong about the field.
  PyCrucible already does uv-embedding and exe-adjacent extraction. Add PyCrucible, pyfuze and
  `pex --scie` to that document's prior-art section, or supersede it with this one.
- **`research/02`** — `UV_PYTHON_INSTALL_MIRROR` is the *wrong* air-gap knob to lead with: the
  per-platform asset filename suffixes are **compiled into the uv binary** and change most
  releases ([#10203](https://github.com/astral-sh/uv/issues/10203)), so a naive rehost breaks on
  every uv upgrade. Prefer **`UV_PYTHON_DOWNLOADS_JSON_URL`** (PR #10939, shipped uv 0.6.13;
  config key `python-downloads-json-url` in 0.7.3), and **do not combine the two**
  ([#17005](https://github.com/astral-sh/uv/issues/17005)). Everything else in `research/02`
  holds.
- **`research/04`** — the "append payload, then sign, scan backward for the magic" advice needs a
  Windows caveat: **uv tried it and signtool broke it** (uv#15022). Use PE resources on Windows.
  The scan-backward technique remains correct for ELF/Mach-O.
- **`docs/SIGNING.md:65` is factually wrong, and it is a spending decision.** It currently reads:
  *"**EV cert** → immediate SmartScreen reputation (the real reason to buy EV over OV)."*
  Microsoft Trusted Root Program requirements §3.D.3 says the opposite, normatively:
  > *"Starting February 2024, Microsoft will no longer accept or recognize EV Code Signing
  > Certificates… Beginning in August 2024, all EV Code Signing OIDs will be removed from
  > existing roots in the Microsoft Trusted Root Program, and **all Code Signing certificates
  > will be treated equally**."*

  The OID is gone from the roots — EV is not "slower to earn reputation", it is *not a
  distinct thing any more*. Corroborated independently by Eric Lawrence (ex-MSFT/Chrome
  security): "EV certificates are no longer treated specially by AppRep." `docs/SIGNING.md:79`
  and `docs/PLAN.md:223` repeat the same assumption ("a real EV cert fixes that"), and Tauri's
  own signing guide is stale in the same way — don't propagate it.

  **Action:** do not buy EV. Use OV, and choose **RSA, not ECC** (Smart App Control does not
  support ECC, and the Trusted Root Program excludes ECC and keys > 4096). Reputation comes from
  a stable stub hash and one long-lived identity (Part 5, #7), not from the certificate class.
  Cheap options: Azure Artifact Signing (no hardware token, CI/Linux-friendly via jsign),
  or SignPath Foundation if we go OSS. The **"EV-signable"** phrasing in `README.md:4`,
  `README.md:128` and `docs/PLAN.md:3` should become just "signable" — it is currently
  advertising a property that no longer means anything.
- **uv's `--native-tls` flag** was deprecated in uv 0.11.0 (March 2026) in favour of
  `--system-certs` / `UV_SYSTEM_CERTS`. **Checked: haru-pack does not use it.** The `native TLS`
  strings in `src/haru_pack/launcher/uvfetch.nim:2` and `docs/TIERS.md:13` refer to puppy's
  OS-native TLS stack in the Nim launcher, which is unrelated. Noted only so nobody "fixes" it.

---

## Part 8 — Open questions

- Does Omaha-style tagging inside the certificate directory survive `EnableCertPaddingCheck`
  (CVE-2013-3900)? Unresolved; check before copying that trick.
- Does the PUA "bundling" criterion match haru-pack? Microsoft's two pages word it differently —
  the criteria page's "**or not required for the software to run**" exculpates us; the Defender
  PUA page's "isn't digitally signed by the same entity" is a literal match. Consumer PUA
  protection defaults to **Audit, not Block**, absent Defender for Endpoint. Worth an actual
  Microsoft answer.
- Do `install_only` p-b-s archives carry license texts? This is a redistribution obligation —
  extract one and check.
- Windows SDK EULA re: redistributing CRT bits — needs a human legal read.
- Nim-produced Mach-O: does it carry a valid `LC_BUILD_VERSION`? Notarization requires it, and
  `ilastik/app-pass` exists because tooling omits it. Verify on a cross-built artifact.
- Nim AV false-positive rate on *our* artifacts is unproven in both directions — do a VirusTotal
  spot-check on a real build.

---

## Part 9 — The substrate: what the prior art learned the hard way

Sharp edges in the layers haru-pack delegates to. Everything here is sourced; the items that
change a design decision are marked **⚠**.

### 9.1 python-build-standalone

**Stewardship.** Astral maintains it; Szorc handed off the umbrella but stated in 2024-03 that
"PyOxidizer and all the projects under its umbrella are effectively in a zombie state… I still
actively support python-build-standalone." Worth watching:
[python/prebuilt-cpython](https://github.com/python/prebuilt-cpython) — an official CPython effort
to ship prebuilt binaries for all tier-1 platforms via python.org, with pbs and BeeWare as named
representatives. Planning-phase only, but it is the thing that could obsolete pbs as our source.

**⚠ Licensing.** pbs's own docs:

> "Notable exceptions to this are GDBM and readline, which are both licensed under GPL Version 3.
> We build CPython against libedit — as opposed to readline — to avoid this GPL dependency…
> **Distribution releases before 2023 may link against readline and are therefore subject to the
> GPL.** … **Distribution releases before 2023 may link against GDBM and be subject to the GPL.**"

Pin a ≥2023 release and we are GPL-free. Separately: `install_only` archives are built by
rewriting `python/install/*` → `python/*`, and **"all files not under `python/install/*` are not
carried forward"** — which includes `PYTHON.json`, the file that carries the licensing metadata.
**Open obligation:** extract one and check whether license texts survive; if not, vendor them at
build time. (Listed in Part 8.)

**⚠ Platform selection.** `x86_64_v3`/`v4` binaries "will crash if you attempt to run them on an
older CPU not supporting the newer instructions." Windows minimums: CPython 3.14+ needs Win10+,
≤3.13 supports 8.1+. Linux glibc ≥2.17 (2.28 riscv64). Non-x86_64/aarch64 targets are
cross-compiled on x86_64 and "not as highly optimized"; pbs also states "the entire Python test
harness is not run on a regular basis" and publishes no stability guarantee or deprecation policy.

**⚠ Pin an exact tag.** Release 20260320 shipped `libpython3.14.so` with the **executable-stack
flag set** — rejected on SELinux/hardened kernels, flagged by scanners. 20260310 was clean. It
went unnoticed because only embedders broke ([pbs#1061](https://github.com/astral-sh/python-build-standalone/issues/1061)).

**Relocatability — this is the real story.** `_sysconfigdata_*.py`, Makefiles and `PYTHON.json`
embed build-infrastructure absolute paths. pbs's docs: *"When installed by uv, these absolute
paths are fixed up to point to the actual location on your system, so this quirk generally does
not affect uv users."* → **let uv do the install, or inherit the fixup work.** Anything calling
`sysconfig.get_paths()` — build backends, source builds of C extensions — sees garbage otherwise.
Third-party fixer if we ever need it: [`sysconfigpatcher`](https://github.com/bluss/sysconfigpatcher).

**Windows CRT.** `PYTHON.json`'s `crt_features` records the vcruntime version. Historically the
DLLs were **stripped** from the archives; release **20251120**'s changelog says *"MSCV runtime
DLLs are no longer stripped on windows."* → **pin pbs ≥ 20251120 and app-local `vcruntime140.dll`
ships with the interpreter.** Below that we must supply it. Note the UCRT is a Windows OS
component and is always present on Win10+; only the VC++ redistributable part is our problem.

**⚠ The SSL cert bundle is a first-run failure *inside our own app*.**
[uv#16703](https://github.com/astral-sh/uv/issues/16703): a uv-managed Python on RHEL/UBI8 reports
`cafile=None, capath='/etc/ssl/certs'` while the distro Python on the same box correctly reports
`/etc/pki/tls/cert.pem` — so HTTPS from the staged Python fails. NixOS has the mirror image.
**Ship `certifi`/`truststore` and set `SSL_CERT_FILE` explicitly.**

**Other quirks that reach users:** terminfo not found → broken REPL arrows in stripped containers
(set `TERMINFO_DIRS`); libedit not readline on Linux 3.10+ (subtle behavioural differences); **no
`Scripts/pip.exe` on Windows** because "the way these executables are built isn't portable" — so
any shim we generate must not assume console-script `.exe`s exist. **Tkinter is a moving target:**
as of Aug 2025 pbs split `_tkinter`, `libtcl8.6` and `libtk8.6` into separate dynamic libraries
relying on `DT_RPATH`/`LC_RPATH` into `lib/` — **both break if we flatten or relocate the
directory layout.** If we support tkinter apps, preserve pbs's layout verbatim, set
`TCL_LIBRARY`/`TK_LIBRARY`, and add a smoke test.

**Signing gap, restated precisely:** the staged **uv** is signed and notarized as of 0.12.12; the
staged **CPython is not** — pbs docs and release notes never mention signing, notarization or
attestations. Re-signing it on macOS hits
[pbs#749](https://github.com/astral-sh/python-build-standalone/issues/749) (`codesign -f -o
runtime` on `_tkinter` fails, insufficient headerpad). This is why Part 5 #6 recommends *ad-hoc*
signing only.

### 9.2 Cross-compilation — the highest-severity finding

**⚠ `--python-platform` silently builds sdists for the host.** uv's own CLI help:

> "**WARNING: When specified, uv will select wheels that are compatible with the *target*
> platform; as a result, the installed distributions may not be compatible with the *current*
> platform. Conversely, any distributions that are built from source may be incompatible with the
> *target* platform, as they will be built for the *current* platform.** The `--python-platform`
> option is intended for advanced use cases."

**pip refuses to start in this situation** (`check_dist_restriction`: "either `--no-deps` must be
set, or `--only-binary=:all:` must be set"). **uv just proceeds.** A Linux-built `.so` goes into
the Windows bundle, no error, failure at the user's first run.

**→ `--only-binary :all:` / `no-build = true` must be a non-optional invariant of every haru-pack
cross build.** It converts silent corruption into a loud failure.

**Checked against our code: we are currently correct.** `--python-platform` appears exactly once,
in `warm_cache_windows()` at `src/haru_pack/bundle.py:144-146`, and that call already passes
`--only-binary :all:` alongside `--python-version`. The risk is regression, not a present bug —
**any future `--python-platform` call site must carry it**, so this belongs in a test or a helper
that refuses to build the argv without it, not in a docstring.

Two related limits: uv's resolver is best-effort on markers — "Python's environment markers expose
far more information about the current machine than can be expressed by a simple
`--python-platform` argument… may lose fidelity for complex package and platform combinations."
And a **dynamic-metadata sdist forces a local PEP 517 build during a cross resolve**, because uv
only builds when it can't find static metadata. `required-environments` is the only mechanism that
*asserts* "a Windows wheel must exist"; `environments` narrows scope instead. Version-splitting
across platforms (a package whose Windows and Linux wheels exist at different versions) is
**open and unsolved** — [uv#13332](https://github.com/astral-sh/uv/issues/13332),
[#9711](https://github.com/astral-sh/uv/issues/9711).

**⚠ `--wine` is the documented industry workaround, not a hack.** Everyone else refuses to
cross-compile, and two of them point at Wine explicitly:

| Tool | Verdict |
|---|---|
| **PyInstaller** | Refuses. FAQ: *"No, this is not supported. **Please use Wine for this, PyInstaller runs fine in Wine.**"* |
| **cx_Freeze** | Refuses, blesses Wine: *"Starting with version 8.0… creating executables in Wine is possible with **no difference compared to Windows**."* |
| **PyOxidizer** | Refuses: *"Cross compiling is not yet supported."* Project is a zombie. |
| **conda constructor** | Refuses — "OS-native tools are needed to generate the Windows `.exe` files." |
| **pyapp** | Supports it, via `cross` containers, with the repo-relative-path constraint. |
| **Nuitka** | No documented cross mode in either direction (negative finding, unverified). |

**⚠ Legal loose end:** if we obtain MSVC CRT bits via `xwin`/`cargo-xwin`, note cargo-xwin's own
disclaimer — *"By using this software you are consented to accept the license at
go.microsoft.com/fwlink/?LinkId=2086102"* (the Windows SDK EULA). Whether that permits
redistributing CRT bits inside a shipped artifact **needs a human legal read**. A
`*-pc-windows-gnu` (MinGW) launcher sidesteps xwin entirely.

### 9.3 First-run-fetch failure modes at scale

**⚠ Corporate TLS: uv fails where pip works.** uv uses **bundled Mozilla roots** by default (rustls
+ aws-lc-rs), *not* the OS trust store. pip **24.2+** goes the other way, using system certificates
by default via `truststore`. On a Zscaler/Netskope box, `pip install` succeeds and `uv` fails from
the same shell. The fix is `--system-certs` / `UV_SYSTEM_CERTS`, or `SSL_CERT_FILE` /
`SSL_CERT_DIR` / `SSL_CLIENT_CERT`. "uv does not use `/etc/ssl/certs/ca-certificates.crt`" was
closed **not planned** ([uv#12871](https://github.com/astral-sh/uv/issues/12871)).
**Default to `--system-certs` and put the remediation string in our error message.**

**⚠ Kerberos/NTLM proxies are a hard wall.** [uv#11494](https://github.com/astral-sh/uv/issues/11494)
(open, `wish`): *"Enterprise environments often have a proxy with Kerberos authentication. **This
is currently not supported in reqwest**"* — blocked upstream on reqwest#953. **On a
Kerberos-authenticated egress proxy a uv-based first-run fetch cannot succeed, period.** This is
the strongest argument that **thick should be the default tier for enterprise targets**, not an
option. Also raise `UV_HTTP_TIMEOUT` (default 30s) on flaky corporate links.

**⚠ The definitive thin-tier argument, twelve days before this survey.** PyPI's
[File Hosting Errors](https://blog.pypi.org/posts/2026-09-08-file-hosting-errors/) incident,
**Aug 15–28 2026**: two weeks of intermittent 502/503s from `files.pythonhosted.org`, caused by a
partial canary rollback leaving one Seattle POP's caching config reverted while routing was not —
plus pre-existing Fastly bugs in fallback routing and **range-request handling**. Diagnosis hinged
on a single user reporting one cache node.

A single POP misbehaving produced two weeks of *intermittent, geographically localized,
vendor-unreproducible* install failures. Our stub looks broken to the end user and is undebuggable
by us. **And note the range-request angle: if the stub does ranged or resumable downloads, it
inherits that bug class specifically.**

**PyPI tells us not to do this at scale.** Their API docs: *"If your consumer is actually an
organization or service that will be downloading a lot of packages from PyPI, **consider using
your own index mirror or cache**."* The AUP reserves the right to throttle "significantly
excessive" usage. **A widely adopted thin tier turns every end-user machine into a PyPI client.
Document that as a stated scaling limit of the tier.**

**⚠ Dependency confusion — why uv's default matters.** The canonical incident is PyTorch's
`torchtriton`, Dec 2022, with a [first-party postmortem](https://pytorch.org/blog/compromised-nightly-dependency/):

> "**Since the PyPI index takes precedence, this malicious package was being installed instead of
> the version from our official repository.**"

Payload exfiltrated `/etc/passwd`, `~/.gitconfig`, `~/.ssh/*` and the first 1,000 files in `$HOME`
over encrypted DNS. uv's default `first-index` strategy prevents this; `unsafe-best-match` is
pip's behaviour and is named "unsafe" for exactly this reason. **Never emit it.**

**⚠ Playwright is the worst-case first-run fetch, and it is unauthenticated.** From the source
(`registry/index.ts`, `browserFetcher.ts`): three rotating CDN mirrors, 5 retries — and **no hash,
checksum or signature verification of the downloaded browser archive.** The only post-download
validation is a marker-file existence check. Disk usage 281M chromium / 187M firefox / 180M
webkit. `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD` is real but undocumented on the current browsers page.
**Two traps for us:** pointing `PLAYWRIGHT_DOWNLOAD_HOST` at a mirror is an unauthenticated-content
trust decision, so *we* must verify; and **unused browsers are auto-reaped** unless
`PLAYWRIGHT_SKIP_BROWSER_GC=1` — a haru-pack bundle that vendors browsers into the shared cache
can have them deleted by an unrelated Playwright install. Version coupling is hard: *"If the
Playwright version in your Docker image does not match the version in your project/tests,
Playwright will be unable to locate browser executables."*

**Neighbours, for calibration:** rustup's own security page says it *"does not validate signatures
of downloaded toolchains"* and is "secure enough for most people, but it still needs work"; nvm has
mirror env vars and `--offline` but **no corporate-proxy or air-gap section at all**.

### 9.4 Overlay vs signature — the spec answer

Read from the *Windows Authenticode Portable Executable Signature Format* v1.0 spec directly.
The PE hash omits the Checksum field, the 8-byte Certificate Table data-directory entry, and the
Attribute Certificate Table itself — "because they are modified by the act of adding an
Authenticode signature." Step 14 of the hashing procedure is the whole answer:

> "If `FILE_SIZE` is greater than `SUM_OF_BYTES_HASHED`, the file contains extra data that must be
> added to the hash. This data begins at the `SUM_OF_BYTES_HASHED` file offset, and its length is:
> `(File Size) – ((Size of AttributeCertificateTable) + SUM_OF_BYTES_HASHED)`"
> "…specified in the second ULONG value in the Certificate Table entry (**32 bit: offset 132,
> 64 bit: offset 148**)."

| Placement | In the hash? | Signature survives? |
|---|---|---|
| **(a)** Overlay at EOF, appended **after** signing | **Yes** | **NO — breaks** |
| **(b)** Smuggled in the WIN_CERTIFICATE PKCS#7 **padding** | No | Survives — **unless `EnableCertPaddingCheck`**; this is CVE-2013-3900 |
| **(c)** Extra **unauthenticated attributes** in the PKCS#7 | No | Survives — the legitimate channel |
| **(d)** Payload appended **before** signing | **Yes** | **YES — the correct design** |

**⚠ The exact historical attack was signed downloader stubs — our architecture.** Eric Lawrence:

> "In December 2013, Microsoft announced that some developers had foolishly used this trick to
> store URLs of code that would be downloaded and installed by a signed 'stub' installer. The bad
> guys noticed that they could edit these 'stub' installers, changing the embedded URLs to point
> to malware, and the signature of the stub wouldn't change."

His best-practice list is worth following literally: don't do it at all; if you must, sign the data
block yourself and reject it if it doesn't validate; **"if the data contains URLs to other code,
validate that code's signature when it is downloaded."** That last line is Part 5 #3, written in
2013. Microsoft Advisory 2915720 confirms the check remains **opt-in and off by default** —
enforcement was announced for June 2014, slipped to August, then cancelled ("the impact to
existing software could be high") — and warns that non-Microsoft signing tools carry a risk of
producing non-compliant signatures. Note the advisory also flags that *"binaries most likely to be
affected are PE installer files distributed via the Internet that are customized at time of
download"* — i.e. exactly a per-project stub.

**⚠ The implementation detail that will bite us: alignment padding.** osslsigncode's `pe.c` pads
the file to an 8-byte boundary before appending the PKCS#7 blob (`len = 8 - fileend % 8`), and pads
the blob itself. **After signing, our payload is followed by up to 7 zero bytes and then the entire
certificate table.** A footer parser assuming "magic at `EOF − sizeof(footer)`" **breaks the moment
we sign** — which is precisely what happened to uv (uv#15022). Either read the certificate-table
offset from the optional header and treat that as effective EOF (tolerating ≤7 padding bytes), or
scan backwards for the magic, as `research/04` already specifies and as PyInstaller had to do.

**⚠ On macOS a tail overlay is not an option at all.** PyInstaller: *"Appending data at the end of
executable breaks the Mach-o format structure"* — `codesign` reports `__LINKEDIT segment does not
cover the end of the file`. `LC_CODE_SIGNATURE` data lives at the end of `__LINKEDIT`, which must
be last. **Use a `.app` bundle with the payload as a resource, or a Mach-O section.** (Related
constraint if we ever ship universal binaries: `lipo`-merging two PyInstaller onefile executables
produces a binary that still runs on only one platform, because the bootloader finds only the last
embedded archive.)

**Placement prior art:** Chrome's `mini_installer` stores its payload as **PE resources**
(`kLZMAResourceType`, `kBinResourceType`, …) — inside a section, fully covered by the hash, no tail
scanning at all. Go's `embed` has the same property. NSIS, 7-Zip SFX and AppImage all append an
overlay and all work only because you **sign last**; AppImage additionally reserves ELF sections
(`.sha256_sig`, `.sig_key`) for its own independent signature. The general zip-append trick works
because zip is read from the end while PE is parsed from the start.

**Signing a PE from Linux** is well supported: `osslsigncode` (PE/CAB/CAT/MSI/APPX, PKCS#11 tokens
and networked HSMs; **no Mach-O**) and `jsign` (platform-independent, Azure Artifact Signing, AWS
and Google KMS, DigiCert ONE). Both carry Advisory 2915720's non-Microsoft-tooling caveat.

> **The rule, once:** emit the stub → embed or append the payload → **sign last**. On Windows
> prefer **PE resources**. If keeping an overlay, parse relative to the certificate-table offset.
> On macOS, no tail overlay.

---

## Sources

Astral: [uv docs](https://docs.astral.sh/uv/) · [uv#5802](https://github.com/astral-sh/uv/issues/5802) ·
[uv#14727](https://github.com/astral-sh/uv/issues/14727) · [uv#10465](https://github.com/astral-sh/uv/issues/10465) ·
[uv#15022](https://github.com/astral-sh/uv/issues/15022) · [astral-sh/war](https://github.com/astral-sh/war) ·
[python-build-standalone](https://github.com/astral-sh/python-build-standalone) · [uvx.sh](https://uvx.sh/) ·
[open source security at Astral](https://astral.sh/blog/open-source-security-at-astral)

Launchers: [pyapp](https://github.com/ofek/pyapp) + [docs](https://ofek.dev/pyapp/latest/) ·
[PyCrucible](https://github.com/razorblade23/PyCrucible) · [pyfuze](https://github.com/TanixLu/pyfuze) ·
[pex scie](https://docs.pex-tool.org/scie.html) · [a-scie/lift](https://github.com/a-scie/lift) ·
[posy](https://github.com/njsmith/posy) · [Hatch binary builder](https://hatch.pypa.io/latest/plugins/builder/binary/)

Adjacent: [mise tool-stub](https://mise.jdx.dev/cli/generate/tool-stub.html) ·
[hermit](https://github.com/cashapp/hermit) · [pixi trampolines](https://pixi.prefix.dev/latest/global_tools/trampolines/) ·
[pixi-pack](https://github.com/quantco/pixi-pack) · [deno compile](https://docs.deno.com/runtime/reference/cli/compile/)

Field: [aider on uv](https://aider.chat/2025/01/15/uv.html) ·
[Trey Hunner, self-installing scripts](https://treyhunner.com/2024/12/lazy-self-installing-python-scripts-with-uv/) ·
[Josh Cannon, remote single-file scripts](https://joshcannon.me/2025/04/24/remote-single-file-scripts.html) ·
[pydevtools, shipping to end users](https://pydevtools.com/handbook/explanation/how-do-i-ship-a-python-application-to-end-users/) ·
[Hynek, uv in Docker](https://hynek.me/articles/docker-uv/)

Substrate (Part 9): [pbs quirks](https://gregoryszorc.com/docs/python-build-standalone/main/quirks.html) ·
[pbs running/licensing](https://gregoryszorc.com/docs/python-build-standalone/main/running.html) ·
[pbs distributions](https://raw.githubusercontent.com/astral-sh/python-build-standalone/main/docs/distributions.rst) ·
[pbs status](https://gregoryszorc.com/docs/python-build-standalone/main/status.html) ·
[python/prebuilt-cpython](https://github.com/python/prebuilt-cpython) ·
[uv resolution concepts](https://docs.astral.sh/uv/concepts/resolution/) ·
[uv indexes / dependency confusion](https://docs.astral.sh/uv/concepts/indexes/) ·
[uv certificates](https://docs.astral.sh/uv/concepts/authentication/certificates/) ·
[uv build failures](https://github.com/astral-sh/uv/blob/main/docs/reference/troubleshooting/build-failures.md) ·
[uv#11494 Kerberos proxies](https://github.com/astral-sh/uv/issues/11494) ·
[PyPI file hosting incident, Aug 2026](https://blog.pypi.org/posts/2026-09-08-file-hosting-errors/) ·
[PyPI API guidance](https://docs.pypi.org/api/) ·
[PyTorch torchtriton postmortem](https://pytorch.org/blog/compromised-nightly-dependency/) ·
[pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/) ·
[Playwright browsers](https://playwright.dev/docs/browsers) ·
[PyInstaller FAQ (cross-compilation)](https://github.com/pyinstaller/pyinstaller/wiki/FAQ) ·
[cx_Freeze FAQ (Wine)](https://cx-freeze.readthedocs.io/en/stable/faq.html) ·
[PyOxidizer status](https://pyoxidizer.readthedocs.io/en/stable/pyoxidizer_status.html) ·
[cargo-xwin](https://github.com/rust-cross/cargo-xwin)

Signing: [Microsoft Trusted Root Program requirements](https://learn.microsoft.com/en-us/security/trusted-root/program-requirements) ·
[Authenticode PE Signature Format v1.0](https://www.symbolcrash.com/wp-content/uploads/2019/02/Authenticode_PE-1.pdf) ·
[Understanding PE signatures](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures) ·
[Advisory 2915720 (CVE-2013-3900)](https://learn.microsoft.com/en-us/security-updates/SecurityAdvisories/2014/2915720) ·
[Eric Lawrence, caveats for Authenticode signing](https://learn.microsoft.com/en-us/archive/blogs/ieinternals/caveats-for-authenticode-code-signing) ·
[osslsigncode](https://github.com/mtrojnar/osslsigncode) · [jsign](https://ebourg.github.io/jsign/) ·
[Chrome mini_installer](https://chromium.googlesource.com/chromium/src/+/main/chrome/installer/mini_installer/mini_installer.cc) ·
[PyInstaller macOS signing recipe](https://github.com/pyinstaller/pyinstaller/wiki/Recipe-OSX-Code-Signing) ·
[rustup security](https://rust-lang.github.io/rustup/security.html) ·
[Eric Lawrence on SmartScreen AppRep](https://textslashplain.com/2024/11/15/best-practices-for-smartscreen-apprep/) ·
[Smart App Control code signing](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control) ·
[App Control managed installer](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph) ·
[Apple: disable-library-validation](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.disable-library-validation) ·
[Apple DTS on quarantine](https://developer.apple.com/forums/thread/706442) ·
[Apple: customizing notarization](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow) ·
[Omaha tagged metainstallers](https://github.com/google/omaha/blob/main/doc/TaggedMetainstallers.md) ·
[Chrome updater functional spec](https://chromium.googlesource.com/chromium/src/+/main/docs/updater/functional_spec.md) ·
[rustup 1.26.0 release notes](https://blog.rust-lang.org/2023/04/25/Rustup-1.26.0/) ·
[SignPath Foundation](https://signpath.org/)

### Confidence notes

Everything above with an inline URL was fetched from a primary source by one of the four agents.
Flagged as **unverified or secondary**, do not cite as fact:

- Astral joining OpenAI (2026-03-19) and pyx winding down (2026-06) — the *signals* are primary
  (Astral's blog index; `astral.sh/pyx` signup notice; `docs.astral.sh/pyx` 404) but the
  narratives are secondary reporting. Neither changes any haru-pack decision.
- Whether uv hard-fails or merely logs on a p-b-s SHA256 mismatch — inferred from source reading,
  not doc-confirmed.
- SmartScreen reputation loss on certificate renewal — practitioner reports plus an
  **AI-generated** Microsoft Learn answer. Treat Learn Q&A as unreliable on this topic;
  Microsoft's own Artifact Signing FAQ and developer docs contradict each other on submission.
- Whether Arch or Alpine patch out uv's self-update or managed-Python downloads — their build
  files were 403 to the agents.
- Reddit was hard-blocked to all four agents, so there are no r/Python citations here — a real
  gap for the "can't use a terminal" end of the user spectrum.
- All four agents exhausted the session's 200-call WebSearch budget; later verification was
  direct URL fetches only.

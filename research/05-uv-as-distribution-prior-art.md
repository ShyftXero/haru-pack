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

Signing: [Microsoft Trusted Root Program requirements](https://learn.microsoft.com/en-us/security/trusted-root/program-requirements) ·
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

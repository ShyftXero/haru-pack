# flex harness — does haru-pack handle real packages?

```sh
python tools/flex-run.py --list top25       # breadth
python tools/flex-run.py --list hard_targets -j 4
python tools/flex-run.py --only numpy       # one package
python tools/flex-run.py --dry-run          # what would run
```

Results land in `flex/out/results.json` and a summary table on stdout. Exit code is
non-zero if anything came out other than expected.

## It runs in a container, because it runs strangers' code

This harness downloads code chosen by PyPI download rank — not by audit — and executes it,
at three points: sdist build backends under `uv sync`, the binary the build produces, and
any `[[bundle]]`/`[[post_install]]` step in the manifest. Every package gets its own
throwaway containers, so a poisoned one cannot reach `$HOME`, your keys, or the next
package's result (`INV-SANDBOX-01`, `docs/adr/0005-sandboxed-flex-and-exam-harnesses.md`).

Two containers per package: the **build** gets the network and the shared cache, the **run**
gets a throwaway cache of its own and — at thick — no network interface at all. The run phase
never sees the shared cache, so one package cannot leave anything behind for the next one to
find.

The image (`docker/flex.Dockerfile`) carries the toolchain and is built on first use. It is
tagged with a hash of the Dockerfile plus `pins.toml`, so bumping a pin rebuilds it. Your
working tree is bind-mounted read-only at `/src`, so flex tests the code you are editing
rather than a copy baked in whenever the image was last built.

```sh
python tools/flex-run.py --require-rootless   # refuse a rootful daemon (docs/ROOTLESS_DOCKER.md)
python tools/flex-run.py --no-docker          # run it on THIS host; prints what that risks
```

There is no silent fallback: if docker is missing and you did not pass `--no-docker`, flex
stops and tells you. The first hard thing to get right about a safe default is that it stays
the default.

## What it does

For each package: build a tiny project that depends on it, then **run the resulting binary**
and require it to print `FLEX_OK`. The entrypoint is `python -m flexapp`, so stdout comes
from a module that had to be importable inside the packaged environment.

Running it is the point. A binary that builds and then dies on startup is a failure, and
only executing it catches that.

## Three rungs, and flex owns the first two

| style | what a pass proves | how |
|---|---|---|
| `importable` | the payload carries a library that **imports** | default |
| `smoke` | the library does one small **real thing** | `--style smoke` |
| `suite` | the library passes its **own test suite** | `tools/exam.py` |

`importable` is the default because it has exactly one failure mode, and it is the one this
harness exists to detect. The `smoke` bodies are hand-written per package in
`flex/curation.toml`, which makes each one a second thing that can break for reasons that
have nothing to do with packaging — an API moved, a keyword was removed, the package wants a
display. When that happened the run said "flex failed" and somebody had to read a traceback
to find out whether haru-pack had done anything wrong at all.

That is a narrowing, and it costs something real: a default run no longer exercises the
library. `--style smoke` and `tools/exam.py` are still there when you want the stronger claim.

The style is recorded in `flex/out/results.json` and printed in the summary header. An
`importable` pass and a `smoke` pass are different claims, and results that do not say which
one they hold invite comparing two runs that were never asking the same question.

## The import name is discovered, never guessed

`pip install pillow` gives you `import PIL`. Nothing recovers that from the name, which is
why `flex/curation.toml` used to carry eight hand-written `import_name` entries — eight human
guesses, each able to go stale without anyone noticing.

The `importable` probe asks the installed distribution instead, from inside the binary, where
it actually exists. Three routes, best first, and **the route is reported** so a guess never
reads as a fact:

| route | means |
|---|---|
| `packages_distributions` | exact: installed metadata, inverted. 3.10+ |
| `top_level.txt` | the wheel said so. Back to 3.8; absent from some wheels |
| `guess` | `name.replace("-", "_")`. Wrong for pillow, and it says so |

Curated `import_name` values are now **assertions**, not inputs: the harness checks each one
against what the binary found and fails the package on a mismatch, naming both and saying the
manifest is what is stale (`INV-FLEX-03`). They cannot steer the probe — if they could,
checking the probe against them would be a tautology.

```
resolved pyyaml -> _yaml, yaml (via packages_distributions)
successfully imported _yaml
successfully imported yaml
```

Each module is attempted in its own `try/except/finally`: the `except` prints the **full
traceback**, because that output is the only artefact left to dig into once the container is
gone, and per-module means a package with several top-level modules tells you *which* one
broke rather than just that something did.

## Keeping the caches off your disk

```sh
python tools/flex-run.py --cache-info            # what is using what
python tools/flex-run.py --flush-cache sandbox   # remove the harness's docker volume
python tools/flex-run.py --flush-cache host      # `uv cache prune` on the shared host cache
python tools/flex-run.py --max-cache-gb 20 ...   # prune the volume before a run if over
```

Measured on the dev box, which moved this design — the sandbox volume was **not** the problem:

| what | size |
|---|---|
| `~/.cache/uv` | **18.9 GB** |
| `haru-flex-cache` (sandbox volume) | 13.5 MB |
| `~/.cache/haru-pack` | 273 MB |
| anonymous run volumes | 0 — `--rm` reaps them |

The volume stays small because `warm_cache_and_lock` points `UV_CACHE_DIR` at the payload's
own bundled cache inside the build tree, not at ours.

Ownership decides what may be reclaimed automatically. The volume is the harness's own and
rebuildable, so `--max-cache-gb` may remove it. `~/.cache/uv` is shared with every project on
the machine and most of it has nothing to do with flex, so it is only ever reported, and only
ever *pruned*, and only when you type `--flush-cache host`. `--max-cache-gb` never touches it.

## Proving the payload carries its dependencies

```sh
python tools/flex-run.py --tier thick --offline-check
```

At the **default** tier the dependency is fetched on first run, so a green result proves the
packaging path and nothing about what the binary contains. At `--thick` the payload is
supposed to carry uv, the interpreter and every dependency.

`--offline-check` runs the thick binary a second time in a container with **no network
interface** and a **cache volume that has never been used**. The pristine cache is
load-bearing: with a warm one the staged tree is reused and the run succeeds no matter what
the payload holds. The summary column reads `carried` or `FETCHED`.

This is a real network namespace (`INV-SANDBOX-02`). It used to force uv offline and point
the proxy variables at a dead port, and this page used to say so: that blocked the
dependency-fetch path but did not stop a package opening a socket of its own. `--network
none` does.

A green offline check still means "the dependencies came from the payload", not "this binary
makes no network calls" — the second is a claim about the package's behaviour, and this
harness does not measure it.

Run with `--no-docker` and the offline check falls back to the old approximation, because
the host cannot create a network namespace. Those results print as `carried*` rather than
`carried`, so the weaker evidence is not read as the stronger.

Measured here, `certifi` at each tier:

| tier | size | offline |
|---|---|---|
| default | 23.2 MB | fetches deps on first run, by design |
| thick | 59.7 MB | `carried` |

## Two lists, different questions

| List | Question | Expectation |
|---|---|---|
| `top25` | Does haru-pack handle ordinary dependencies? | Should pass. A failure is a regression in normal packaging. |
| `hard_targets` | Does it handle the shapes that break packaging tools? | Mixed, on purpose. Some are `expect_failure`. |

The top-25 is the public number and it is mostly pure-Python wheels — packages that were
never going to be hard. The hard targets are where the tool earns its keep: browser
binaries (`playwright`), post-install downloads (`spacy`, `nltk`, `tiktoken`,
`transformers`), giant native wheels (`torch`), runtime driver fetches (`selenium`), and
system libraries pip cannot bundle (`weasyprint`).

`weasyprint` is marked `expect_failure`. It needs pango and cairo. Failing is the correct
result; an unexpected **pass** is the interesting direction and shows as `XPASS`.

## Coverage: where we are, and the target

**Target: the top 100 most-downloaded PyPI packages.** That is the breadth bar haru-pack is
aiming to clear — if the hundred packages the ecosystem pulls most all pack and run, "handles
ordinary dependencies" stops being a claim and becomes a checked fact.

**Where we are — 25 of 100, as of 2026-09-11** (ranking snapshot 2026-09-01). The `top25`
list is ranks 1–25 of the download ranking:

| | | | | |
|---|---|---|---|---|
| 1. boto3 | 2. packaging | 3. typing-extensions | 4. certifi | 5. idna |
| 6. urllib3 | 7. requests | 8. charset-normalizer | 9. cryptography | 10. cffi |
| 11. pluggy | 12. pygments | 13. pyyaml | 14. botocore | 15. python-dateutil |
| 16. six | 17. pydantic | 18. numpy | 19. click | 20. pycparser |
| 21. anyio | 22. pytest | 23. pydantic-core | 24. iniconfig | 25. aiobotocore |

Ranks **26–100 are not yet in the matrix**. The eight `hard_targets` are a separate, harder
axis (see below) and are *not* part of the top-100 count.

### The bar is "does it work", not "does it import"

Most of these packages are libraries, not applications: `requests`, `six`,
`typing-extensions` do nothing an end user sees directly. Bundling one and checking that
`import` succeeds is the shipping-a-game-and-never-playing-it trap — a syntactically valid,
runnable binary proves nothing about whether the *library* survived packaging. `import numpy`
succeeds long before numpy is usable; the failure modes of a packed library live in the parts
an import never touches (a lazily-loaded `.so`, a data file, a compiled extension).

So a package is exercised by running **something that uses it** from inside the delivered
binary, strongest first:

| method | what it proves | maintenance |
|---|---|---|
| **sit the exam** — the package's OWN test suite as the entrypoint (`examiner`, INV-TIER-01) | the library *works* after packaging, not merely imports | **none** — no bespoke script; it is the package's own suite |
| bespoke `smoke` in `curation.toml` | one hand-picked real operation ran | a script per package — the thing we are moving *away* from |
| import-and-version fallback | the module loaded | none, but it is the weak bar above |

**Where the exam stands today (2026-09-11): 2 of the 25 sit a real exam** — `numpy`
(2175 passed inside the binary) and `certifi`. The other 23 fall back to a bespoke smoke or
import-and-version. Not because the suite is uninteresting but because **their tests are not
in the wheel** — checked 2026-09-10, only numpy and certifi ship a runnable suite in the
built wheel. Everyone else's suite lives in the **sdist**.

### Closing the gap — `tools/exam.py`, and the proof page

The sdist acquisition path exists: **`tools/exam.py`**. For each top-N package it fetches the
sdist (its tests ride along, not just the wheel), finds the test tree wherever it lives
(`tests/`, `testing/`, or a bare `test_*.py` at the root), ships that whole tree — fixtures
included — into a thick app whose entrypoint runs the package's own suite, installs the test
extras the package *declares* (not a guessed set), and runs the binary offline. A pass means
the payload carried a working library, not an importable one.

```sh
python tools/exam.py refresh     # rank/version/repo-url for the top-N (network)
python tools/exam.py run         # sit the exam for each; write flex/exam-results.json
python tools/exam.py emit        # render top_n_pypi_stats.md from the ledger (offline)
```

The result is a git-tracked proof page, [`top_n_pypi_stats.md`](../top_n_pypi_stats.md),
rendered **deterministically** from `flex/exam-results.json` — no AI writes the table, and it
reproduces byte-for-byte from the committed ledger. Its honest limits, both recorded per row:
a package whose sdist ships **no** tests (boto3, botocore, aiobotocore) cannot sit an exam,
and a suite that needs the network, a display or a system library will fail inside an offline
thick binary — which is a property of that suite, not a packaging defect. Widening to 100 is a
config change on the matrix (`gen-package-manifest.py --top-n 100`); `exam.py` then covers the
new rows for free. Keep the `2 of 25` / `25 of 100` figures above in step with the page.

## Where the list comes from

Three files, two of them committed, one generated:

```
flex/sources.toml     the PyPI download ranking, extracted   (committed, generated)
flex/curation.toml    hand-written: smoke scripts, tiers, hard targets   (committed)
        |
        v  tools/gen-package-manifest.py   (no network, no clock)
flex/packages.toml    the matrix the runner reads            (committed, generated)
```

Ranking source: [Top PyPI Packages](https://hugovk.github.io/top-pypi-packages/), derived
from PyPI's public download statistics. Counts include mirrors and CI, so it ranks what gets
**downloaded**, not what humans use most — good enough for a breadth sample, which is all it
is for.

### Refreshing the ranking

```sh
python tools/fetch-top-pypi.py        # fetch, rewrite flex/sources.toml
python tools/gen-package-manifest.py  # regenerate flex/packages.toml
git diff flex/                        # review — this is a decision, not a drift
```

Fetching is a separate step from generating, deliberately. Generation must be reproducible:
same inputs, byte-identical output, offline, years from now. A generator that fetched could
not promise that, because the ranking changes monthly. `tools/fetch-top-pypi.py --check`
tells you whether the committed extract still matches upstream without writing anything.

The raw snapshot (~800 KB) is gitignored; its sha256 is recorded in `flex/sources.toml`, so
anyone who refetches can tell whether they got the same upstream bytes. The committed
extract — names in rank order — is what actually regenerates the manifest.

## Growing the list

```sh
python tools/gen-package-manifest.py -n 250
```

`flex/sources.toml` keeps 300 names, so growing to ~250 needs no refetch — which also means
growing the list does not silently pull in a different month's ranking at the same time.

At 250, mind the cost: a default-tier build is ~15 MB and ~25 s here. Use `-j` for
parallelism, and expect the thick-tier hard targets to dominate wall clock and disk.

## Adding a package

Edit `flex/curation.toml`, then regenerate. Nothing else is hand-edited.

```toml
[package.somelib]
import_name = "some_lib"          # only if it differs from the distribution name
smoke = """
import some_lib
assert some_lib.works()
print("FLEX_OK")
"""
why = "one line on what this covers"
```

A smoke script must run offline once the package is installed, need no credentials or
display, finish in a second or two, and print `FLEX_OK` exactly once. Without one the
package is imported and its version printed — weaker, and honest about being weaker.

To exclude a package, set `skip = true` with a `skip_reason`. The exclusion is recorded in
the generated manifest's header, so it stays visible rather than looking like an oversight.

## What the tests cover

`tests/test_flex.py` runs offline in milliseconds and checks the **list**, not the builds:
that the manifest matches its inputs, that generation is deterministic, that the generator
imports no network or clock module, that the hard targets and `scaffold.py`'s `KNOWN` table
have not drifted apart, and that every smoke script parses and signals success.

See `INV-FLEX-01` and `INV-FLEX-02` in [INVARIANTS.md](../INVARIANTS.md).

## First full hard-target run — 2026-09-09

This box: linux-x86_64, all thick unless noted, `--offline-check`.

> **Smoke-era, and on the host.** These numbers predate two changes and are not directly
> comparable with a run from today. They were produced with the hand-written `smoke` bodies,
> which is now `--style smoke` rather than the default; and before the harness ran in
> containers, so the `offline` column here is the old `UV_OFFLINE`-plus-dead-proxy
> approximation rather than a real network namespace (`INV-SANDBOX-02`). The findings below
> stand — they are about package *shapes*, which have not changed.

| package | tier | verdict | size | build | run | offline |
|---|---|---|---|---|---|---|
| playwright | thick | ok | 224.8 MB | 126 s | 15.7 s | carried |
| torch | thick | ok | **3072 MB** | 669 s | 78.8 s | carried |
| transformers | thick | ok | 105.7 MB | 63 s | 9.2 s | carried |
| selenium | thick | ok | 73.1 MB | 48 s | 3.5 s | carried |
| tiktoken | thick | ok | 63.8 MB | 50 s | 3.4 s | carried |
| weasyprint | thick | XPASS | 78.3 MB | 50 s | 6.9 s | carried |
| nltk | thick | FAIL | 64.0 MB | 46 s | 6.8 s | **FETCHED** |
| spacy | thick | FAIL | 142.9 MB | 93 s | 11.0 s | — |

**playwright is the headline pass.** Firefox baked in by a `[[bundle]]` step, launched a
real browser, rendered, and did it from a pristine cache with uv offline. 225 MB.

**torch at 3 GB** builds in 11 minutes and runs offline. The size stress case works.

### The two failures were findings, not bugs in the packages

`spacy` failed on the **first** run; `nltk` passed with a network and failed the offline
check. Both were configured exactly as `scaffold.KNOWN` recommends — a `post_install` step.

That combination is contradictory: `post_install` means "fetch on the target, first run",
and thick sets `UV_OFFLINE=1` and promises to download nothing. haru-pack accepted it
silently. It now warns and names the steps (`INV-TIER-02`), and these two are tested at the
default tier — the tier their documented handling is actually for.

The fix for a step that downloads is a `[[bundle]]` step, which runs at build time and ships
its output. That is precisely what playwright does, and why playwright passes thick.

### The XPASS was a weak test, not a capability

`weasyprint` was marked `expect_failure` because it needs pango and cairo, which pip cannot
bundle. It passed. Two reasons, both worth naming: this build host **has** those libraries,
and the smoke test only did `import weasyprint`, which never touches them.

Both were fixed rather than the mark being flipped: the smoke now renders a real PDF and
asserts the `%PDF` header, and the expectation records that the outcome depends on the host
running the binary — something this harness cannot settle from here. A pass means *this*
machine has the libraries, not that the binary is portable.

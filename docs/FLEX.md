# flex harness — does haru-pack handle real packages?

```sh
python tools/flex-run.py --list top25       # breadth
python tools/flex-run.py --list hard_targets -j 4
python tools/flex-run.py --only numpy       # one package
python tools/flex-run.py --dry-run          # what would run
```

Results land in `flex/out/results.json` and a summary table on stdout. Exit code is
non-zero if anything came out other than expected.

## What it does

For each package: build a tiny project that depends on it, whose `flexapp/__main__.py`
imports it and does one small real thing, then **run the resulting binary** and require it
to print `FLEX_OK`. The entrypoint is `python -m flexapp`, so stdout comes from a module
that had to be importable inside the packaged environment.

Running it is the point. A binary that builds and then dies on startup is a failure, and
only executing it catches that.

## Proving the payload carries its dependencies

```sh
python tools/flex-run.py --tier thick --offline-check
```

At the **default** tier the dependency is fetched on first run, so a green result proves the
packaging path and nothing about what the binary contains. At `--thick` the payload is
supposed to carry uv, the interpreter and every dependency.

`--offline-check` runs the thick binary a second time with a **pristine cache directory**
and uv forced offline. The pristine part is load-bearing: with a warm `~/.cache/haru-pack`
the staged tree is reused and the run succeeds no matter what the payload holds. The summary
column reads `carried` or `FETCHED`.

What this does *not* prove: it forces uv offline and points the proxy variables at a dead
port, which blocks the dependency-fetch path. It is not a network namespace, so it does not
stop a package from opening a socket of its own. A green offline check means "the
dependencies came from the payload", not "this binary makes no network calls".

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

At 250, mind the cost: a default-tier build is ~23 MB and ~25 s here. Use `-j` for
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

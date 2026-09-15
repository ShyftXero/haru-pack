# haru-pack — cutting a release

## The short version

```sh
./scripts/cut-release.sh --check      # run the gate, tag nothing. Safe anywhere, any branch.
./scripts/cut-release.sh 0.2.0        # verify, stamp, tag, and offer to push
```

Everything below explains why the script does what it does. You do not need it to ship —
run `--check`, read what it prints, and the script tells you the rest.

## The model

After the first release, work flows: **branch → PR → merge to `main` → stamp a `main` commit
you like as a release.** Tags are cut from commits that are already merged and pushed. There
is no release branch and no long-lived staging.

That means a release is a *decision about an existing commit*, not a separate build. The
script's job is to make sure that commit deserves it.

## What the gate actually checks

`cut-release.sh` **runs** these. It does not accept a claim that they passed:

| Check | Why it blocks a release |
|---|---|
| `uvx "ruff@$RUFF_PIN" check .` | don't tag what you wouldn't merge — and through the **pinned** ruff, because this gate once passed on the exact commit CI rejected. The pin is `sed`-ed out of `pyproject.toml`, the same single source CI reads, and a missing `ruff==` pin is itself a hard failure. Deliberately not `uv run --group dev ruff`, which would install the linter into the environment the tests below are about to run in (`INV-CI-01`) |
| `./scripts/self-build.sh` | haru-pack packs haru-pack for linux + windows, and each artifact's payload is verified. If the tool cannot pack itself, the project's central claim is false — better to learn that before a tag exists than after (`INV-CI-02`). `--no-self-build` skips it and says so |
| `pytest -m invariant` | the invariant contract — see below |
| the full suite | the obvious one |
| `nim c -d:release` on the launcher | every shipped binary embeds it |

Plus repo hygiene: on `main`, clean tree, commit present on `origin/main`, tag not already
taken.

The invariant contract is the one worth understanding. It fails when an `active` entry in
`INVARIANTS.md` has no claiming test, when a `proposed` entry has acquired one, or when any
file cites an `INV-` id that was never declared. In other words it fails when the repo's
written security claims and its executable evidence have drifted apart — which is exactly
the condition you do not want to publish in.

**Do not relax the contract to get a release out.** If it fails, either the tests or the
document is wrong; fix whichever it is.

If instead you see collection errors or `OSError`, the suite could not *run* — that's an
environment problem, not a release blocker. The script uses a private scratch directory to
avoid the most common one (a shared `/tmp/pytest-of-$USER` owned by another uid).

## Versioning

`__version__` in `src/haru_pack/__init__.py` is the single source; hatchling reads it at
build time (`[tool.hatch.version]`). The script rewrites that line, commits it as
`release: X.Y.Z`, and tags `vX.Y.Z`.

Versions are `N.N.N`, optionally with an `a`/`b`/`rc` suffix. The pattern is deliberately
strict: a typo becomes a permanent filename on PyPI.

## Publishing

Pushing the tag is what publishes. `.github/workflows/publish.yml` triggers on `v*`, runs
**the full CI workflow again** on the tagged commit, and only then uploads to PyPI via
trusted publishing (OIDC — no API token stored anywhere).

So the gate runs twice: once locally before you tag, once in CI on the tag. That is
intentional. A local run can pass on a machine with an unusual toolchain; CI is the one that
matches what everyone else gets.

## If something goes wrong

The script prints the undo commands when it stops after tagging. Before the tag is pushed,
everything is local and reversible:

```sh
git tag -d v0.2.0          # remove the tag
git reset --hard HEAD~1    # drop the version-bump commit
```

Once a tag is pushed and PyPI has accepted an upload, **that version is spent**. Yanking
removes it from resolution but the filename is never reusable. Cut `0.2.1`.

## Bumping a pinned dependency

Pinned digests live in **`src/haru_pack/pins.toml`** — one `[[artifact]]` table per asset,
each carrying the digest, the URL, and the publisher channel the digest came from. That is
the single source of truth: `src/haru_pack/bundle.py` no longer holds dict literals, it calls
`pins.uv_digests()` / `pins.python_digests()` (they moved out of `bundle.py` on 2026-09-09).
Pinned Nim *package* versions are the exception and still live in `src/haru_pack/bootstrap.py`
(`NIM_DEPS`).

Bump a digest with `python tools/add-pin.py <kind> <version> <asset>` (or `--all` for every
asset haru-pack can target). It fetches the **publisher's** digest — the release's
`<asset>.sha256` sidecar, else the release API's per-asset digest — and writes it with its
provenance. Do not hand-edit a digest into `pins.toml` that you computed by downloading the
artifact and hashing it: that pins whatever the server sent you, which is the thing the pin
exists to catch. Never edit a digest to make a failing check pass. If neither publisher
channel offers a digest, the correct outcome is no pin and a refused artifact. See
`docs/CONFIG.md`.

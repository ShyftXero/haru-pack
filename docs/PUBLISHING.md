# Publishing haru-pack to PyPI

The package is `haru-pack` (import `haru_pack`), with **two console scripts — `haru-pack`
and `haru`** — that are the same program (`INV-PKG-01`). Pure-Python wheel
(`py3-none-any`) — the Nim launcher source and the vendored XZ decoder's C ship as package
data and are compiled on the user's machine by `haru-pack build`, so there are no
per-platform wheels to build.

Keeping it `py3-none-any` is a deliberate choice, not an accident of the build. See
"Why not ship the packed binary through PyPI" below.

## Before the first publish — the current state

Verified 2026-09-10 on this commit:

| | |
|---|---|
| name `haru-pack` on PyPI | free (HTTP 404) — first publish claims it |
| name `haru` on PyPI | **taken** by an unrelated web framework. The *command* is fine; the distribution name is not available |
| `uv build` | clean; sdist + wheel |
| wheel contents | 7 `.nim`, 8 vendored `xz/*.c`/`.h`, `PROVENANCE.md`, `pins.toml` — checked, and `INV-PKG-02` keeps it that way |
| `LICENSE` | present, and hatchling ships it to `dist-info/licenses/LICENSE` |
| clean-venv install | both `haru-pack` and `haru` land on PATH and run |
| `./scripts/cut-release.sh --check` | passes locally |
| **GitHub Actions `ci`** | **failing** — and `publish.yml` has `needs: ci`, so a tag push will not publish |

That last row is the only thing actually blocking a release. The cause is that CI runs
`uvx ruff check .` **unpinned**, so it lints with whatever ruff was released most recently;
newer ruff turned on rules this repo does not satisfy (`I001`, `PLW1510`, `RUF100`). The
same commit passes the local gate and fails CI, which is the tell. Pin the linter — this
repo pins every other tool it executes (`INV-SUPPLY-01`) — e.g.

```yaml
- name: lint
  run: uv run ruff check .        # ruff is already in [dependency-groups] dev, pin it there
```

Two steps remain that only a human with the accounts can do, both unchanged from below:
the PyPI **pending publisher**, and the GitHub **`pypi` environment**.

Also decide before publishing: the repo is currently **private**, while the package
metadata advertises `Homepage`/`Repository`/`Issues` URLs that point at it. Those links
will 404 for everyone who finds the project on PyPI.

## One-time: name + trusted publisher
1. The name `haru-pack` is free on PyPI (checked 2026-09-09) — first publish claims it.
2. **Recommended: Trusted Publishing (OIDC, no API token).** On PyPI →
   *Your project → Publishing → Add a pending publisher*:
   - Owner: `ShyftXero`, Repo: `haru-pack`, Workflow: `publish.yml`, Environment: `pypi`.
   Then create a GitHub Environment named `pypi` in the repo settings.

## Release (trusted publishing)
```sh
# bump version in src/haru_pack/__init__.py, commit
git tag v0.1.0 && git push origin v0.1.0     # publish.yml builds + publishes
```

## Manual publish (token fallback)
```sh
uv build
uv publish --token pypi-XXXX                  # or set UV_PUBLISH_TOKEN
# TestPyPI first:
uv publish --publish-url https://test.pypi.org/legacy/ --token pypi-XXXX
```

## Verify
```sh
uvx haru-pack version          # run the just-published CLI ephemerally
pipx install haru-pack         # or a normal install
```

## Why not ship the packed binary through PyPI

haru-pack can pack itself — verified 2026-09-10: `haru-pack build . -e haru-pack` produced a
15.5 MB single file that runs `version` and `doctor` with no Python on the user's side. And a
wheel *can* carry that binary: put it in `<name>-<ver>.data/scripts/`, tag the wheel for the
platform, and `uv tool install` reports "Installed 1 executable" and puts it on PATH, mode
775, working. Also verified.

So it is possible. It is still the wrong channel, for three reasons:

1. **The audience is inverted.** The packed binary exists for machines with no Python and no
   uv. `uv tool install` requires uv, which brings its own Python. Anyone who can run the
   install command did not need the packed binary; anyone who needs the packed binary cannot
   run the install command.
2. **It costs the `py3-none-any` wheel.** Shipping a binary means one platform-tagged wheel
   per target (linux x86_64/aarch64, windows x86_64, macOS arm64/x86_64) — and macOS cannot
   be cross-compiled from Linux, so that row needs a Mac in CI. Today there is one wheel and
   no build matrix.
3. **It breaks `import haru_pack`.** A wheel whose payload is an executable is not the
   library, so anyone using haru-pack as a Python API — including its own test suite — gets
   a package that cannot be imported. Two distributions solve that and then you are
   maintaining two.

**Recommended split:** PyPI keeps the pure-Python wheel (`pip`/`uv tool install haru-pack`
→ the CLI, importable, one artifact, no matrix). Packed native binaries go to **GitHub
Releases**, fetched with a `curl`/`irm` one-liner — which is what someone without Python can
actually run, and where a signed Windows `.exe` belongs anyway.

The genuinely valuable half of the idea is the **dogfooding**: have CI build haru-pack with
haru-pack and attach the result to the release. It proves the tool works on a real project
with native dependencies (`cryptography`) on every release, and it gives the no-Python
audience something to download. That is worth doing; routing it through PyPI is not.

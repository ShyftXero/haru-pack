# Publishing haru-pack to PyPI

The package is `haru-pack` (import `haru_pack`), CLI `haru-pack`. Pure-Python wheel
(`py3-none-any`) — the Nim launcher source ships as package data and is compiled on the
user's machine by `haru-pack build`, so there are no per-platform wheels to build.

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

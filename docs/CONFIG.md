# haru-pack configuration

## Discovery (usually you write nothing)
`haru-pack build <path>` auto-discovers from the target:
- **kind** — `pyproject.toml` with `[project]` → project; a single `.py` (or a `.py` path) →
  PEP 723 script.
- **Python version** — `requires-python` (pyproject or PEP 723 block) → `.python-version` →
  else `3.12`. Override with `--python X.Y` or `haru_pack.toml` `python`.
- **entrypoint** — the single `[project.scripts]` entry (two or more and it refuses, naming
  them); else `python -m <name>` **if `<name>/__main__.py` exists**; else the script
  filename for a script. An importable-but-not-executable package is refused rather than
  turned into a `python -m` that fails on the target.

  A `module:callable` entrypoint is also checked: if that module is in the project tree and
  does not define the attribute, the build refuses. Note that `app:main` means "import
  `main` from module `app`" — it is **not** the `if __name__ == "__main__":` block, which
  cannot be imported and called. If your logic lives in that guard, either move it into a
  function or put it in `<pkg>/__main__.py` and let discovery emit `python -m <pkg>`.
- **name** — `[project].name` or the script stem.

## `haru-pack init` — scaffold it
```sh
haru-pack init ./myproject     # writes a commented haru_pack.toml, pre-filled
```
`init` discovers kind/name/entrypoint/Python and **learns from an available venv**
(`<project>/.venv`, `venv`, or `$VIRTUAL_ENV`): it reads the venv's Python version and
installed packages, so it can suggest bundle/post_install steps (e.g. a Playwright browser)
even when they aren't in `pyproject.toml`. Add `--force` to overwrite.

## Where directives live
Two places, and a project may use either or both:

```
discovery  <  [tool.haru-pack] in pyproject.toml  <  haru_pack.toml  <  CLI flags
```

- **`[tool.haru-pack]` in `pyproject.toml`** — for a project that is already a package. It
  already declares everything else about itself; asking for a second file to say "this is
  how I am bundled" is friction for no gain. Same keys as below, one table deeper.
- **`haru_pack.toml`** — the only option for a tree with *no* pyproject (a bare script, a
  folder of `.py` files), the local override for one that has it, and what `haru-pack init`
  writes. Wins where both speak.

The merge is per top-level key, not deep: a `[[bundle]]` list in `haru_pack.toml` **replaces**
the one in `pyproject.toml` rather than appending to it, so a directive can be removed and
not just added to.

`[tool.haru_pack]` (underscore) is **refused, not ignored** — a config table read by nobody
is worse than a missing one, because you believe it took effect. `INV-BUILD-07`.

PEP 723 allows `[tool]` tables inside a script's inline metadata block; that is not read yet.

```toml
# in pyproject.toml
[tool.haru-pack]
entrypoint = "myapp"
cwd_policy = "exe"
```

## haru_pack.toml (optional, at the project root)
Declare overrides + extras. Precedence as above.
```toml
name = "myapp"                   # usually discovered
kind = "project"                 # usually discovered
app_subdir = "app"               # where source is placed inside the payload
entrypoint = ["python", "-m", "myapp"]   # string (script) or argv (command)
python = "3.12"                  # staged Python version
cwd_policy = "exe"               # "launch" (native cwd, default) | "exe" (exe-adjacent)
verbose_uv = false
uv_run_args = ["--isolated"]

# OS-specific run-once hooks (the per-OS-compiled stager runs only matching ones)
[[post_install]]
os = ["windows"]                 # ["linux"|"windows"|"macos"|"all"]; omit = all
run = ["playwright", "install", "firefox"]
[[pre_install]]
run = ["python", "-c", "import myapp; myapp.setup()"]

# build-time bundling (thick): bake output into the exe; same env re-applied at runtime
[[bundle]]
run = ["playwright", "install", "firefox"]
into = "vendor/ms-playwright"
[bundle.env]
PLAYWRIGHT_BROWSERS_PATH = "{into}"        # {into} -> stage dir at runtime
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = "1"

# --shake (thick only): how to OBSERVE this project so unused payload files can be pruned.
# Full semantics and limits: docs/SHAKE.md
[shake]
test = ["pytest", "-q"]          # required; a bare tests/ dir is discovered as ["pytest"]
also_run = [["python", "-m", "myapp", "--selftest"]]   # extra observation runs
keep = ["torch/lib/libtorch_cpu.so"]   # never prune these, whatever the trace says
follow_lazy_imports = true       # keep the AST closure of function-level imports too
shake_interpreter = true         # also apply the CPython rulepack (test/, idlelib, tk, ...)

# encryption — same fields as the --encrypt CLI flags; the SECRET is never stored here
[encryption]
enabled = true
expires = "2027-01-01"
geo = ["US", "CA"]
machine = "<machine-id>"         # cryptographic bind (haru-pack machine-id on the target)
user = "alice"                   # cryptographic bind
embed_secret = false
```

## `[sources]` — where third-party artifacts are downloaded from

haru-pack downloads three things while building: the `uv` binary, a standalone Python
interpreter, and your project's wheels. By default all three come from their upstream
publishers on github.com and PyPI. If your environment can't reach those — an air-gapped
build host, a corporate proxy, a mandated mirror — point them somewhere else:

```toml
[sources]
uv_base     = "https://mirror.example/uv/releases/download"
python_base = "https://mirror.example/python-build-standalone/releases/download"
index_url   = "https://pypi.example/simple"
```

Or per-invocation, which is usually what CI wants:

```sh
HARUPACK_UV_BASE=... HARUPACK_PYTHON_BASE=... HARUPACK_INDEX_URL=... haru-pack build ./app
```

`haru_pack.toml` wins over the environment; the environment wins over the defaults.

**A mirror must be a path-preserving reverse proxy.** Everything after the base URL is
reused verbatim, so `<uv_base>/0.10.4/uv-x86_64-unknown-linux-gnu.tar.gz` has to resolve.
That's the same shape `uv python install --mirror` expects, so a mirror that works for uv
works here.

### Changing where bytes come from does not change whether they're checked

Every downloaded artifact is verified against a SHA-256 pinned **in this repository**
(`bundle.UV_SHA256`, `bundle.PBS_SHA256`), and the pin is chosen by the artifact's
*upstream* identity before the download point is rewritten. So:

- Pointing at a hostile or stale mirror gives you a `DigestMismatch` and a failed build,
  not a compromised binary.
- An artifact with **no pin is refused rather than downloaded** — haru-pack will not stage
  something unverified into a binary you're about to sign.

If a mirror produces a digest mismatch, the mirror is wrong or out of date. **Do not edit
the pin to make it pass.** Fix the mirror, or set the base back to upstream. Bumping a
pinned version means recording the publisher's real digest — from the release's
`<asset>.sha256` sidecar or the release API — never a value you computed from whatever the
mirror happened to serve.

The build receipt records which sources were used, so `haru-pack build` output tells you
whether a mirror was in play for that artifact.

## Generated `manifest.toml`
`haru-pack build` writes a resolved `manifest.toml` **into the payload** (kind, entrypoint,
cwd_policy, tier, offline, cache_dir, bundle, pre/post_install). That's what the launcher
reads at runtime — you don't author it; edit `haru_pack.toml` instead.

## post_install vs bundle
- **`bundle`** (build-time): bake artifacts into the exe → offline (thick).
- **`post_install`** (run-once on target): fetch/setup on first run → smaller exe, needs
  network once (thin/default). OS-tagged. haru-pack can't infer these — you declare them.

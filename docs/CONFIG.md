# haru-pack configuration

## Discovery (usually you write nothing)
`haru-pack build <path>` auto-discovers from the target:
- **kind** — `pyproject.toml` with `[project]` → project; a single `.py` (or a `.py` path) →
  PEP 723 script.
- **Python version** — `requires-python` (pyproject or PEP 723 block) → `.python-version` →
  else `3.12`. Override with `--python X.Y` or `haru_pack.toml` `python`.
- **entrypoint** — `[project.scripts]` first entry, else `python -m <name>` for a project;
  the script filename for a script.
- **name** — `[project].name` or the script stem.

## `haru-pack init` — scaffold it
```sh
haru-pack init ./myproject     # writes a commented haru_pack.toml, pre-filled
```
`init` discovers kind/name/entrypoint/Python and **learns from an available venv**
(`<project>/.venv`, `venv`, or `$VIRTUAL_ENV`): it reads the venv's Python version and
installed packages, so it can suggest bundle/post_install steps (e.g. a Playwright browser)
even when they aren't in `pyproject.toml`. Add `--force` to overwrite.

## haru_pack.toml (optional, at the project root)
Declare overrides + extras. Precedence: discovery < `haru_pack.toml` < CLI flags.
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

# encryption — same fields as the --encrypt CLI flags; the SECRET is never stored here
[encryption]
enabled = true
expires = "2027-01-01"
geo = ["US", "CA"]
machine = "<machine-id>"         # cryptographic bind (haru-pack machine-id on the target)
user = "alice"                   # cryptographic bind
embed_secret = false
```

## Generated `manifest.toml`
`haru-pack build` writes a resolved `manifest.toml` **into the payload** (kind, entrypoint,
cwd_policy, tier, offline, cache_dir, bundle, pre/post_install). That's what the launcher
reads at runtime — you don't author it; edit `haru_pack.toml` instead.

## post_install vs bundle
- **`bundle`** (build-time): bake artifacts into the exe → offline (thick).
- **`post_install`** (run-once on target): fetch/setup on first run → smaller exe, needs
  network once (thin/default). OS-tagged. haru-pack can't infer these — you declare them.

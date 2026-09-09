# haru-pack manifest (TOML)

`manifest.toml` at the payload root declares how to run your project. All haru-pack
configs are TOML.

```toml
name = "myapp"
kind = "project"                 # "script" (PEP 723) | "project" (pyproject.toml)
app_subdir = "app"               # payload subdir holding your code
entrypoint = ["python", "-m", "myapp"]   # string (script path) OR argv (command)
cwd_policy = "exe"               # "launch" (native, default) | "exe" (always exe-adjacent)
verbose_uv = false               # show uv's own logs (default: quiet)
uv_run_args = ["--isolated"]     # extra args passed to `uv run`

# --- OS-specific install hooks (run once each, in the uv env). The Nim launcher is
#     compiled per-OS, so it runs only the steps whose `os` matches the machine. ---
[[post_install]]
os = ["windows"]                 # ["linux"|"windows"|"macos"|"all"]; omit = all
run = ["playwright", "install", "firefox"]

[[post_install]]
os = ["linux"]
run = ["playwright", "install", "firefox"]

[[pre_install]]                  # runs before post_install (also once, OS-filtered)
run = ["python", "-c", "import myapp; myapp.setup()"]

# --- build-time bundling (thick): run a command during `haru-pack build` and bake its
#     output into the exe. The same `env` is re-applied at runtime with {into} -> stage. ---
[[bundle]]
run = ["playwright", "install", "firefox"]
into = "vendor/ms-playwright"
[bundle.env]
PLAYWRIGHT_BROWSERS_PATH = "{into}"
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = "1"
```

## Fields set by the tier (don't hand-set)
`tier`, `offline`, `fetch_uv`, `cache_dir` are written by `haru-pack build` based on
`--thin/--thick`. See [TIERS.md](TIERS.md).

## post_install vs bundle — which do I use?
- **`bundle`** (build-time): bake artifacts into the exe → offline (thick). Use when you
  want the browser/model shipped inside the artifact.
- **`post_install`** (run-once on target): fetch/setup on first run → smaller exe, needs
  network once (thin/default). OS-tagged so e.g. `playwright install firefox` runs on the
  right platform. haru-pack can't infer these — you declare them.

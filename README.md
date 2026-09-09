# haru-pack

Single-file, **EV-signable native launcher** (Nim) that carries an arbitrary Python
project — a PEP 723 script *or* a full multi-folder project (e.g. a Flask app) — stages
`uv` + a standalone Python into per-user appdata on first run, and runs it **as if it were
a compiled binary sitting in the folder the exe was launched from**. Windows-first, Linux
supported.

Think PyInstaller's UX, but the interpreter + deps are delegated to `uv` and the launcher
is a thin signable native stub.


## Install & use (builder CLI)
```sh
pip install haru-pack            # or: uvx haru-pack ...
haru-pack bootstrap              # install Nim (+zippy, puppy) & check the C toolchain
haru-pack doctor --target windows   # verify cross-compile toolchain (prints mingw install cmd if missing)
haru-pack build ./myproject --thin              # smallest; fetch uv+python on target
haru-pack build ./myproject                      # default; uv bundled
haru-pack build ./myproject --thick --target windows   # everything bundled, offline (build thick on the target OS)
```
Tiers: **--thin** (bundle nothing) · default (uv bundled) · **--thick/--chonky** (uv +
Python bundled, offline). See [docs/TIERS.md](docs/TIERS.md).

## Status
Research + design. Nothing to build yet.
- `docs/PLAN.md` — the plan (architecture, container format, uv wiring, signing, milestones)
- `research/01-war-and-prior-art.md` — astral `war` (NOT a builder) + `pyapp`
- `research/02-uv-staging.md` — driving `uv` fully offline
- `research/03-nim-launcher.md` — Nim embed/extract/exec/sign
- `research/04-pyinstaller-lessons.md` — what to steal / reject from PyInstaller


## Validated so far (2026-09-09)
- **Cross-compile Linux → Windows** PE via `nim -d:mingw` (core requirement).
- **Signable-after-attach**: append payload → `osslsigncode` sign → Authenticode digest
  matches and the Nim launcher still relocates its payload from its own *signed* exe
  (backward magic scan survives the appended cert table). See `docs/SIGNING.md`.

## Key findings
- **`astral-sh/war` is not what it looked like** — it's a draft *archive-format* spec
  ("Way better ARchive"), Paperware, **no binary encoding defined yet**. Can't build on
  it today; we borrow its ideas in our own container and can adopt it later.
- **Persistent, hash-versioned extract to appdata** (PyInstaller *onedir* semantics), not
  per-run temp extraction (*onefile*) — faster, crash-safe, AV-friendlier.
- **Run-in-place cwd** + explicit three-root model (CWD / exe dir / stage dir) so a config
  dropped next to the exe is found and relative paths behave natively.
- **Append payload, sign last, no UPX** — EV signing + reputation is the AV story.

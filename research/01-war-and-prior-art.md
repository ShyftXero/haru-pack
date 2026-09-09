# Research 01 — astral `war`, and the real prior art

_Agent: Warhawk. Date: 2026-09-09._

## Headline: `war` is NOT a builder

`astral-sh/war` = **"Way better ARchive format"** — a draft *archive format spec* for
Python packaging, authored by William Woodruff (Astral). It is **not** an executable
builder and has no tool at all.

- README self-labels it **"Paperware"** and "a very early draft".
- Repo (checked 2026-09-09): created 2026-05-26, last push 2026-07-06, **9 stars, 5
  commits, 0 releases**, docs-only (README.md + SPEC.md).
- **SPEC.md v0.0.2 explicitly: "war does not currently define a binary encoding; the
  type definitions below are intended to be abstract."** → cannot be implemented as-is.

### What war's format *is* (the borrowable ideas)
- Layout: magic bytes `war!`, version, an **FST-based name index** (name → u64 store
  offset), then a **Store** of File/Dir/Link entries.
- Per-entry compression enum: `{Store, Deflate, Zstd}`; metadata carries `executable:bool`.
- **Unpack model:** build into a temp dir, then **atomic rename** to target. Enforces
  decompressed-size limits, rejects path traversal + Windows-reserved names.
- Inspirations: Nix Archive (NAR) and XAR. Goals are speed + indexability +
  unambiguity vs tar/zip. Anti-goal: not general-purpose, not max compression.

**Implication for haru-pack:** "use war's file format" is not literally possible today.
Adopt the *concepts* (magic footer + index + per-entry zstd + atomic unpack) in our own
overlay container now, and keep the door open to swap in real `war` once it defines a
binary encoding + ships a lib. Do not pin the design on it.

## Real prior art: `ofek/pyapp` (Rust)

Mature (~2030 stars, v0.29.0 2025-10-15, active). "Runtime installer for Python apps" —
produces a genuine **native per-platform binary** (Win/Linux/macOS), can embed a
python-build-standalone CPython + the project for an offline single artifact, optionally
uses uv, and installs+caches to an OS data dir on first run (self update/remove).

Because output is an ordinary native binary, **it Authenticode-signs like any exe**.

### pyapp gaps haru-pack can own (differentiation)
1. **Native PEP 723 ingestion** — read inline `# /// script` metadata, auto-translate.
2. **Truly embed** uv binary + pinned standalone Python + resolved wheels → zero runtime
   network. (pyapp by default *downloads* CPython/uv on first run unless you set
   `PYAPP_DISTRIBUTION_EMBED=1`, `PYAPP_PROJECT_PATH`, `PYAPP_UV_SOURCE`, `PYAPP_SKIP_INSTALL=1`.)
3. **Run-in-place UX** — behave as if executing in the folder the exe sits in (config
   adjacent to exe), not pyapp's install-to-appdata-then-run model.

### Decision
- Do **not** build on `war` (immature, no encoding).
- **Evaluate pyapp** as either (a) a fork/wrap target, or (b) reference architecture for
  a Nim launcher. Given the user wants a Nim stub + specific run-in-place cwd UX + EV
  signing, **Nim launcher is the chosen path**; pyapp is the reference to steal from.

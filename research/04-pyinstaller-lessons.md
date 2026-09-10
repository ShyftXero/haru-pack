# Research 04 — PyInstaller architecture → lessons for haru-pack

_Agent: Bootloader. Date: 2026-09-09._

## Two models
- **ONEFILE:** appends a compressed **CArchive** after a C bootloader. Every launch
  self-extracts to a random `_MEIxxxxxx` temp dir, re-execs a child, deletes on clean
  exit. `sys._MEIPASS` = that temp root. Slow (decompress every run), AV-tripping, and
  **leaks temp on crash/kill** (cleanup only on graceful exit).
- **ONEDIR:** persistent folder, no runtime extraction, faster, AV-friendly.

**haru-pack target = ONEDIR's persistence, keyed by a content hash** — extract once to
appdata, skip on later runs. Explicitly reject onefile's re-extract-every-launch.

## The overlay / magic-cookie pattern (steal this)
- CArchive TOC lives at **end of file**, followed by a **cookie**: magic
  `MEI\014\013\012\013\016` + `!8siiii` trailer (24B: 8B magic + 4 int offsets).
- Bootloader opens **its own exe**, seeks to EOF, and **scans backward for the magic** —
  added specifically so an appended OS signature doesn't hide the cookie.
- Nim equivalent: `getAppFilename()` → open self → read a fixed-size, self-describing
  footer `{magic, version, offset, length, sha256, tail-magic}`. Scan backward so an
  Authenticode cert table appended at EOF doesn't move the fields.

## Two-root idiom (the UX crux)
- `sys._MEIPASS` = bundled/staged resources root.
- `dirname(sys.executable)` = the **shipped exe's dir** → where a user-dropped config
  lives. `os.getcwd()` is the shell's launch dir (bootloader does NOT chdir).
- Frozen check: `getattr(sys,'frozen',False) and hasattr(sys,'_MEIPASS')`.
- **haru-pack exposes three explicit roots** (see PLAN): CWD, EXE dir, STAGE dir. Never
  derive user-data paths from `__file__`.

## Signing + AV

> _Two corrections from `research/05`: "EV signing" below should read "OV signing" (EV OIDs
> were removed from Microsoft's trusted roots in Aug 2024), and on **Windows** prefer PE
> resources over a tail overlay — uv appended a magic trailer exactly as described here and
> signtool broke it (uv#15022, fixed by moving to `.rcdata`). Scan-backward remains correct
> for ELF; on Mach-O a tail overlay is not possible at all._

- **Append payload FIRST, sign LAST.** Appending after signing breaks it. Footer must
  stay locatable after the cert table is appended (scan-backward-for-magic).
- **No UPX** (invalidates sig + trips heuristics). Persistent on-disk files + code signing
  + accrued SmartScreen reputation = the real AV mitigation. Onefile+UPX+unsigned = worst.
- Offer an **external-payload mode** (launcher + sidecar archive, onedir-like) for
  enterprise AV that still distrusts a single self-extracting stub.

## Other stealable machinery
- **Splash / progress line** during the one-time stage (uv/python/venv) so cold start
  doesn't look hung.
- **Runtime-hook** concept: a pre-run shim setting env (`UV_*`, `VIRTUAL_ENV`, `PATH`).
- **argv/env/signal passthrough:** forward argv verbatim, inherit stdio, propagate exit
  code, forward Ctrl+C/SIGTERM so the launcher is transparent.
- Delegate the interpreter to **uv** — no libpython embedding, keeps the Nim stub thin.

## Do differently
- Persistent, **content-addressed** cache (hash-named dirs), not random ephemeral ones.
- Write a `.ready`/`.complete` **sentinel last**; stage to `<hash>.tmp-<pid>` then atomic
  rename → crash-safe + concurrency-safe. Add age/LRU eviction of old hash dirs.

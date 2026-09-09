# Research 03 — Nim launcher: embed, extract, exec, sign

_Agent: Acid_Burn. Nim 2.2 stdlib. Date: 2026-09-09._

## Payload embedding — the one real design fork
- `staticRead`/`slurp` embed a file at **compile time** as a Nim string constant.
  Fine for a few MB. **Does NOT scale to 30–100MB**: becomes one giant C string literal →
  slow/OOM C backend, nimsuggest memory blowup (nim#19075, nimsuggest#75).
- **For a uv+python+app bundle: append the payload zip as a PE OVERLAY** (SFX style):
  write a small trailer `{magic, offset, length, sha256}`, at runtime `getAppFilename()`
  locates the exe and you seek to the offset. Or ship the zip as a sidecar file.
- Embed a **single already-compressed blob** (one constant), not the loose tree.

## Per-user staging dir
- No single Nim proc gives exactly (Windows `%LOCALAPPDATA%` + Linux `~/.local/share`):
  - `getCacheDir()` → Win `LOCALAPPDATA` (no trailing sep) / Linux `~/.cache`.
  - `getDataDir()`  → Win **roaming** `APPDATA` (bad for 100MB, syncs) / Linux `~/.local/share`.
- Tree is **regenerable** → use `getCacheDir()` (LOCALAPPDATA on Win) OR hand-roll with
  `os.getEnv`. Roaming APPDATA is wrong for a big extract. Build paths with the `/`
  operator (mind getCacheDir's missing trailing sep).

## Locate self vs cwd
- `getAppFilename()` / `getAppDir()` → the exe and its dir (correct).
- `getCurrentDir()` → the user's launch cwd (the folder the exe was double-clicked in) —
  **this is the "run-in-place" root** we pass to uv, NOT where we find our payload.
- Never use `paramStr(0)`/`getCurrentDir()` to find the exe.

## Extract (atomic, versioned, first-run skip)
- zippy (`nimble install zippy`, pure-Nim, arc/orc + vcc ok): `extractAll(zip, dest)`
  (dest must NOT pre-exist), or `openZipArchive`/`walkFiles`/`extractFile`.
- Version dir: bake `const buildId = staticExec("git rev-parse --short HEAD")` (or hash of
  blob) → target `<baseDir>/haru-pack/<buildId>/`. Skip if `<dir>/.complete` exists.
- Atomic: extract to `<baseDir>/haru-pack/.tmp-<rand>`, write `.complete`, then
  `moveDir(tmp, final)` (rename = atomic same-FS). Guard `if not dirExists(final)`;
  tolerate concurrent-loser race (moveDir fails when target now exists).

## Launch child
```nim
let p = startProcess(uvExe, workingDir = runDir, args = commandLineParams(),
                     options = {poParentStreams})   # inherit stdio directly
let rc = p.waitForExit(); p.close(); quit(rc)
```
- `runDir` = the exe's launch cwd (`getCurrentDir()`) → run-in-place semantics.
- Absolute path to bundled uv; omit `poUsePath`. Never `poEvalCommand` (ignores args).
- Console subsystem (`--app:console`) for a CLI wrapper so stdio inheritance works.
  `--app:gui` (no console) would starve a console child's stdio. Use gui only for a
  windowed app that manages its own I/O.

## Windows EV code signing
- Nim → normal C → normal Authenticode-capable PE. `signtool sign /fd SHA256 /tr <ts>
  /td SHA256 /a app.exe`.
- **Order:** embedding via a PE section is inside the hash (fine). **Appending an overlay
  AFTER signing breaks the signature** — overlay bytes are within the Authenticode hash.
  So: **append/embed payload FIRST, sign LAST.**
- **No UPX**: invalidates prior signature + trips AV/SmartScreen heuristics. Nim binaries
  already carry a mild AV false-positive reputation; **EV signing + accrued SmartScreen
  reputation** is the real mitigation, not packing.

## Cross-compile
- From Linux: `nim c -d:mingw --cpu:amd64 -d:release app.nim` (needs `mingw-w64`) → normal
  signable PE. Or build natively on Windows (choosenim mingw, or `--cc:vcc` MSVC).

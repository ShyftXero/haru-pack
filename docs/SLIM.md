# `--slim-python` — drop the interpreter furniture a packed app never touches

```sh
haru-pack build ./myproject --thick --slim-python
```

A `--thick` binary bundles python-build-standalone (PBS) unmodified. About 9.5 MB zipped of
it is furniture most packed apps never touch: tcl/tk + tkinter, pip in the interpreter's
site-packages, ensurepip's bundled wheels, `share/man`, the C headers under `include/`,
idlelib, and pydoc_data. `--slim-python` removes that fixed set. It is **opt-in and never the
default.**

## Not the same feature as `--shake`

| | `--shake` | `--slim-python` |
|---|---|---|
| what it removes | whatever the test run never touched | a **fixed, known-unused** set |
| evidence | a traced test suite, re-proven after pruning | none — the set is structural |
| test command | **required** (`INV-SHAKE-03`) | not required |
| scope | dependencies, uv cache, and the interpreter | the interpreter only |

They are kept separate on purpose. `--shake` earns each deletion with an observation;
`--slim-python` asserts up front that a specific list of things cannot be reached, and lets
you drop them without a suite. Use `--shake` when you have a suite and want the dependency
closure shaken; use `--slim-python` when you just want the interpreter furniture gone.

## Why it is opt-in, and never the default

Shipping PBS **unmodified** is what makes `INV-SUPPLY-01` meaningful: the staged interpreter
is byte-for-byte the pinned artifact the publisher released, verified against a digest, and a
third party can repeat that check against the release. Pruning it breaks that property — the
tree in the binary no longer matches any published artifact. So a default build prunes
**nothing**, and `--slim-python` earns the trade back by two rules (`INV-SHAKE-05`):

- **Prune only after verification.** `thick.stage` fetches and digest-verifies the
  interpreter (`bundle_python`, `INV-SUPPLY-01`) *before* a single file is removed. The chain
  is "verified publisher artifact, then these N files removed by haru-pack", never "some tree
  we assembled".
- **Record what was removed.** Every removed path (and its size) lands on the build receipt,
  so the provenance is auditable rather than implicit.

## The tkinter trap — read this before you use the flag

`--slim-python` removes tkinter and the whole Tcl/Tk stack. A project that imports `tkinter`
will fail at runtime, on the user's machine, on first run — which is exactly the failure the
third user in [`PRINCIPLES.md`](PRINCIPLES.md) must never see. The same applies to any project
that shells out to `pip` or `ensurepip` at runtime: uv does the installing in a packed app, so
they are gone.

Static import detection is not enough — `__import__("tkinter")`, a plugin that imports it, a
GUI code path your smoke test never reaches. That is precisely why this is opt-in and not a
default, and why `--shake` (which *does* observe) keeps tkinter unless the run touched it.
**If your app might use tkinter, pip or ensurepip, do not pass `--slim-python`.**

## What is removed

| Removed | Why it is safe to drop |
|---|---|
| `tkinter/`, `lib-dynload/_tkinter*`, `libtcl*`/`libtk*`/`tcl8*`/`tk8*` and friends | the GUI stack — unreachable unless you `import tkinter` |
| `site-packages/pip/`, `pip-*.dist-info` | uv does the installing; the app never imports pip |
| `ensurepip/` (incl. its bundled wheels) | only `python -m ensurepip` reads it |
| `idlelib/` | the bundled IDE |
| `pydoc_data/` | topic text for interactive `help()` |
| `include/` | C headers — only to *compile* extensions against the interpreter |
| `share/man/` | man pages |

`share/terminfo/` is **kept** — a console app needs it — as is the entire stdlib. The set is
matched prefix-free against every path suffix, so an upstream layout that nests the tree under
`python/install/` cannot silently disable a rule (the trap that once made `--shake`'s
interpreter prune a no-op).

## The receipt

A `--slim-python` build records `slim_python` on the build receipt: the file count, the bytes
freed, and **every** removed path. When someone asks "what is different about this interpreter
from the published PBS release", that list is the answer.

## Related

- `--shake`, the evidence-based tree-shaker: [`SHAKE.md`](SHAKE.md)
- Tiers, and why thick carries what it carries: [`TIERS.md`](TIERS.md)
- `INV-SHAKE-05` and `INV-SUPPLY-01` in [`../INVARIANTS.md`](../INVARIANTS.md).

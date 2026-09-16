# `--shake` — tree-shaking a thick payload

```sh
haru-pack build ./myproject --thick --shake
```

A `--thick` payload carries the whole dependency closure, because that is what the tier
promises. But a closure resolved by a **resolver** is much larger than the set of files a
**program** opens. `--shake` runs the project's own test suite under a file-access tracer,
keeps what was touched, and deletes the rest — then rebuilds the environment from the
pruned payload and re-runs the suite. If that fails, the build fails.

This is the same bet `slim` (formerly docker-slim) makes for container images, made the
same way: observe a real execution, keep what was touched, verify the result. It does not
read your code and reason about it.

## The honest limit, first

**A passing test suite is evidence about the suite, not about the program.** A code path
your tests never exercise is invisible to observation, and if the only thing reaching a
file is that path, `--shake` will delete it.

That is why the flag is opt-in, why it refuses to run without a declared test command, why
it keeps the static closure of every lazy import inside a kept module, and why it writes
down every file it removed. It does not claim a shaken payload is safe. It claims the
payload was observed running, re-proven afterwards, and that you can see exactly what
changed.

If your suite is thin, `--shake` is a bad idea and the fix is the suite.

## What actually happens

**1. Observe.** The declared test command runs against the *bundled* interpreter, in an
environment `uv` built from the *bundled* cache — so every path the tracer sees maps onto
a file that is really in the payload. Tracing your project's own `.venv` instead would
observe a different resolution against a different Python.

`strace -e trace=%file` when it is available, and that preference is not stylistic:
strace sees `openat` from anywhere in the process tree, which is the only way to observe a
shared library `dlopen`ed from inside a C extension — the exact case that makes torch's
CUDA libraries prunable. A Python audit hook is the fallback; it cannot see that, so a
payload shaken without strace keeps native libraries it might not need. The receipt records
which tracer ran.

A test command that exits non-zero prunes nothing (`INV-SHAKE-03`). A red suite is the
worst possible input: everything after the first failure went unexecuted, so it all looks
prunable — and that is exactly when the apparent saving is largest.

**2. Prune.** The observed set is intersected with rules that keep things whose absence
breaks *importability* rather than a feature:

| Always kept | Why |
|---|---|
| `*.dist-info/**` | `importlib.metadata`, entry points, and uv's install bookkeeping all read it |
| `*.data/**`, `*.pth` | the wheel's non-purelib payload; a `.pth` runs at interpreter start |
| `__init__.py` on any retained path | `import a.b.c` executes `a/__init__.py` first |
| the static closure of every **lazy** import | see below |
| the project's own code | small, yours, and the last thing a packager should delete |
| anything matching `--shake-keep` / `[shake] keep` | your override, and it wins over the trace |

Dropped:

| Dropped | Why |
|---|---|
| files in a runtime dist that nothing opened | the feature |
| dists outside the `--no-dev` resolution, whole | pytest and friends are the *measuring device*, not a dependency. Since `INV-PAYLOAD-03` this is mostly defence in depth — a plain `--thick` build no longer warms the cache with dev groups — but the rule stays, because the observation run *does* touch those files and a keep set built from it would otherwise vote to keep them |
| `simple-*`, `builds-*`, `interpreter-*` uv cache buckets | only a *resolve* reads them, and thick resolves at build time |
| CPython's `test/`, `idlelib/`, `turtledemo/`, `pydoc_data/`, `ensurepip/_bundled/`, `config-*/`, `include/` | cannot be imported at all, or exist to *compile against* the interpreter |
| the Tk/Tcl family, if the run never touched `tkinter` | 10–20 MB spread across four directories |

An **unrecognised** uv cache bucket is kept, not dropped: a future uv that stores something
load-bearing under a new name must not be pruned by a rule written before it existed.

The bundled interpreter is pruned by **rule**, not by observation, and that asymmetry is
deliberate — the stdlib is where lazy and conditional imports are densest (`encodings`
resolved by name, codecs chosen by locale), so "delete every stdlib file the run did not
open" buys tens of megabytes and risks a failure your suite cannot see.

Nothing is `unlink`ed. Files move to a quarantine directory, which is what makes the
receipt truthful.

### The lazy-import closure

The break observation cannot see:

```python
def upload(path):
    import boto3          # the suite never calls upload()
```

A module-level import runs when its module is imported, so the tracer already saw it. A
function-level one did not. So every kept `.py` is parsed and **all** of its import
statements, at any nesting depth, are resolved against the files in the payload,
transitively.

Note what this does *not* pull back: a `.so`, a model weight, a bundled browser. Nothing
reaches those through an `import` statement — so the closure protects importability while
leaving the gigabyte-scale native payload prunable. That asymmetry is why `--shake` can be
both conservative and worth running.

**3. Verify.** A fresh environment is built from the pruned cache with `UV_OFFLINE=1` and
the bundled interpreter — the same thing the launcher does on the target — and the suite
runs against it. Anything less than a pass fails the build (`INV-SHAKE-01`). There is no
"warn and ship it unshaken": that hands you a binary many times the size you asked for,
and you would find out from `ls -l` or not at all.

The test tooling is installed into that environment from the *build host's* cache
afterwards, since the payload no longer contains it. If a dev dependency pins a different
version of a runtime dist, uv can reinstall that dist whole and un-pruned — so every pruned
path is re-checked for absence *before* the suite runs (`INV-SHAKE-02`). A false green here
would be worse than no verification at all.

## The receipt

Every shaken build writes `<out>.shake.json` next to the binary: the tracer, every dropped
path, per-dist kept/dropped counts and bytes, and the verification result. When someone
reports "it works on your machine and `ImportError`s on mine", that file is the answer.
A summary (`shaken`, `tracer`, `dropped_files`, `freed_bytes`, `verified`) also goes into
the payload manifest.

## Configuration

```toml
[shake]
test = ["pytest", "-q"]                    # required (or discovered: a tests/ dir is enough)
also_run = [["python", "-m", "myapp", "--selftest"]]   # extra observation runs
keep = ["torch/lib/libtorch_cpu.so"]       # never prune, whatever the trace says
follow_lazy_imports = true                 # the AST closure above
shake_interpreter = true                   # the CPython rulepack
```

`--shake-keep GLOB` is the same as `keep`, repeatable, for the one-off.

`also_run` is the highest-value knob for a thin suite: a `--selftest` entry point that
exercises the app's real startup path observes far more than unit tests do.

## When it refuses

| Situation | Why |
|---|---|
| no `--thick` | at thin/default the dependencies are not in the payload; uv fetches them on the target. Nothing to prune |
| `--target` is not this host | observing means *running* the suite, and this host cannot run that binary |
| a bare PEP 723 script | no dependency group to run a suite from, no declared test command |
| no test command | `INV-SHAKE-03` — no evidence, no deletion |
| the suite fails after pruning | `INV-SHAKE-01` — nothing is shipped |

## What it is worth

Measured on `examples/shake-demo` (pandas + requests, a suite exercising one reduction),
`--thick` on Linux x86_64, 2026-09-10:

| | payload unpacked | payload zipped |
|---|---|---|
| `--thick` | 285.4 MB | 92.1 MB |
| `--thick --shake` | 231.9 MB | **75.9 MB** |

6 395 files removed, 53.9 MB uncompressed: 34.2 MB of dependencies (pandas 1 193 files,
numpy 753), 13.3 MB of interpreter, 6.3 MB of uv cache buckets.

> **These figures predate `INV-PAYLOAD-03`** and are left as measured rather than adjusted
> by arithmetic. A plain `--thick` build no longer warms the bundled cache with the dev
> group, so the 285.4 MB baseline is now smaller and `--shake`'s *marginal* saving is
> correspondingly less than the table shows — roughly 6.5 MB of it (11 dists: pytest,
> pluggy, iniconfig, pygments, hatchling, editables, pathspec, tomlkit, trove-classifiers,
> packaging) is now never downloaded instead of being pruned afterwards. Re-measure before
> quoting this table.
>
> **They also predate `INV-PAYLOAD-06`** (2026-09-15), which stopped the payload storing
> python-build-standalone's symlink targets once per alias. That takes ~35 MB off the
> *zipped* column of any thick build, baseline and shaken alike, so both zipped figures here
> are high by roughly that much. It does not change the unpacked column — the aliases are
> re-created as copies at stage time — nor the "13.3 MB of interpreter" that `--shake`
> prunes, which is measured on the unpacked tree.

**Set your expectations from the floor, not the percentage.** A thick payload contains a
`uv` binary (~55 MB unpacked, a single executable — unprunable) and a CPython. That is the
bulk of what is left above, and it is why a shaken thick binary lands around 50–60 MB
however hard you shake it.

Which means the interesting case is the one where the dependencies dwarf that floor. A
CPU-only inference app on torch ships gigabytes of CUDA kernels it never `dlopen`s; that is
where the order-of-magnitude claim lives, and it is a claim about *native* dead weight, not
about Python files. For a project whose deps are already small, `--shake` mostly buys you
the interpreter rulepack and the dev-group drop, and is not worth the build time.

## Related

- Tiers, and why thick carries what it carries: [`TIERS.md`](TIERS.md)
- `tools/file-trace.py` — the tracer as a standalone diagnostic. Answers "what does this
  command actually open, under this directory, biggest-unused first" for any command, not
  just a haru-pack payload.
- `INV-SHAKE-01` … `INV-SHAKE-04` in [`../INVARIANTS.md`](../INVARIANTS.md).
  `INV-SHAKE-04` is `proposed`, not implemented: a shaken binary does not yet fail at
  startup with a pointer to its own receipt when a pruned import is hit.

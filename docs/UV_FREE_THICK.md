# Design: a thick tier that ships no `uv` at all

> **Status: NOT PURSUED.** Decided 2026-09-10, after the design was worked out and its
> load-bearing assumption was validated empirically. This document exists so that the
> reasoning, the measurements, and the one finding that kills the *obvious* version of the
> idea are not rediscovered from scratch. Nothing here is committed scope. Do not start
> implementing it because it looks finished — read "Why we are not doing it" first.

## The idea

At `--thick`, everything is already resolved and cached at build time. `uv`'s only job on
the target is to build a virtualenv out of the bundled cache on first run. If the build
shipped an already-installed dependency tree instead, the target would need no `uv`, and the
largest single item in the payload could leave it entirely.

## What it is actually worth (revised down)

This is the first thing to know, because it changed after `INV-PAYLOAD-04` landed:

| | unpacked | in the exe |
|---|---|---|
| `uv` before compression | 55.59 MB | 22.25 MB (DEFLATE) |
| `uv` today, XZ-compressed | 55.59 MB | **14.17 MB** |

So removal is now worth **~14 MB of exe**, not the ~22 MB it was worth before, and not the
55 MB that the unpacked figure suggests. Compressing uv already captured 8 MB of the prize
for a much smaller change. Any future case for this work has to be made against 14 MB, and
against a `--thick` binary that is ~85 MB (measured) — so it is roughly a 17% cut, not an
order-of-magnitude one.

There is a real secondary benefit that is not about size: at thick, a payload that ships no
`uv` has no third-party executable in it at all, which simplifies the story an operator
tells their security reviewer.

## The finding that kills the obvious version

**Do not ship a prebuilt virtualenv.** It cannot be made to work cross-platform, and
cross-platform is a hard constraint for this project.

A venv is not relocatable *across operating systems*: it needs `Scripts/` with `.exe`
console-script stubs on Windows versus `bin/` with shebang scripts on POSIX, and a
`pyvenv.cfg` naming an interpreter path. You cannot create a Windows venv from Linux with
`python -m venv`. So a prebuilt-venv thick tier would work on the host and fall back to
bundling uv for every cross target — a host/cross fork where the host path is the novel,
less-tested one. That is precisely the shape the README rejects:

> **One code path, not two.** Where there used to be a fork — a "fast path" for the host —
> the fast path was the unverified one, and it was the path almost everyone took.

## The version that does work

Ship a flat `--target` install tree and put it on `PYTHONPATH`. No venv, no uv.

```sh
# host, or cross — installing wheels for another platform is just unzipping,
# so no target-native code is executed at build time
uv pip install --only-binary :all: --target <payload>/vendor/site \
    [--python-platform windows --python-version 3.13] -r <locked reqs>
```

At runtime the launcher runs the bundled interpreter directly:

```
PYTHONPATH=<stage>/vendor/site  PYTHONNOUSERSITE=1  <stage>/vendor/python/bin/python -m myapp
```

**Validated 2026-09-10** on `examples/shake-demo` (pandas + requests): the app imports and
runs correctly from such a tree with `PYTHONPATH` alone — including numpy's vendored
`numpy.libs/*.so`, which the dynamic loader finds through its `$ORIGIN` RPATH exactly as it
does inside a venv. No `.pth` files and no `*.data/scripts` directories appeared for that
dependency set.

Two things make this feasible that would not be obvious:

1. **`uv pip install --python-platform windows --only-binary :all: --target` already exists
   in this codebase** — `bundle.warm_cache_windows` uses it to resolve Windows wheels from
   Linux, then throws the resulting tree away. The cross path is not new work; it is work
   that is currently discarded.
2. **Entrypoints are already argv.** `entrypoints.resolve_entrypoint` reduces a console
   script or `module:callable` to an argv list at *build* time, deliberately, "so the
   launcher never parses it". That means no generated console-script shims are needed —
   which is the single biggest reason a venv would otherwise be required.

## Open problems, none of them known-fatal

- **`.pth` files.** `PYTHONPATH` does not process them; `site.addsitedir()` does. Packages
  using setuptools-style namespace packages emit them. Handling means generating a tiny
  `sitecustomize.py` into the stage that calls `site.addsitedir(vendor/site)` — which also
  gets `.pth` processing for free. None appeared for pandas/requests, so this is unproven
  either way and would need a `flex` sweep across real projects before being trusted.
- **A second execution path in the launcher.** `main.nim` currently runs everything through
  `uv run` (`uv_run_args`, `verbose_uv`, `UV_OFFLINE`). A uv-free thick tier means a direct
  interpreter invocation as well. It is defensible for the tier to decide which is used, but
  it doubles the launcher's execution surface and both paths then need the full test matrix.
- **`pre_install` / `post_install`.** These are documented as running via `uv run` in the
  project env. They would need a direct-interpreter equivalent. `post_install` at thick is
  already warned against by `INV-TIER-02`, so the surface is smaller than it looks.
- **sdist-only dependencies still cannot cross.** `--only-binary :all:` is what makes cross
  installs safe, so a dependency with no wheel remains a host-only thick build — the same
  limitation the current cross path already has, not a new one.
- **Dead manifest fields.** `cache_dir`, `fetch_uv`, `uv_version` become meaningless for
  thick. A field nothing reads is a field someone later mistakes for load-bearing, so they
  would have to be removed for that tier rather than left set-and-ignored.
- **Windows is unverified.** The validation above was Linux-only. numpy on Windows finds its
  DLLs via `os.add_dll_directory` relative to `__file__`, which should behave the same in a
  `--target` tree, but "should" is not a measurement.

## What it contradicts

`docs/TIERS.md` states, as an invariant enforced by `tiers.bundles_uv()`:

> **uv is bundled in every tier except `thin`.** haru-pack never assumes the target machine
> already has uv […] `thin` is the sole opt-out and it pays for that with a first-run
> download.

That statement is about not assuming uv is *present on the target*. A uv-free thick tier does
not violate its intent — it removes the need for uv rather than assuming a system copy — but
it does falsify the sentence as written, and `bundles_uv()` is the single source of truth for
both the bundler and the manifest's `fetch_uv` flag. So this is a tier-design change with a
documented invariant to amend, not a patch.

## Why we are not doing it

- The prize dropped to ~14 MB of exe once uv shipped compressed, while the change is the
  largest single edit to the launcher's run path since it was written.
- It adds a second way to execute the payload, in the component whose whole design argument
  is that it has one.
- The `.pth` question is unresolved and is exactly the kind of thing that works on every
  project you try and then breaks on a customer's.
- `--shake` already attacks thick's size where the mass actually is — the dependency closure
  and the interpreter — and did so without touching the launcher.

## What would change the decision

- A concrete target where ~14 MB matters and `--thin`/`--default` are not options (an
  air-gapped install with a hard artifact size cap).
- An operator or security review that objects to shipping a third-party executable inside a
  signed artifact at all. This is the strongest argument for the work and it is not about
  size.
- A `flex` sweep showing `.pth` usage is negligible or mechanically handleable across the
  real-project corpus, which would retire the main unknown.

## Bonus, if it is ever built

`--shake` gets simpler, not harder. It currently maps traced paths back into
`vendor/cache/archive-v0/<opaque-id>/` trees by relative path. Against a flat `--target`
tree the observed path *is* the payload path, so the mapping step — and the
`_index_archives` / dist-identification machinery behind it — largely disappears.

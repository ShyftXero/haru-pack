# flex exam — running the top-N PyPI proof

The flex **exam** (`tools/exam.py`) is the PROOF that a haru-pack thick binary carries a *working*
library: for every top-N PyPI package it fetches the **sdist** (tests almost never ship in the
wheel — they ride in the source distribution), finds the package's own test tree, ships it into a
thick binary whose entrypoint runs `pytest`, and runs that binary **with the network denied**. A
pass means the packed payload ran the package's real suite offline.

This runbook is the manual command sequence to refresh the ranking to a fresh **top-1000** and sit
the exam on the **top-250**. Run it wherever a thick build works (locally, or a long-run box like
`xps` — see the last section).

## Prerequisites

- `haru-pack` importable + on PATH (or `.venv/bin/haru-pack`), with a working thick toolchain
  (`haru-pack bootstrap` — a bundled `zig cc` is enough; no sudo needed on a set-up box).
- Network for the *build* phase (PyPI sdist + wheel fetches). The *run* phase denies network on
  purpose, so a pass proves offline operation.
- Python for the tools: `./.venv/bin/python` below is the repo venv.

## The chain

```
fetch-top-pypi.py  →  flex/sources.toml   (the ranking extract, COMMITTED)
gen-package-manifest.py -n 250  →  flex/packages.toml   (the top-250 matrix, COMMITTED)
exam.py refresh    →  rank/version/repo metadata for the page (network)
exam.py run        →  builds+runs each package, writes flex/exam-results.json (the ledger)
exam.py emit       →  renders top_n_pypi_stats.md from the ledger (offline, no AI)
```

## Step 1 — fresh top-1000 ranking (network)

```sh
# Pull today's PyPI download ranking (hugovk/top-pypi-packages), keep the top 1000.
./.venv/bin/python tools/fetch-top-pypi.py --keep 1000

# It writes flex/sources.toml (committed extract + provenance: source URL, upstream
# timestamp, snapshot sha256) and a gitignored raw snapshot under flex/snapshots/.
# The ranking changes monthly, so review the diff before committing:
git diff flex/sources.toml
```

## Step 2 — generate the top-250 matrix

```sh
# Walk the ranking, skip curated-out entries (flex/curation.toml), take the top 250.
./.venv/bin/python tools/gen-package-manifest.py -n 250

# Verify it is a pure function of sources.toml + curation.toml (no hand edits):
./.venv/bin/python tools/gen-package-manifest.py --check
git diff flex/packages.toml
```

## Step 3 — sit the exam on the top 250

```sh
# Optional but recommended: refresh rank/version/repo metadata for the generated page.
./.venv/bin/python tools/exam.py refresh

# Build a thick binary per package, ship its sdist test tree, run pytest offline.
# HEAVY: 250 thick builds + suites. Keep -j low (each staging is memory-heavy). Idempotent —
# already-passed packages are skipped, so a killed run resumes where it stopped.
./.venv/bin/python tools/exam.py run --top-n 250 -j 2 \
    --timeout 1800 --run-timeout 420

# Re-run everything (including passes):   ... run --top-n 250 --rerun-passed
# One package while debugging:            ... run --only numpy,idna
```

## Step 4 — render the page

```sh
# Pure formatting over flex/exam-results.json — offline, never AI-written, reproducible.
./.venv/bin/python tools/exam.py emit
git diff top_n_pypi_stats.md
```

Results live in `flex/exam-results.json` (the ledger, committed) and `top_n_pypi_stats.md` (the
generated page). A `❌` is not always a packaging defect — a suite may need a system library, a
display, or the network the exam denies on purpose; each row records its reason.

## Dispatching to the xps long-run box

`xps` (`xps9360.tail8940e.ts.net`, tailnet) is the box for long jobs: 4 cores / 15 GiB, no sudo,
no docker, thick builds work (thin SIGSEGVs there). Source is **rsynced**, not git-cloned (its SSH
key is not registered with GitHub).

```sh
# 1. Sync this branch's tree to the box (excludes the venv/build junk).
rsync -a --delete \
    --exclude .git --exclude .venv --exclude 'busybody/out' --exclude 'flex/out' \
    ~/Dropbox/code/haru-pack/ xps9360.tail8940e.ts.net:~/code/haru-pack/

# 2. Launch under screen (non-login ssh lacks ~/.local/bin on PATH → source env / bash -lc).
#    A completion sentinel to wait on, never a process-name grep.
ssh xps9360.tail8940e.ts.net 'screen -dmS flex250 bash -lc "
  source ~/.local/bin/env
  cd ~/code/haru-pack
  uv venv --python 3.14 && uv pip install -e . >/tmp/flex-setup.log 2>&1
  ./.venv/bin/python tools/exam.py run --top-n 250 -j 2 --timeout 1800 --run-timeout 420 \
      >~/flex250.log 2>&1
  echo EXIT=\$? >>~/flex250.log
"'

# 3. Watch / collect.
ssh xps9360.tail8940e.ts.net 'tail -f ~/flex250.log'          # progress
ssh xps9360.tail8940e.ts.net 'grep EXIT= ~/flex250.log'       # done?
rsync -a xps9360.tail8940e.ts.net:~/code/haru-pack/flex/exam-results.json flex/   # bring the ledger back
./.venv/bin/python tools/exam.py emit                          # render the page locally
```

Note: the top-250 matrix (`flex/packages.toml`) must already be generated (Steps 1–2) in the tree
you rsync, or run Steps 1–2 on the box first. The box has no GitHub push access, so results come
back by rsync.

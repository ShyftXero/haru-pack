#!/usr/bin/env bash
# Regenerate every GIF in docs/media/ from the tapes beside this script.
#
#   docs/tapes/record.sh            # all tapes
#   docs/tapes/record.sh 02         # just the ones whose name starts 02
#
# WHY THE RECORDINGS ARE SCRIPTED RATHER THAN CAPTURED
#
# Every frame in docs/media/ is real output from a real build. The tapes are the source and
# they are committed, so a claim in the docs that rests on a GIF can be re-derived by anyone
# with the repo — the same standard the rest of this project holds itself to. A hand-made
# terminal recording is a screenshot of someone's memory; this is a build log that happens to
# be animated.
#
# WHAT IS STAGED, AND WHY EXACTLY THIS MUCH
#
# The recordings run on a real machine, so they can leak one. Two things are staged and
# nothing else:
#
#   XDG_CACHE_HOME   haru-pack prints the staging path when a packed binary runs, and on a
#                    developer's box that is /home/<you>/.cache/... Pointing it at the demo
#                    root makes that line publishable without editing the image.
#   the working dir  the example programs print their cwd, for the run-in-place demo.
#
# HOME is deliberately NOT faked. An earlier attempt did, and `haru-pack doctor` started
# reporting `nim : None`: the choosenim-installed compiler resolves its own config through
# HOME, so a fake one breaks the toolchain and the recording would have documented a broken
# machine. Nothing prints HOME, so there is nothing to hide.
#
# No secret in these recordings is real. The encryption demo uses a throwaway passphrase that
# exists only in 05-encrypt.tape, and it is passed by environment rather than argv — both
# because that is what the docs tell you to do, and because argv is world-readable in `ps`.
# It is visible in that GIF on purpose, so the reader can see what DEMO_SECRET holds.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
media="$repo/docs/media"
demo="${HARU_DEMO_ROOT:-/tmp/haru-demo}"

command -v vhs >/dev/null || { echo "vhs is not installed: https://github.com/charmbracelet/vhs"; exit 1; }
command -v haru-pack >/dev/null || {
    echo "haru-pack is not on PATH. Activate the environment you want recorded, e.g."
    echo "    source .venv/bin/activate   # or: uv tool install haru-pack"
    exit 1
}

mkdir -p "$media"
# The work tree is rebuilt every run so a recording can never pick up a stale artifact from
# the last one. The CACHE is kept: it holds the XZ-compressed uv, which costs about 100
# seconds to produce and is a pure function of the uv version. Wiping it made every recording
# open with a compression message and pushed the builds past their `Sleep`, so the next
# command got typed into a busy shell and queued instead of running — the GIFs showed a
# prompt that had never returned. Keeping it also matches what a reader sees: the first build
# on a machine pays that cost once, and every build after it does not.
rm -rf "$demo/work"
mkdir -p "$demo/cache" "$demo/work"

# The demo programs. Small on purpose: what is being shown is the packaging, and a big app
# would only make the recording longer without making the point better.
cat > "$demo/work/hello.py" <<'PY'
print("hello from a single binary")
PY

mkdir -p "$demo/work/greeter/greeter"
cat > "$demo/work/greeter/pyproject.toml" <<'PY'
[project]
name = "greeter"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = ["cowsay"]
PY
cat > "$demo/work/greeter/greeter/__init__.py" <<'PY'
PY
cat > "$demo/work/greeter/greeter/__main__.py" <<'PY'
import cowsay
cowsay.cow("packed, shipped, and offline")
PY
cat > "$demo/work/greeter/haru_pack.toml" <<'PY'
entrypoint = ["python", "-m", "greeter"]
PY

# Shown by the run-in-place recording: where the code thinks it lives once it is inside a
# binary, which is the question every packaging tool gets asked and most answer badly.
cat > "$demo/work/whereami.py" <<'PY'
import os
from pathlib import Path

print("cwd              :", Path.cwd())
print("__file__         :", __file__)
print("HARUPACK_EXE_DIR :", os.environ.get("HARUPACK_EXE_DIR", "(not set)"))
PY

export XDG_CACHE_HOME="$demo/cache"
export HARU_DEMO_ROOT="$demo"

# Warm the cache before recording anything. Each tape gives its build a fixed `Sleep` — VHS
# 0.7.2 has no "wait for the prompt" — so a build that runs long does not just make a slower
# GIF, it makes a WRONG one: the next line gets typed while the shell is still busy and ends
# up queued rather than executed. Measured on this box: 100 s cold, 21 s warm, for the same
# default-tier build. The sleeps in the tapes are sized for the warm number.
if [ ! -d "$demo/cache/haru-pack" ]; then
    echo "==> warming the build cache (about two minutes, once per uv version)"
    ( cd "$demo/work" && haru-pack hello.py -o /tmp/haru-demo-warmup >/dev/null 2>&1 ) || {
        echo "::error:: warm-up build failed — recording now would produce wrong GIFs"; exit 1; }
    rm -f /tmp/haru-demo-warmup
fi

status=0
for tape in "$here"/${1:-}*.tape; do
    [ -e "$tape" ] || { echo "no tape matched '${1:-}'"; exit 1; }
    echo "==> $(basename "$tape")"
    vhs "$tape" || status=1
    # VHS records the tape's final `Sleep` as identical trailing frames, and gifski dedupes
    # them — so the end state flashes by at one frame before the loop and the reader never sees
    # the last of the output. Re-assert a ~4s hold on the last frame (byte-level, lossless — no
    # re-encode, no bloat; see tools/gif_hold_last.py) so there is a pause before it loops.
    out="$(sed -nE 's/^Output "([^"]+)".*/\1/p' "$tape" | head -1)"
    if [ -n "$out" ] && [ -f "$repo/$out" ]; then
        python3 "$repo/tools/gif_hold_last.py" 400 "$repo/$out" || status=1
    fi
done

echo
echo "GIFs in $media"
# A recording that leaked a home directory is a recording that has to be redone, and it is
# much cheaper to notice here than in a pull request. Checks the tapes, not the frames — the
# frames are pixels, and the tape is what decides what gets typed.
if grep -rlE "/home/[a-z]" "$here"/*.tape 2>/dev/null; then
    echo "::warning:: a tape above hardcodes a home directory; recordings are not portable"
    status=1
fi
exit "$status"

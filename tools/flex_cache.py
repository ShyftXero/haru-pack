"""`flex-run.py --cache-info` / `--flush-cache`: where the disk went, and what may be freed.

WHAT IS ACTUALLY BIG, MEASURED RATHER THAN ASSUMED

The design for this started from "the sandbox cache volume will fill the disk". It will not.
Measured on the dev box, 2026-09-14:

    ~/.cache/uv          18.9 GB   <- the thing actually filling the disk
    haru-flex-cache       13.5 MB  <- the sandbox volume
    ~/.cache/haru-pack     273 MB
    anonymous run volumes      0   <- `--rm` reaps them; verified by count before and after

The volume stays small because `bundle.warm_cache_and_lock` points `UV_CACHE_DIR` at the
payload's own bundled cache inside the build tree, not at ours. The host cache is where the
bytes are, and most of them have nothing to do with flex.

WHICH IS WHY OWNERSHIP DECIDES WHAT MAY BE DELETED

`haru-flex-cache` is the harness's own, rebuildable, and used by nothing else — a size budget
may remove it without asking. `~/.cache/uv` is shared with every project on the machine, so
this tool reports it, and only ever PRUNES it, and only when a human types `--flush-cache
host`. Automatically deleting 18.9 GB that mostly belongs to someone else's work would be a
much worse bug than a full disk.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import sandbox  # noqa: E402


def _measurable_image(a) -> str:
    """The sandbox image, but only if it already exists.

    Never builds one: `--cache-info` is the command you reach for when the disk is full, and
    building a multi-GB image to measure a 13 MB volume is the opposite of helping.
    """
    if a.no_docker or sandbox.available():
        return ""
    image = f"{sandbox.IMAGE_NAME}:{sandbox.current_tag()}"
    if subprocess.run(["docker", "image", "inspect", image],
                      capture_output=True).returncode != 0:
        return ""
    return image


def cache_command(a) -> int:
    """`--cache-info` / `--flush-cache`. Reports before it removes, and never guesses scope."""
    image = _measurable_image(a)

    if a.flush_cache == "sandbox":
        removed, freed = sandbox.flush_volume(image=image or None)
        print(f"removed {sandbox.CACHE_VOLUME} ({sandbox.human(freed)} freed)" if removed
              else f"{sandbox.CACHE_VOLUME} does not exist; nothing to remove")
        return 0

    if a.flush_cache == "host":
        paths = sandbox.host_cache_paths()
        print(f"pruning {paths['uv']} — this cache is shared with every other project on "
              f"this machine, so it is PRUNED (unreachable entries only), never emptied.")
        return subprocess.run(["uv", "cache", "prune"], text=True).returncode

    print(f"{'what':22} {'size':>10}  where")
    print("-" * 78)
    for label, where, size, owner in sandbox.cache_report(image or None):
        mark = "" if owner == "harness" else "  (shared with this whole machine)"
        print(f"{label:22} {sandbox.human(size):>10}  {where}{mark}")
    print("\n  --flush-cache sandbox   remove the harness's own docker volume")
    print("  --flush-cache host      `uv cache prune` on the shared host cache")
    print("  --max-cache-gb N        prune the sandbox volume before a run if it is over N")
    if not image:
        print("\n  note: the sandbox image is not built, so the volume was not measured.")
    return 0

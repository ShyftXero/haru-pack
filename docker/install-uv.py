#!/usr/bin/env python3
"""Install the uv binary that `src/haru_pack/pins.toml` pins, verifying its digest first.

    python3 install-uv.py <pins.toml> <bindir>

WHY THIS EXISTS RATHER THAN `curl -LsSf https://astral.sh/uv/install.sh | sh`

A thick `haru-pack build` shells out to `uv sync` (`bundle.warm_cache_and_lock`), so the
image needs uv on PATH. Fetching it with the upstream installer would put a SECOND artifact
acquisition path in this repo: its own version, its own (absent) digest check, sitting next
to the pinned-and-verified one that INV-SUPPLY-01 covers. Two paths means the audited one is
not the one that runs.

So this reads the same `pins.toml` everything else reads, and refuses an artifact with no
entry rather than downloading it — the same rule `haru_pack.pins` applies. It is a small
duplicate of that logic on purpose: it runs during `docker build`, before haru-pack is
importable, and a bootstrap step that imports the thing it is bootstrapping is a worse
problem than thirty lines of tomllib.
"""
from __future__ import annotations

import hashlib
import io
import platform
import sys
import tarfile
import tomllib
import urllib.request
from pathlib import Path, PurePosixPath

#: uname machine -> the `asset` field pins.toml uses for a linux-gnu uv tarball.
LINUX_ASSETS = {
    "x86_64": "uv-x86_64-unknown-linux-gnu.tar.gz",
    "aarch64": "uv-aarch64-unknown-linux-gnu.tar.gz",
    "armv7l": "uv-armv7-unknown-linux-gnueabihf.tar.gz",
}


def _request(url: str) -> urllib.request.Request:
    """A request with a real User-Agent.

    Some publishers answer urllib's default `Python-urllib/3.x` with HTTP 403 — nim-lang.org
    does. The failure arrives as a bare Forbidden in the middle of an image build and reads
    like a bad pin or a blocked host, which is a very expensive way to learn about a header.

    It weakens nothing: the digest check is what decides whether the bytes are acceptable,
    and that is unchanged by who we said we were.
    """
    return urllib.request.Request(url, headers={"User-Agent": "haru-pack-image-build"})

def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    pins_path, bindir = Path(argv[1]), Path(argv[2])

    machine = platform.machine()
    asset = LINUX_ASSETS.get(machine)
    if asset is None:
        print(f"no pinned uv asset for linux/{machine}; known: {sorted(LINUX_ASSETS)}",
              file=sys.stderr)
        return 1

    pins = tomllib.loads(pins_path.read_text(encoding="utf-8"))
    entry = next((a for a in pins.get("artifact", [])
                  if a.get("kind") == "uv" and a.get("asset") == asset), None)
    if entry is None:
        # Refused, not downloaded — the same rule pins.toml states for everything else.
        print(f"{asset} has no entry in {pins_path}. Add one with tools/add-pin.py; do NOT "
              f"download it and hash whatever the server sent.", file=sys.stderr)
        return 1

    url, want = entry["url"], entry["sha256"]
    print(f"install-uv: {asset} (uv {entry.get('version')}) from {url}")
    with urllib.request.urlopen(_request(url), timeout=300) as r:
        blob = r.read()

    got = hashlib.sha256(blob).hexdigest()
    if got != want:
        print(f"DIGEST MISMATCH for {asset}\n  pinned: {want}\n  got:    {got}\n"
              f"This is not the artifact this repo pinned. Do not 'fix' the pin.",
              file=sys.stderr)
        return 1

    # Read the ONE member we want straight out of the archive rather than extracting a tree.
    # Nothing attacker-controlled is ever used as a path, so the traversal class of bug that
    # `filter="data"` exists to stop (INV-SUPPLY-03) cannot arise here. That also keeps this
    # working on the image's Python 3.11.2, where `extractall(filter=...)` does not exist yet.
    bindir.mkdir(parents=True, exist_ok=True)
    dest = bindir / "uv"
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        member = next((m for m in tf.getmembers()
                       if m.isfile() and PurePosixPath(m.name).name == "uv"), None)
        if member is None:
            print(f"no `uv` binary inside {asset}", file=sys.stderr)
            return 1
        src = tf.extractfile(member)
        if src is None:
            print(f"could not read `uv` out of {asset}", file=sys.stderr)
            return 1
        dest.write_bytes(src.read())
    dest.chmod(0o755)
    print(f"install-uv: wrote {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

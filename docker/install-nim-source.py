#!/usr/bin/env python3
"""Fetch and verify the pinned Nim SOURCE tarball, and extract it ready to bootstrap.

    python3 install-nim-source.py <pins.toml> <destdir>     # prints the extracted source dir

WHY THIS EXISTS

`haru_pack.toolchain` documents the build hosts choosenim publishes binaries for — linux
x86_64, macOS x86_64/arm64, Windows — and linux **aarch64** is not among them. On that host
Nim has to be built from source, which is what the flex sandbox image does (issue #32).

It is a separate script from `install-uv.py` rather than a flag on it: the two do genuinely
different things once the bytes are on disk (one copies a binary out of an archive, the other
hands a tree to a compiler), and the shared part is thirty lines of download-and-verify that
is cheaper duplicated than abstracted.

WHAT IS AND IS NOT PINNED

The tarball is. Its digest comes from nim-lang.org's own `.sha256` file, not from hashing
whatever the server happened to send, and an artifact with no entry in `pins.toml` is refused
rather than downloaded — the same rule `haru_pack.pins` applies.

The bootstrap stays inside that one artifact: the source archive ships `c_code/` (11,473
prebuilt C files) and a `build.sh` that compiles the bootstrap compiler from them. `build.sh`
is used deliberately; `build_all.sh`, which lives next to it, CLONES csources from git and
would put an unpinned fetch in the middle of a verified chain.
"""
from __future__ import annotations

import hashlib
import io
import sys
import tarfile
import urllib.request
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:                     # 3.9/3.10
    import tomli as tomllib                     # type: ignore


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    pins_path, dest = Path(argv[1]), Path(argv[2])

    pins = tomllib.loads(pins_path.read_text(encoding="utf-8"))
    entries = [a for a in pins.get("artifact", [])
               if a.get("kind") == "nim" and a.get("variant") == "source"]
    if not entries:
        print(f"no `kind = \"nim\", variant = \"source\"` entry in {pins_path}. A source "
              f"build needs a pinned tarball; add one with its publisher's own digest.",
              file=sys.stderr)
        return 1
    if len(entries) > 1:
        # Ambiguity here would mean silently building a different compiler than intended.
        versions = ", ".join(sorted(e.get("version", "?") for e in entries))
        print(f"{pins_path} pins more than one nim source ({versions}); this script cannot "
              f"choose. Leave exactly one.", file=sys.stderr)
        return 1

    entry = entries[0]
    url, want, version = entry["url"], entry["sha256"], entry.get("version", "?")
    print(f"install-nim-source: nim {version} from {url}", flush=True)
    with urllib.request.urlopen(url, timeout=900) as r:
        blob = r.read()

    got = hashlib.sha256(blob).hexdigest()
    if got != want:
        print(f"DIGEST MISMATCH for nim {version}\n  pinned: {want}\n  got:    {got}\n"
              f"This is not the artifact this repo pinned. Do not 'fix' the pin.",
              file=sys.stderr)
        return 1

    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:xz") as tf:
        members = tf.getmembers()
        # filter="data" is 3.12+; this runs on the image's 3.11. Check the paths ourselves
        # rather than skip the check: an absolute path or a `..` escape in an archive we are
        # about to extract as root is exactly INV-SUPPLY-03's concern.
        for m in members:
            p = Path(m.name)
            if p.is_absolute() or ".." in p.parts:
                print(f"refusing {m.name!r}: escapes the extraction directory",
                      file=sys.stderr)
                return 1
            if not (m.isfile() or m.isdir() or m.issym()):
                print(f"refusing {m.name!r}: unexpected member type", file=sys.stderr)
                return 1
        tf.extractall(dest)

    roots = {Path(m.name).parts[0] for m in members if Path(m.name).parts}
    if len(roots) != 1:
        print(f"expected a single top-level directory, got {sorted(roots)}", file=sys.stderr)
        return 1
    src = dest / roots.pop()
    if not (src / "build.sh").exists() or not (src / "c_code").is_dir():
        print(f"{src} has no build.sh + c_code/; this archive cannot bootstrap offline",
              file=sys.stderr)
        return 1

    print(str(src))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

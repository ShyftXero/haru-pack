#!/usr/bin/env python3
"""Install the pinned PREBUILT Nim for this platform. The primary path; compiling is the fallback.

    python3 install-nim-binary.py <pins.toml> <destdir>    # prints the installed prefix
    exit 0   installed
    exit 3   nothing pinned for this platform (the caller may fall back to a source build)
    exit 1   something pinned, and it was wrong — never fall back past this

WHY A BINARY IS THE PRIMARY PATH

Bootstrapping Nim compiles roughly eleven thousand C files. On the platforms choosenim covers
nobody pays that, and there is no reason an arm64 user should either just because upstream
publishes no binary for them. So this repository builds one — from the source tarball already
pinned in `pins.toml`, by `.github/workflows/nim-aarch64.yml` — and pins the result.

WHY EXIT 3 IS A SEPARATE ANSWER FROM EXIT 1

"There is no pin for linux-aarch64" and "there is a pin and the bytes do not match it" must
not lead to the same place. The first is a gap, and falling back to a source build is the
right response. The second is a supply-chain signal, and quietly compiling instead would
erase exactly the evidence worth keeping. A single non-zero exit would have collapsed them.

ON TRUSTING THIS BINARY

Its digest attests to a build WE published, not to something nim-lang.org published — a
different claim, and a weaker one, which is why `provenance` for a binary entry must be the
workflow run URL. Anyone who would rather not run it has `NIM_FROM=source`, which never
consults this file at all.
"""
from __future__ import annotations

import hashlib
import io
import platform
import sys
import tarfile
import urllib.request
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:                     # 3.9/3.10
    import tomli as tomllib                     # type: ignore

NO_PIN_FOR_PLATFORM = 3


def target_platform() -> str:
    machine = {"aarch64": "aarch64", "arm64": "aarch64",
               "x86_64": "x86_64", "amd64": "x86_64"}.get(platform.machine(), platform.machine())
    return f"linux-{machine}"


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
    pins_path, dest = Path(argv[1]), Path(argv[2])
    want_platform = target_platform()

    pins = tomllib.loads(pins_path.read_text(encoding="utf-8"))
    entries = [a for a in pins.get("artifact", [])
               if a.get("kind") == "nim" and a.get("variant") == "binary"
               and a.get("platform") == want_platform]
    if not entries:
        print(f"install-nim-binary: nothing pinned for {want_platform}", file=sys.stderr)
        return NO_PIN_FOR_PLATFORM
    if len(entries) > 1:
        versions = ", ".join(sorted(e.get("version", "?") for e in entries))
        print(f"{pins_path} pins more than one nim binary for {want_platform} ({versions}); "
              f"this script cannot choose. Leave exactly one.", file=sys.stderr)
        return 1

    entry = entries[0]
    url, want, version = entry["url"], entry["sha256"], entry.get("version", "?")
    # stderr: stdout carries the installed prefix and nothing else (see install-nim-source).
    print(f"install-nim-binary: nim {version} for {want_platform} from {url}",
          file=sys.stderr, flush=True)
    try:
        with urllib.request.urlopen(_request(url), timeout=900) as r:
            blob = r.read()
    except Exception as e:                       # noqa: BLE001
        # A pinned artifact that cannot be fetched is a gap, not a mismatch: the network is
        # down, or the release is not public yet. Falling back to source is correct here.
        print(f"install-nim-binary: {url} could not be fetched ({e})", file=sys.stderr)
        return NO_PIN_FOR_PLATFORM

    got = hashlib.sha256(blob).hexdigest()
    if got != want:
        # Deliberately NOT exit 3. Do not let a mismatch turn into a silent source build.
        print(f"DIGEST MISMATCH for nim {version} ({want_platform})\n"
              f"  pinned: {want}\n  got:    {got}\n"
              f"This is not the artifact this repo pinned. Do not 'fix' the pin, and do not "
              f"fall back — find out why.", file=sys.stderr)
        return 1

    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:xz") as tf:
        members = tf.getmembers()
        for m in members:
            p = Path(m.name)
            if p.is_absolute() or ".." in p.parts:
                print(f"refusing {m.name!r}: escapes the extraction directory",
                      file=sys.stderr)
                return 1
        tf.extractall(dest)

    roots = {Path(m.name).parts[0] for m in members if Path(m.name).parts}
    if len(roots) != 1:
        print(f"expected a single top-level directory, got {sorted(roots)}", file=sys.stderr)
        return 1
    prefix = dest / roots.pop()
    if not (prefix / "bin" / "nim").exists():
        print(f"{prefix} has no bin/nim", file=sys.stderr)
        return 1

    print(str(prefix))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

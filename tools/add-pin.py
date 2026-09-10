#!/usr/bin/env python3
"""Add a pinned artifact digest to src/haru_pack/pins.toml, fetched from the publisher.

    python tools/add-pin.py uv 0.10.4 uv-aarch64-unknown-linux-gnu.tar.gz
    python tools/add-pin.py python https://github.com/astral-sh/python-build-standalone/...tar.gz
    python tools/add-pin.py uv 0.11.0 --all      # every asset haru-pack can target

WHY A TOOL AND NOT A COPY-PASTE

A digest is only meaningful if it is the publisher's statement about what they published.
There are two honest ways to get one:

  1. the `<asset>.sha256` sidecar the release publishes, and
  2. the release API's per-asset `digest` field.

This script tries them in that order and records which one it used, next to the value.

There is a third way that looks identical and is NOT equivalent: downloading the artifact
and hashing it yourself. That pins whatever the server sent you — including, if you are
having a bad day, exactly the thing the pin is supposed to catch. This script will not do
that, and neither should you.

If neither channel has a digest, the correct outcome is NO PIN. haru-pack then refuses to
bundle that artifact, which is the safe failure. Do not paste in a locally computed hash to
make the refusal go away.

NO AI REQUIRED. It is a short script over two public URLs; read it and run the pieces by
hand if it ever breaks.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PINS = REPO / "src/haru_pack/pins.toml"

UV_BASE = "https://github.com/astral-sh/uv/releases/download"
UV_API = "https://api.github.com/repos/astral-sh/uv/releases/tags/"
PBS_BASE = "https://github.com/astral-sh/python-build-standalone/releases/download"
PBS_API = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/tags/"

# Kept in step with haru_pack.targets._UV_ASSETS.
UV_ASSETS = [
    "uv-x86_64-unknown-linux-gnu.tar.gz",
    "uv-aarch64-unknown-linux-gnu.tar.gz",
    "uv-armv7-unknown-linux-gnueabihf.tar.gz",
    "uv-x86_64-apple-darwin.tar.gz",
    "uv-aarch64-apple-darwin.tar.gz",
    "uv-x86_64-pc-windows-msvc.zip",
    "uv-aarch64-pc-windows-msvc.zip",
]


def _get(url: str, headers: dict | None = None, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "haru-pack-add-pin"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def from_sidecar(url: str) -> tuple | None:
    try:
        txt = _get(url + ".sha256").decode().strip()
    except Exception:
        return None
    digest = txt.split()[0].strip().lower()
    return (digest, url + ".sha256") if len(digest) == 64 else None


def from_release_api(api_tag_url: str, asset_name: str) -> tuple | None:
    try:
        rel = json.loads(_get(api_tag_url, {"Accept": "application/vnd.github+json",
                                            "User-Agent": "haru-pack-add-pin"}))
    except Exception as e:
        print(f"  release API unavailable: {type(e).__name__} {getattr(e, 'code', '')}",
              file=sys.stderr)
        return None
    for a in rel.get("assets", []):
        if a.get("name") == asset_name:
            dig = (a.get("digest") or "")
            if dig.startswith("sha256:"):
                return (dig[7:], f"release API per-asset digest ({api_tag_url})")
            return None
    return None


def resolve(url: str, api_tag_url: str, asset_name: str) -> tuple | None:
    got = from_sidecar(url)
    if got:
        return got
    print("  no .sha256 sidecar; trying the release API", file=sys.stderr)
    return from_release_api(api_tag_url, asset_name)


def already_pinned(text: str, needle: str) -> bool:
    return needle in text


def append_entry(lines: list) -> None:
    text = PINS.read_text()
    if not text.endswith("\n"):
        text += "\n"
    PINS.write_text(text + "\n".join(lines) + "\n")


def add_uv(version: str, assets: list, retrieved: str) -> int:
    text = PINS.read_text()
    added = 0
    for asset in assets:
        url = f"{UV_BASE}/{version}/{asset}"
        if already_pinned(text, f'asset = "{asset}"') and f'version = "{version}"' in text:
            print(f"= {asset} already pinned for {version}")
            continue
        print(f"* {asset}")
        got = resolve(url, UV_API + version, asset)
        if not got:
            print("  NO DIGEST PUBLISHED — not pinning. haru-pack will refuse this asset.",
                  file=sys.stderr)
            continue
        digest, prov = got
        append_entry(["[[artifact]]", 'kind = "uv"', f'version = "{version}"',
                      f'asset = "{asset}"', f'sha256 = "{digest}"', f'url = "{url}"',
                      f'provenance = "{prov}"', f'retrieved = "{retrieved}"', ""])
        text = PINS.read_text()
        added += 1
        print(f"  pinned {digest[:16]}… via {prov.split('(')[0].strip()}")
    return added


def add_python(url: str, retrieved: str) -> int:
    text = PINS.read_text()
    if already_pinned(text, f'url = "{url}"'):
        print("= already pinned")
        return 0
    if not url.startswith(PBS_BASE):
        print(f"refusing: {url} is not a python-build-standalone release URL", file=sys.stderr)
        return 0
    tag = url.split("/download/")[1].split("/")[0]
    name = url.rsplit("/", 1)[-1].replace("%2B", "+")
    print(f"* {name}")
    got = resolve(url, PBS_API + tag, name)
    if not got:
        print("  NO DIGEST PUBLISHED — not pinning. haru-pack will refuse this interpreter.",
              file=sys.stderr)
        return 0
    digest, prov = got
    append_entry(["[[artifact]]", 'kind = "python"', f'url = "{url}"', f'sha256 = "{digest}"',
                  f'provenance = "{prov}"', f'retrieved = "{retrieved}"', ""])
    print(f"  pinned {digest[:16]}… via {prov.split('(')[0].strip()}")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kind", choices=["uv", "python"])
    ap.add_argument("args", nargs="*", help="uv: <version> [asset]   python: <url>")
    ap.add_argument("--all", action="store_true", help="uv: pin every targetable asset")
    ap.add_argument("--date", default="", help="value for `retrieved` (default: today, UTC)")
    a = ap.parse_args()

    if not PINS.exists():
        print(f"{PINS} not found", file=sys.stderr)
        return 1

    retrieved = a.date
    if not retrieved:
        import datetime
        retrieved = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    if a.kind == "uv":
        if not a.args:
            ap.error("uv needs a version, e.g. `add-pin.py uv 0.11.0 --all`")
        version = a.args[0]
        assets = UV_ASSETS if (a.all or len(a.args) == 1) else a.args[1:]
        n = add_uv(version, assets, retrieved)
    else:
        if len(a.args) != 1:
            ap.error("python needs exactly one release URL")
        n = add_python(a.args[0], retrieved)

    print(f"\n{n} entry/entries added to {PINS.relative_to(REPO)}")
    if n:
        print("Review the diff before committing: git diff src/haru_pack/pins.toml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

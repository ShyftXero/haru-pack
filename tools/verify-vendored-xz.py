#!/usr/bin/env python3
"""Re-derive the vendored xz-embedded decoder from upstream and prove it is unmodified.

    python tools/verify-vendored-xz.py            # verify against the pinned tag
    python tools/verify-vendored-xz.py --tags     # also list upstream tags

WHAT THIS ADDS OVER THE EXISTING CHECK

`tests/test_uv_compression.py::test_the_vendored_decoder_matches_its_recorded_digests`
(`INV-PAYLOAD-05`) proves the vendored files match the digests in `PROVENANCE.md` and that
no undeclared file sits alongside them. That catches drift *inside this repository* — but
both halves of it live in this repository, so a commit that edited a `.c` file and updated
its recorded digest in the same breath passes.

The tarball SHA-256 in `PROVENANCE.md` is the only link back to upstream, and until this
script existed nothing ever checked it. This closes that loop: fetch the tag, verify the
archive digest, and compare every vendored file byte-for-byte with the file it came from.
A green run means what ships inside every signed launcher is upstream's code, unmodified.

It needs the network, so it is NOT a unit test. It runs weekly in `vendored-xz.yml`, which
is also how a moved tag would be noticed — a retagged release is a supply-chain event, and
the digest here is what makes it visible.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
XZ_DIR = REPO / "src" / "haru_pack" / "launcher" / "xz"
PROVENANCE = XZ_DIR / "PROVENANCE.md"
UPSTREAM = "tukaani-project/xz-embedded"

# Vendored name -> path inside the upstream tarball. This mapping is the thing a reviewer
# needs in order to re-derive the vendoring by hand, so it is also written into
# PROVENANCE.md's table rather than living only here.
WHERE = {
    "xz.h":            "linux/include/linux/xz.h",
    "xz_crc32.c":      "linux/lib/xz/xz_crc32.c",
    "xz_dec_lzma2.c":  "linux/lib/xz/xz_dec_lzma2.c",
    "xz_dec_stream.c": "linux/lib/xz/xz_dec_stream.c",
    "xz_lzma2.h":      "linux/lib/xz/xz_lzma2.h",
    "xz_private.h":    "linux/lib/xz/xz_private.h",
    "xz_stream.h":     "linux/lib/xz/xz_stream.h",
    "xz_config.h":     "userspace/xz_config.h",
}


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "haru-pack-vendor-check"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def pinned() -> tuple[str, str]:
    """(tag, tarball sha256) as recorded in PROVENANCE.md."""
    text = PROVENANCE.read_text()
    tag = re.search(r"tag `([^`]+)`", text)
    digest = re.search(r"Tarball SHA-256 \| `([0-9a-f]{64})`", text)
    if not tag or not digest:
        sys.exit("PROVENANCE.md does not record a tag and tarball digest in the expected shape")
    return tag.group(1), digest.group(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tags", action="store_true", help="list upstream tags as well")
    args = ap.parse_args()

    tag, want_sha = pinned()
    url = f"https://github.com/{UPSTREAM}/archive/refs/tags/{tag}.tar.gz"
    print(f"pinned tag : {tag}\nupstream   : {url}\n")

    blob = _get(url)
    got_sha = hashlib.sha256(blob).hexdigest()
    if got_sha != want_sha:
        print(f"TARBALL DIGEST MISMATCH\n  recorded {want_sha}\n  fetched  {got_sha}\n\n"
              "The tag moved, or the archive changed under us. Do not update the recorded\n"
              "digest to make this pass — find out why it changed first.")
        return 1
    print(f"tarball sha256 matches PROVENANCE.md: {got_sha}\n")

    # One member read at a time; no tree extraction, so no traversal risk.
    members: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
            if rel in WHERE.values():
                f = tf.extractfile(m)
                if f:
                    members[rel] = f.read()

    bad = 0
    for name, rel in sorted(WHERE.items()):
        ours = XZ_DIR / name
        if not ours.exists():
            print(f"MISSING LOCALLY  {name}")
            bad += 1
            continue
        if rel not in members:
            print(f"MISSING UPSTREAM {name}  (expected at {rel})")
            bad += 1
            continue
        a = hashlib.sha256(ours.read_bytes()).hexdigest()
        b = hashlib.sha256(members[rel]).hexdigest()
        if a == b:
            print(f"identical  {name:16} {a[:12]}  <- {rel}")
        else:
            print(f"DIFFERS    {name:16} ours {a[:12]} upstream {b[:12]}  <- {rel}")
            bad += 1

    unmapped = {p.name for p in XZ_DIR.iterdir() if p.suffix in (".c", ".h")} - set(WHERE)
    if unmapped:
        print(f"\nvendored files with no upstream mapping: {sorted(unmapped)}")
        print("Every vendored file must be traceable to an upstream path. Add it to WHERE,")
        print("or remove it — an unmapped file is C in a signed binary with no provenance.")
        bad += len(unmapped)

    if args.tags:
        try:
            tags = [t["name"] for t in json.loads(
                _get(f"https://api.github.com/repos/{UPSTREAM}/tags"))]
            print("\nupstream tags:", ", ".join(tags[:10]))
            print("NOTE: upstream's tag names are not consistently formatted "
                  "(v20240322, v2024-04-05, v2024-12-30), so 'is there a newer one' cannot "
                  "be decided by sorting. Read the list.")
        except Exception as e:                       # informational only; never fails the run
            print(f"\ncould not list tags: {e}")

    print()
    if bad:
        print(f"DRIFT: {bad} problem(s). The vendored decoder is NOT upstream's code.")
        return 1
    print("OK: every vendored file is byte-identical to upstream " + tag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Vendored: xz-embedded (XZ/LZMA2 **decoder only**)

Third-party C compiled into every launcher haru-pack builds — including the ones operators
Authenticode-sign. It is vendored rather than fetched so that what ships is what is in this
repository, reviewable in a diff, and pinned by the commit rather than by a network fetch at
build time (`INV-SUPPLY-01`'s reasoning, applied to source instead of a binary).

| | |
|---|---|
| Upstream | <https://github.com/tukaani-project/xz-embedded> |
| Version | tag `v2024-12-30` |
| Tarball | `https://github.com/tukaani-project/xz-embedded/archive/refs/tags/v2024-12-30.tar.gz` |
| Tarball SHA-256 | `ee12fa8c49c9c0ef4a144af4234d2530d786c1ce14247a7d5fc92a946628977d` |
| License | 0BSD (BSD Zero Clause) — see `COPYING` upstream |
| Author | Lasse Collin / Igor Pavlov (LZMA algorithm) |
| Retrieved | 2026-09-10 |

## Why this library

It is the decoder the Linux kernel uses to boot XZ-compressed kernels (`lib/xz/`), so it is
about as widely exercised as C gets. It is **decoder-only** — there is no compressor here to
audit, because compression happens at build time in Python's `lzma` stdlib module. It has no
dependencies beyond `memcpy`/`memmove`/`memset`, which is what lets it cross-compile to
Windows and ARM with no target-side library. The alternatives were worse for exactly that
reason: every LZMA/zstd option in nimble is a *binding* to a system library, which would put
a runtime dependency on the target machine and break the promise that a haru-pack binary
needs nothing preinstalled.

## What is vendored, and what is deliberately not

| File | Lines | Role |
|---|---|---|
| `xz.h` | 448 | public API |
| `xz_dec_lzma2.c` | 1345 | LZMA2 decoder |
| `xz_dec_stream.c` | 984 | `.xz` container framing |
| `xz_crc32.c` | 58 | CRC32 for the stream check |
| `xz_private.h`, `xz_stream.h`, `xz_lzma2.h` | 453 | internal headers |
| `xz_config.h` | 138 | upstream's userspace (non-kernel) config |

**Not vendored:** `xz_dec_bcj.c` (BCJ branch-conversion filters), `xz_crc64.c`,
`xz_dec_syms.c` (kernel module symbol exports), `xz_dec_test.c`, `xz_sha256.c`. The build
side compresses with a plain LZMA2 filter chain and CRC32 — no BCJ, no CRC64 — so those
files would be unreachable code inside a signed binary. Keeping them out is the point: the
smaller the vendored surface, the smaller the thing a reviewer has to read.

`XZ_DEC_BCJ` is therefore *not* defined. If a future change ever compresses with a BCJ
filter (it would shrink an x86 binary further), `xz_dec_bcj.c` has to be vendored in the
same commit or the decoder will reject the stream at runtime, on the customer's machine.

## Updating it

1. Download the new tag's tarball and record its SHA-256 in the table above.
2. Copy the same file list. Do not add files without reading them.
3. Re-run `pytest tests/test_uv_compression.py`, which round-trips a real payload through
   the vendored decoder on the host and asserts byte-identity.
4. Cross-compile check, because the header include path is the thing that breaks:
   `haru-pack build examples/hello-script --target windows-x86_64`.

## Per-file SHA-256 as vendored

```
e6373b6d1aa11535260e153d8d7c62485ce82fbcb1d9dd66e6d984025771eec6  xz_crc32.c
248dcd23e186b179a3fd1f5150c70cde13670521251e62bc44b15c99241491c4  xz_dec_lzma2.c
bb5d29c33bd29b7d7993ae6b1a60f1750c509b1935fe2d28d46dfd8c5f46e9ce  xz_dec_stream.c
59196b9c8296815f6a029f26d202bcd404078e27fc6e9bc4077db5f6865664c7  xz.h
25fba71668254ba56709e9c176521a24a304b5521a9a337fb51d8334fa07e875  xz_config.h
5681cf01bdcfab8907c02194eeaf9d4415166b3b5d48b50a34df809276f63aa1  xz_lzma2.h
9d8d116354cca408ef17a10cd544a955ea5d26e8f9f50885e99adab9135917d5  xz_private.h
89e80af27003ad39f3122ad447861ec574fa235a0c6339c26bb48a53c3d9e12b  xz_stream.h
```

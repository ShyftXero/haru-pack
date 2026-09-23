#!/usr/bin/env python3
"""Hold a GIF's LAST frame for N centiseconds, in place, at the byte level.

    tools/gif_hold_last.py 400 docs/media/03-tiers.gif [more.gif ...]   # 400cs = 4s

Why this exists: VHS records each tape's final `Sleep` as many identical trailing frames, and
its gif encoder (gifski) dedupes them — so the end state flashes by at ~1 frame before the
animation loops, and the reader never sees the last of the output. This re-asserts a hold on
the final frame so there is a ~3-4s pause before the loop.

Why byte-level and not ImageMagick: re-encoding through ImageMagick de-optimizes the delta
frames and ~3x's the file (and coalesce+optimize to undo that is slow and memory-hungry). A
GIF frame's delay lives in a 2-byte, little-endian, centisecond field inside its Graphic
Control Extension (`0x21 0xF9 0x04 <packed> <delay_lo> <delay_hi> <transparent> 0x00`). We
walk the GIF89a block structure, find the LAST GCE, and rewrite just those two bytes — so the
pixels, frame count, and file size are otherwise untouched. `docs/tapes/record.sh` calls this
after every `vhs` render so a re-record keeps the hold.
"""
import struct
import sys


def _skip_subblocks(b: bytearray, i: int) -> int:
    """Advance past a GIF sub-block chain: <len><len bytes>... terminated by a 0x00 length."""
    while True:
        n = b[i]
        i += 1
        if n == 0:
            return i
        i += n


def set_last_delay(path: str, delay_cs: int) -> int:
    b = bytearray(open(path, "rb").read())
    if b[:3] != b"GIF":
        raise ValueError(f"{path}: not a GIF")
    i = 13  # header(6) + logical screen descriptor(7)
    if b[10] & 0x80:  # global color table present
        i += 3 * (2 ** ((b[10] & 0x07) + 1))
    last_delay_off = None
    while i < len(b):
        blk = b[i]
        if blk == 0x3B:  # trailer
            break
        if blk == 0x21:  # extension introducer
            if b[i + 1] == 0xF9:  # graphic control extension -> delay is b[i+4:i+6]
                last_delay_off = i + 4
            i = _skip_subblocks(b, i + 2)
        elif blk == 0x2C:  # image descriptor
            imgpacked = b[i + 9]
            i += 10
            if imgpacked & 0x80:  # local color table
                i += 3 * (2 ** ((imgpacked & 0x07) + 1))
            i += 1  # LZW minimum code size
            i = _skip_subblocks(b, i)  # image data sub-blocks
        else:
            raise ValueError(f"{path}: unexpected block 0x{blk:02x} at offset {i}")
    if last_delay_off is None:
        raise ValueError(f"{path}: no graphic control extension (no animated frame) found")
    struct.pack_into("<H", b, last_delay_off, delay_cs)
    open(path, "wb").write(b)
    return last_delay_off


def main(argv: list) -> int:
    if len(argv) < 3:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    delay = int(argv[1])
    for p in argv[2:]:
        off = set_last_delay(p, delay)
        print(f"{p}: last-frame delay -> {delay}cs (patched @ byte {off})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

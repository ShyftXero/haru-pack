#!/usr/bin/env python3
"""uvcannon: append a payload blob + fixed footer to a launcher PE.
Footer (68B, little-endian) matches docs/PLAN.md and src/overlay.nim:
  magic "UVCANON1"(8) | format_ver u16 | flags u16 |
  payload_off u64 | payload_len u64 | payload_sha256(32) | tail "1NONACVU"(8)
Run BEFORE signing. Authenticode cert table is appended AFTER this footer;
the reader scans backward for the magic, so the footer stays locatable.
"""
import hashlib, struct, sys
MAGIC=b"UVCANON1"; TAIL=b"1NONACVU"
def attach(exe, payload, out, flags=0):
    stub=open(exe,"rb").read()
    blob=open(payload,"rb").read()
    off=len(stub)                      # payload starts right after the PE
    sha=hashlib.sha256(blob).digest()
    footer=MAGIC+struct.pack("<HHQQ",1,flags,off,len(blob))+sha+TAIL
    assert len(footer)==68, len(footer)
    open(out,"wb").write(stub+blob+footer)
    print(f"attached: payload_off={off} payload_len={len(blob)} sha256={sha.hex()}")
if __name__=="__main__":
    attach(*sys.argv[1:4])

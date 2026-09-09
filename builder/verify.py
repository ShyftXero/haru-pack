#!/usr/bin/env python3
"""Prove the footer + payload survive an appended Authenticode cert table.
Scans backward for MAGIC (footer is NOT at EOF once signed), re-hashes the
payload slice, and reports whether it still verifies."""
import hashlib, struct, sys
MAGIC=b"HARUPACK"; TAIL=b"KCAPURAH"
data=open(sys.argv[1],"rb").read()
i=data.rfind(MAGIC)
assert i!=-1, "footer magic not found"
footer=data[i:i+68]
assert footer[60:68]==TAIL, "tail sentinel mismatch"
ver,flags,off,ln=struct.unpack("<HHQQ",footer[8:28])
sha=footer[28:60]
payload=data[off:off+ln]
ok=hashlib.sha256(payload).digest()==sha
tail_after=len(data)-(i+68)
print(f"footer_at={i} file_len={len(data)} bytes_after_footer={tail_after}")
print(f"format_ver={ver} payload_off={off} payload_len={ln}")
print(f"payload_sha_ok={ok}")
sys.exit(0 if ok else 1)

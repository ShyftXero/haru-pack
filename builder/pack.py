#!/usr/bin/env python3
"""haru-pack: pack a payload dir into a zip and append it to a launcher.
Usage: pack.py <launcher> <payload_dir> <out_exe>"""
import io, os, sys, zipfile
sys.path.insert(0, os.path.dirname(__file__))
from attach import attach
def pack(launcher, payload_dir, out):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(payload_dir):
            for fn in files:
                full = os.path.join(root, fn)
                z.write(full, os.path.relpath(full, payload_dir))
    tmpzip = out + ".payload.zip"
    open(tmpzip, "wb").write(buf.getvalue())
    attach(launcher, tmpzip, out)
    os.remove(tmpzip)
if __name__ == "__main__":
    pack(*sys.argv[1:4])

"""INV-PAYLOAD-02 and INV-SUPPLY-03.

Read the Note on INV-PAYLOAD-02 before trusting these: they cover the BUILD-TIME check
only. The shipped launcher does not verify its payload digest at all (INV-LAUNCH-01,
`proposed`). A green suite here is not evidence that distributed binaries self-verify.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from haru_pack.archives import safe_extract_tar
from haru_pack.overlay import attach, verify

SRC = Path(__file__).resolve().parent.parent / "src/haru_pack"


@pytest.fixture
def built(tmp_path):
    stub = tmp_path / "stub"
    stub.write_bytes(b"\x7fELF" + b"\x00" * 4096)
    payload = b"PK\x03\x04" + bytes(range(256)) * 8
    out = tmp_path / "app"
    info = attach(stub, payload, out)
    return out, payload, info


@pytest.mark.invariant("INV-PAYLOAD-02")
def test_untouched_binary_verifies(built):
    out, payload, info = built
    got = verify(out)
    assert got["sha_ok"] is True
    assert got["payload_len"] == len(payload)


@pytest.mark.invariant("INV-PAYLOAD-02")
@pytest.mark.parametrize("index", [0, 17, 1024, -1])
def test_any_payload_mutation_is_detected(built, index):
    out, payload, info = built
    data = bytearray(out.read_bytes())
    pos = info["payload_off"] + (index % len(payload))
    data[pos] ^= 0xFF
    out.write_bytes(bytes(data))
    assert verify(out)["sha_ok"] is False, (
        "a modified payload still verified — the build-time integrity check is decorative"
    )


@pytest.mark.invariant("INV-PAYLOAD-02")
def test_footer_survives_data_appended_after_it(built):
    """A signed PE gets its certificate table appended at EOF after we attach. The footer
    is located by backward scan precisely so that still works."""
    out, payload, info = built
    out.write_bytes(out.read_bytes() + b"\xde\xad\xbe\xef" * 512)
    got = verify(out)
    assert got["sha_ok"] is True
    assert got["bytes_after_footer"] == 2048


@pytest.mark.invariant("INV-PAYLOAD-02")
def test_missing_footer_is_an_error_not_a_pass(tmp_path):
    plain = tmp_path / "notours"
    plain.write_bytes(b"\x7fELF" + b"\x00" * 1024)
    with pytest.raises(ValueError):
        verify(plain)


@pytest.mark.invariant("INV-SUPPLY-03")
def test_no_unfiltered_tar_extraction_in_the_source():
    """Every tarfile extraction must go through archives.safe_extract_tar.

    Red-path: call `tarfile.open(...).extractall(dest)` anywhere under src/ and this
    goes red. Grep-based guards are usually weak; this one is appropriate because the
    property IS syntactic — the danger is the call shape itself.
    """
    offenders = []
    for p in SRC.rglob("*.py"):
        if p.name == "archives.py":
            continue
        for i, line in enumerate(p.read_text().splitlines(), 1):
            if re.search(r"\.extractall\(", line) and "zipfile" not in line and "z.extractall" not in line:
                offenders.append(f"{p.relative_to(SRC.parent.parent)}:{i}: {line.strip()}")
    assert not offenders, f"unfiltered tar extraction: {offenders}"


@pytest.mark.invariant("INV-SUPPLY-03")
def test_traversing_member_is_rejected(tmp_path):
    """Efficacy, not linkage: build a malicious tar and confirm it cannot escape."""
    import tarfile

    evil = tmp_path / "evil.tar"
    victim = tmp_path / "victim.txt"
    victim.write_text("original\n")
    payload = tmp_path / "payload.txt"
    payload.write_text("pwned\n")
    with tarfile.open(evil, "w") as tf:
        tf.add(payload, arcname="../victim.txt")

    dest = tmp_path / "dest"
    with pytest.raises((ValueError, tarfile.TarError, OSError)):
        safe_extract_tar(evil, dest)
    assert victim.read_text() == "original\n", "path traversal wrote outside the destination"

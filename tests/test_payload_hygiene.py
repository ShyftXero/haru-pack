"""INV-PAYLOAD-01 — credential material never enters a payload.

Red-path: delete `*_SECRET_PATTERNS` from `build._IGNORE`. Every assertion below goes red.
"""
from __future__ import annotations

import io
import zipfile

import pytest

from haru_pack.build import assemble_payload
from haru_pack.payload import build_payload_zip

SECRET_FILES = [
    ".env",
    ".env.production",
    ".envrc",
    "id_rsa",
    "id_ed25519",
    "server.pem",
    "tls.key",
    "keystore.p12",
    "credentials",
    ".npmrc",
    ".pypirc",
    "service-account-prod.json",
]


@pytest.fixture
def leaky_project(tmp_path):
    """A project laid out the way a real one is: source next to the operator's secrets."""
    d = tmp_path / "proj"
    (d / "pkg").mkdir(parents=True)
    (d / "hello.py").write_text("print('hi')\n")
    (d / "pkg" / "__init__.py").write_text("")
    for name in SECRET_FILES:
        (d / name).write_text("SUPER_SECRET_VALUE=abc123\n")
    # and one nested a level down, where a flat top-level check would miss it
    (d / "pkg" / ".env").write_text("NESTED_SECRET=xyz789\n")
    (d / ".ssh").mkdir()
    (d / ".ssh" / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    return d


@pytest.mark.invariant("INV-PAYLOAD-01")
def test_no_credential_file_reaches_the_payload_tree(leaky_project, tmp_path):
    manifest = {"app_subdir": "app", "kind": "script", "entrypoint": ["hello.py"]}
    payload = assemble_payload(leaky_project, manifest, "thin", "host", "3.12",
                               tmp_path / "asm")
    packed = sorted(p.name for p in payload.rglob("*") if p.is_file())
    leaked = [n for n in packed if n in set(SECRET_FILES) | {"id_rsa"}]
    assert not leaked, f"credential material copied into the payload tree: {leaked}"


@pytest.mark.invariant("INV-PAYLOAD-01")
def test_no_secret_value_survives_into_the_payload_zip(leaky_project, tmp_path):
    """Check the shipped *contents*, not just the file names — this still holds if a
    pattern is renamed or a secret arrives under an unexpected filename.

    The first draft of this test searched the raw zip blob and stayed green with the
    guard removed: the payload is DEFLATE-compressed, so the plaintext never appears in
    the container bytes. It asserted linkage, not efficacy. Read the members.
    """
    manifest = {"app_subdir": "app", "kind": "script", "entrypoint": ["hello.py"]}
    payload = assemble_payload(leaky_project, manifest, "thin", "host", "3.12",
                               tmp_path / "asm")
    blob = build_payload_zip(payload)

    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        names = z.namelist()
        contents = {n: z.read(n) for n in names if not n.endswith("/")}

    for needle in (b"SUPER_SECRET_VALUE", b"NESTED_SECRET", b"BEGIN OPENSSH PRIVATE KEY"):
        hits = [n for n, body in contents.items() if needle in body]
        assert not hits, f"{needle.decode()} is readable inside the shipped payload, in {hits}"

    # sanity: the app itself did make it in, so we are not asserting on an empty payload
    assert any(n.endswith("hello.py") for n in names), f"payload is missing the app: {names}"


@pytest.mark.invariant("INV-PAYLOAD-01")
def test_ssh_directory_is_excluded_wholesale(leaky_project, tmp_path):
    manifest = {"app_subdir": "app", "kind": "script", "entrypoint": ["hello.py"]}
    payload = assemble_payload(leaky_project, manifest, "thin", "host", "3.12",
                               tmp_path / "asm")
    assert not list(payload.rglob(".ssh")), "a .ssh directory was copied into the payload"

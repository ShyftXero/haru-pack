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


def test_a_file_with_a_pre_1980_timestamp_still_packs(tmp_path):
    """A payload file whose mtime predates 1980 — an sdist shipped with mtime 0, a zeroed
    vendored artifact — must not fail the build. Zip's DOS date cannot encode a year < 1980 and
    ZipFile.write dies on it; build_payload_zip clamps the date instead and keeps the exec bit.

    Red-path: restore `z.write(p, arc)` in build_payload_zip and this raises ValueError."""
    import os
    import stat as _stat
    (tmp_path / "manifest.toml").write_text('name = "t"\nkind = "script"\n')
    old = tmp_path / "old.py"
    old.write_text("x = 1\n")
    os.utime(old, (0, 0))                       # 1970 — pre-1980
    exe = tmp_path / "vendor" / "uv"
    exe.parent.mkdir()
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    os.utime(exe, (0, 0))
    blob = build_payload_zip(tmp_path)          # must not raise
    z = zipfile.ZipFile(io.BytesIO(blob))
    assert "old.py" in z.namelist()
    info = z.getinfo("vendor/uv")
    assert info.date_time >= (1980, 1, 1, 0, 0, 0), "pre-1980 dates must be clamped to the epoch"
    assert (info.external_attr >> 16) & _stat.S_IXUSR, "the exec bit must survive the clamp"


def test_a_nested_build_package_survives_the_denylist(tmp_path):
    """Root-only anchoring: a source subpackage named `build` (haru-pack has `haru_pack/build/`)
    must be copied, while a top-level `build/` (compiler output) is excluded. A bare any-depth
    `build` pattern dropped the source package and shipped a binary that died with
    `ModuleNotFoundError: No module named 'haru_pack.build'`.

    No git repo here on purpose — this isolates the denylist layer from `.gitignore`.
    Red-path: move `build`/`dist` from `_ROOT_ONLY` back into the any-depth `_IGNORE`.
    """
    from haru_pack.build.tree import copy_app_tree

    src = tmp_path / "proj"
    (src / "pkg" / "build").mkdir(parents=True)            # a source subpackage named "build"
    (src / "pkg" / "__init__.py").write_text("")
    (src / "pkg" / "build" / "__init__.py").write_text("X = 1\n")
    (src / "hello.py").write_text("print('hi')\n")
    (src / "build").mkdir()                                # top-level build OUTPUT (not source)
    (src / "build" / "artifact.o").write_text("junk\n")

    app = tmp_path / "app"
    copy_app_tree(src, app)
    names = {p.relative_to(app).as_posix() for p in app.rglob("*") if p.is_file()}
    assert "hello.py" in names and "pkg/__init__.py" in names, f"source dropped: {names}"
    assert "pkg/build/__init__.py" in names, f"nested source 'build' package dropped: {names}"
    assert "build/artifact.o" not in names, f"top-level build output bundled: {names}"


def test_gitignored_paths_are_not_bundled(tmp_path):
    """copy_app_tree honours `.gitignore` for UNTRACKED ignored junk (a dev box's `.venv`,
    `.claude/` agent worktrees, `.busybody/` run dirs, caches). This is what kept a ~15 MB
    self-build from shipping at 438 MB — a 759 MB gitignored `.claude/` swept in because the
    exclusion was a fixed denylist that had never heard of it. Tracked source is unaffected.

    Red-path: drop the `_git_ignored()` layer from `copy_app_tree`; `logs/` and `debug.log`
    reappear in the copied tree.
    """
    import subprocess

    from haru_pack.build.tree import copy_app_tree

    src = tmp_path / "proj"
    (src / "pkg").mkdir(parents=True)
    (src / "pkg" / "__init__.py").write_text("")
    (src / "hello.py").write_text("print('hi')\n")
    (src / ".gitignore").write_text("logs/\n*.log\n")
    (src / "logs").mkdir()
    (src / "logs" / "huge.bin").write_text("x" * 4096)     # gitignored dir (untracked)
    (src / "debug.log").write_text("noise\n")              # gitignored file (untracked)
    # `git ls-files --exclude-standard` reads the working-tree .gitignore directly, so an init
    # is enough — no commit (and no committer identity / gpg config) needed.
    subprocess.run(["git", "-C", str(src), "init", "-q"], check=True, capture_output=True)

    app = tmp_path / "app"
    copy_app_tree(src, app)
    names = {p.relative_to(app).as_posix() for p in app.rglob("*") if p.is_file()}
    assert "hello.py" in names and "pkg/__init__.py" in names, f"source dropped: {names}"
    assert not any(n.startswith("logs/") for n in names), f"gitignored dir bundled: {names}"
    assert "debug.log" not in names, f"gitignored file bundled: {names}"
    assert ".git" not in {p.name for p in app.rglob("*")}, ".git must never be copied"

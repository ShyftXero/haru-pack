"""INV-LAUNCH-01/02/04/05/06 — the launcher's own integrity and execution gating.

These are end-to-end: every test here compiles the real Nim launcher, appends a real
payload with `overlay.attach()`, and *runs the resulting executable*. Nothing is stubbed
on the launcher side, because the failure this suite exists to prevent was a test that
proved a claim about a binary without ever running one.

`uv` is stood in for by a shell script that prints a marker, so a test can tell WHICH uv
the launcher chose, and so "did it get all the way to execution?" is observable rather
than inferred.
"""
from __future__ import annotations

import io
import os
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest

from haru_pack import crypto
from haru_pack.overlay import attach
from haru_pack.payload import build_payload_zip

REPO = Path(__file__).resolve().parent.parent
LAUNCHER_SRC = REPO / "src/haru_pack/launcher/main.nim"

# Exit codes declared in launcher/main.nim. A distinct code per refusal is the point:
# "it did not run" is not evidence, "it refused for THIS reason" is.
EXIT_DIGEST_MISMATCH = 6
EXIT_INTERNAL = 7
EXIT_BAD_FOOTER = 8
EXIT_NO_UV = 9

pytestmark = pytest.mark.skipif(shutil.which("nim") is None,
                                reason="nim not installed; the launcher cannot be built")


# ---------------------------------------------------------------- build helpers

def _compile(out: Path, *defines: str) -> Path:
    args = ["nim", "c", "-d:release", f"--nimcache:{out.parent / ('nimcache-' + out.name)}",
            f"--out:{out}", *[f"-d:{d}" for d in defines], str(LAUNCHER_SRC)]
    r = subprocess.run(args, capture_output=True, text=True, cwd=REPO)
    if r.returncode != 0 or not out.exists():
        pytest.fail("nim compile failed:\n" + (r.stderr or r.stdout)[-3000:])
    return out


@pytest.fixture(scope="session")
def release_launcher(tmp_path_factory) -> Path:
    return _compile(tmp_path_factory.mktemp("nim-release") / "launcher")


@pytest.fixture(scope="session")
def dev_launcher(tmp_path_factory) -> Path:
    return _compile(tmp_path_factory.mktemp("nim-dev") / "launcher", "haruDev")


def _fake_uv(path: Path, marker: str) -> Path:
    """A stand-in for uv that announces itself and succeeds."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'#!/bin/sh\necho "{marker}"\nexit 0\n')
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def make_payload_dir(root: Path, *, tier: str = "default", uv_marker: str | None = None,
                     entrypoint: str = '["hello.py"]', bundled_python: bool = False,
                     python_as_symlink: bool = False) -> Path:
    """A minimal but *real* payload tree: manifest + app + (optionally) a bundled uv.

    `bundled_python` writes the shape `findBundledPython` looks for — vendor/python/**/bin
    /python3 — which a thick build must have before the launcher will run at all.
    `python_as_symlink` writes the REAL python-build-standalone shape: the interpreter is
    `python3.NN` and `python3`/`python` are symlinks to it, which INV-STAGE-04 stages as
    on-disk symlinks — the case `findBundledPython` must handle.
    """
    root.mkdir(parents=True, exist_ok=True)
    (root / "app").mkdir(exist_ok=True)
    (root / "app" / "hello.py").write_text("print('hi')\n")
    (root / "manifest.toml").write_text(
        'name = "t"\nkind = "script"\napp_subdir = "app"\n'
        f'entrypoint = {entrypoint}\ntier = "{tier}"\n'
        "fetch_uv = false\noffline = false\n")
    if uv_marker:
        _fake_uv(root / "vendor" / "uv", uv_marker)
    if bundled_python:
        bindir = root / "vendor" / "python" / "install" / "bin"
        if python_as_symlink:
            _fake_uv(bindir / "python3.12", "STAGED_PY")
            bindir.joinpath("python3").symlink_to("python3.12")
            bindir.joinpath("python").symlink_to("python3.12")
        else:
            _fake_uv(bindir / "python3", "STAGED_PY")
    return root


def build_exe(launcher: Path, payload: bytes, out: Path, flags: int = 0) -> dict:
    info = attach(launcher, payload, out, flags=flags)
    out.chmod(0o755)
    return info


def run_exe(exe: Path, tmp_path: Path, *, env_extra: dict | None = None,
            path_dirs: list[Path] | None = None) -> subprocess.CompletedProcess:
    """Run a built launcher with a hermetic cache dir and a controlled PATH.

    PATH defaults to empty: this box has a real `uv`, and a test that silently found it
    would be measuring the developer's machine rather than the launcher.
    """
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    env = {"HOME": str(tmp_path / "home"), "XDG_CACHE_HOME": str(cache),
           "PATH": os.pathsep.join(str(p) for p in (path_dirs or []))}
    (tmp_path / "home").mkdir(exist_ok=True)
    env.update(env_extra or {})
    # umask 022: this box runs 002, and stage.nim (correctly) refuses a group-writable
    # stage directory. Pin the child's umask so these tests measure the launcher's gating
    # rather than the developer's umask.
    return subprocess.run([str(exe)], capture_output=True, text=True, cwd=tmp_path,
                          env=env, umask=0o022)


def add_zip_comment(zip_bytes: bytes, comment: bytes) -> bytes:
    """Return the same archive carrying a trailing archive comment.

    A zip comment is ignored by every extractor, which makes it the ideal place to prove
    the digest check has teeth: a byte flipped in here changes the payload's sha256 while
    leaving the extracted tree byte-identical. Without the check the launcher runs the
    modified binary happily; that is exactly the red-path INVARIANTS.md describes.
    """
    buf = io.BytesIO(zip_bytes)
    with zipfile.ZipFile(buf, "a") as z:
        z.comment = comment
    return buf.getvalue()


def flip(exe: Path, offset: int) -> None:
    data = bytearray(exe.read_bytes())
    data[offset] ^= 0xFF
    exe.write_bytes(bytes(data))


# ---------------------------------------------------------------- INV-LAUNCH-01

@pytest.fixture
def commented_payload(tmp_path) -> bytes:
    src = make_payload_dir(tmp_path / "payload", uv_marker="PAYLOAD_UV_RAN")
    return add_zip_comment(build_payload_zip(src), b"C" * 64)


@pytest.mark.invariant("INV-LAUNCH-01")
def test_intact_payload_runs(release_launcher, commented_payload, tmp_path):
    """Baseline: an untouched build gets all the way to executing its bundled uv."""
    exe = tmp_path / "app.exe"
    build_exe(release_launcher, commented_payload, exe)
    r = run_exe(exe, tmp_path)
    assert "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stdout, r.stderr)
    assert r.returncode == 0, (r.stdout, r.stderr)


@pytest.mark.invariant("INV-LAUNCH-01")
def test_benign_payload_edit_is_refused(release_launcher, commented_payload, tmp_path):
    """The efficacy test.

    The flipped byte lands in the zip's archive comment, so the payload still extracts to
    a byte-identical tree — asserted below, not assumed. The ONLY thing that differs is
    the sha256. If the launcher runs this binary, it is not checking its digest; a test
    that mutated compressed data instead could not tell the two cases apart.
    """
    exe = tmp_path / "app.exe"
    info = build_exe(release_launcher, commented_payload, exe)
    victim = info["payload_off"] + info["payload_len"] - 32      # inside the comment
    flip(exe, victim)

    edited = exe.read_bytes()[info["payload_off"]:info["payload_off"] + info["payload_len"]]
    with zipfile.ZipFile(io.BytesIO(commented_payload)) as a, zipfile.ZipFile(io.BytesIO(edited)) as b:
        assert a.namelist() == b.namelist()
        assert all(a.read(n) == b.read(n) for n in a.namelist()), (
            "the mutation was not benign — this test would then prove nothing about the "
            "digest check, only that a broken zip fails to extract")

    r = run_exe(exe, tmp_path)
    assert r.returncode == EXIT_DIGEST_MISMATCH, (r.returncode, r.stdout, r.stderr)
    assert "integrity check FAILED" in r.stderr
    assert "PAYLOAD_UV_RAN" not in r.stdout, "it executed the payload before/despite refusing"


@pytest.mark.invariant("INV-LAUNCH-01")
@pytest.mark.parametrize("where", ["first", "middle", "last"])
def test_payload_mutation_anywhere_is_refused(release_launcher, commented_payload, tmp_path, where):
    exe = tmp_path / "app.exe"
    info = build_exe(release_launcher, commented_payload, exe)
    n = info["payload_len"]
    off = info["payload_off"] + {"first": 0, "middle": n // 2, "last": n - 1}[where]
    flip(exe, off)
    r = run_exe(exe, tmp_path)
    assert r.returncode == EXIT_DIGEST_MISMATCH, (r.returncode, r.stdout, r.stderr)
    assert "PAYLOAD_UV_RAN" not in r.stdout


@pytest.fixture
def encrypted_container(tmp_path) -> bytes:
    src = make_payload_dir(tmp_path / "payload", uv_marker="PAYLOAD_UV_RAN")
    box = crypto.encrypt(build_payload_zip(src), b"s3cret", iters=2000)
    assert box.startswith(crypto.MAGIC)
    return box


@pytest.mark.invariant("INV-LAUNCH-01")
def test_an_intact_encrypted_container_passes_the_digest_check(
        release_launcher, encrypted_container, tmp_path):
    """Ordering, stated as a test.

    `build.build()` encrypts and then hands `attach()` the container, so the footer
    digest covers the CIPHERTEXT. Verify at the wrong layer — against the decrypted zip
    — and every encrypted build exits 6 before it ever asks for a secret. So: an
    untouched encrypted build must get PAST the digest check and on to decryption.

    Deliberately silent about whether decryption then succeeds: crypto.py and
    cryptbox.nim are a different territory, and this invariant is about which bytes the
    launcher hashes, not about the AEAD.
    """
    exe = tmp_path / "app.exe"
    build_exe(release_launcher, encrypted_container, exe, flags=1)
    r = run_exe(exe, tmp_path, env_extra={"HARU_SECRET": "s3cret"})
    assert r.returncode != EXIT_DIGEST_MISMATCH, (
        "an untouched encrypted build failed its own digest check — the digest is being "
        f"taken over the wrong layer ({r.stderr})")
    assert "integrity check FAILED" not in r.stderr


@pytest.mark.invariant("INV-LAUNCH-01")
def test_edited_encrypted_container_is_caught_by_the_digest_before_the_aead(
        release_launcher, encrypted_container, tmp_path):
    """Exit 6 (digest), not 5 (AEAD): proof the hash covered the container, since a
    digest taken over the decrypted zip could not possibly fire here."""
    exe = tmp_path / "app.exe"
    info = build_exe(release_launcher, encrypted_container, exe, flags=1)
    flip(exe, info["payload_off"] + info["payload_len"] - 1)   # last ciphertext byte
    r = run_exe(exe, tmp_path, env_extra={"HARU_SECRET": "s3cret"})
    assert r.returncode == EXIT_DIGEST_MISMATCH, (
        "the digest check must fire on the container, ahead of decryption "
        f"(got {r.returncode}: {r.stderr})")


# ---------------------------------------------------------------- INV-LAUNCH-02

@pytest.fixture
def dev_stage(tmp_path) -> Path:
    return make_payload_dir(tmp_path / "devstage", uv_marker="DEV_UV_RAN")


@pytest.mark.invariant("INV-LAUNCH-02")
def test_release_build_ignores_dev_stage_env(release_launcher, commented_payload,
                                             dev_stage, tmp_path):
    """A release launcher must not be redirectable to an attacker-chosen tree."""
    exe = tmp_path / "app.exe"
    build_exe(release_launcher, commented_payload, exe)
    r = run_exe(exe, tmp_path, env_extra={"HARUPACK_DEV_STAGE": str(dev_stage)})
    assert "DEV_UV_RAN" not in r.stdout, (
        "HARUPACK_DEV_STAGE redirected a RELEASE launcher — a signed binary that runs "
        "code from any directory an environment variable names")
    assert "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stdout, r.stderr)


@pytest.mark.invariant("INV-LAUNCH-02")
def test_release_build_does_not_mention_the_dev_variable(release_launcher):
    """The string is compiled out, not merely branched around."""
    assert b"HARUPACK_DEV_STAGE" not in release_launcher.read_bytes()


@pytest.mark.invariant("INV-LAUNCH-02")
def test_dev_build_still_honours_dev_stage(dev_launcher, commented_payload,
                                           dev_stage, tmp_path):
    """The workflow survives; it just needs -d:haruDev. A gate nobody can opt into
    gets deleted or reverted, so prove the opt-in works."""
    exe = tmp_path / "app.exe"
    build_exe(dev_launcher, commented_payload, exe)
    r = run_exe(exe, tmp_path, env_extra={"HARUPACK_DEV_STAGE": str(dev_stage)})
    assert "DEV_UV_RAN" in r.stdout, (r.returncode, r.stdout, r.stderr)


# ---------------------------------------------------------------- INV-LAUNCH-04

@pytest.fixture
def planted_uv(tmp_path) -> Path:
    """A hostile `uv` sitting in PATH, as any local user could arrange."""
    d = tmp_path / "hostile-bin"
    _fake_uv(d / "uv", "PATH_UV_RAN")
    return d


@pytest.mark.invariant("INV-LAUNCH-04")
def test_thick_tier_refuses_a_uv_from_path(release_launcher, planted_uv, tmp_path):
    # interpreter present, uv absent: isolates the uv half of the invariant
    src = make_payload_dir(tmp_path / "payload", tier="thick", bundled_python=True)
    exe = tmp_path / "app.exe"
    build_exe(release_launcher, build_payload_zip(src), exe)
    r = run_exe(exe, tmp_path, path_dirs=[planted_uv])
    assert "PATH_UV_RAN" not in r.stdout, (
        "a thick-tier launcher executed a uv it found on PATH — the tier's offline/"
        "hermetic claim is that it resolves nothing off the host")
    assert r.returncode == EXIT_NO_UV, (r.returncode, r.stdout, r.stderr)
    assert "thick tier" in r.stderr


@pytest.mark.invariant("INV-LAUNCH-04")
def test_thick_tier_prefers_its_own_uv_over_path(release_launcher, planted_uv, tmp_path):
    src = make_payload_dir(tmp_path / "payload", tier="thick", uv_marker="PAYLOAD_UV_RAN",
                           bundled_python=True)
    exe = tmp_path / "app.exe"
    build_exe(release_launcher, build_payload_zip(src), exe)
    r = run_exe(exe, tmp_path, path_dirs=[planted_uv])
    assert "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stdout, r.stderr)
    assert "PATH_UV_RAN" not in r.stdout


@pytest.mark.invariant("INV-LAUNCH-04")
def test_thick_tier_finds_a_symlinked_interpreter(release_launcher, planted_uv, tmp_path):
    """Regression (aaba3f7 / INV-STAGE-04): python-build-standalone ships `bin/python3` as a
    symlink to `python3.NN`, and the launcher now stages it as an on-disk symlink. When it
    does, the thick launcher must still find its own interpreter and run — with the default
    `walkDirRec` filter (`{pcFile}`) `findBundledPython` skipped the symlink, found no name it
    recognised, and every thick POSIX launch died 'no Python interpreter staged'."""
    src = make_payload_dir(tmp_path / "payload", tier="thick", uv_marker="PAYLOAD_UV_RAN",
                           bundled_python=True, python_as_symlink=True)
    exe = tmp_path / "app.exe"
    build_exe(release_launcher, build_payload_zip(src), exe)
    r = run_exe(exe, tmp_path, path_dirs=[planted_uv])
    assert "no Python interpreter staged" not in r.stderr, (r.returncode, r.stdout, r.stderr)
    assert "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stdout, r.stderr)


@pytest.mark.invariant("INV-LAUNCH-04")
def test_thick_tier_refuses_an_interpreter_from_path(release_launcher, tmp_path):
    """The other half of the statement: "never resolves uv OR AN INTERPRETER from PATH".

    With no UV_PYTHON set, uv picks an interpreter off the host. `offline` only stops it
    DOWNLOADING one — a `python3` planted in PATH would still be executed. So a thick
    build with no staged interpreter must refuse rather than proceed.
    """
    src = make_payload_dir(tmp_path / "payload", tier="thick", uv_marker="PAYLOAD_UV_RAN")
    exe = tmp_path / "app.exe"
    build_exe(release_launcher, build_payload_zip(src), exe)
    r = run_exe(exe, tmp_path)
    assert r.returncode == EXIT_NO_UV, (r.returncode, r.stdout, r.stderr)
    assert "no Python interpreter staged" in r.stderr
    assert "PAYLOAD_UV_RAN" not in r.stdout


# -------------------------------- INV-LAUNCH-05 (footer extents) / INV-LAUNCH-06 (W16)

def _footer_field(exe: Path, info: dict, field: str, value: int) -> None:
    """Rewrite payload_off / payload_len in the footer of a built exe."""
    import struct
    data = bytearray(exe.read_bytes())
    i = data.rfind(b"HARUPACK")
    at = i + 12 + (0 if field == "off" else 8)
    data[at:at + 8] = struct.pack("<Q", value)
    exe.write_bytes(bytes(data))


@pytest.mark.invariant("INV-LAUNCH-05")
@pytest.mark.parametrize("field,value", [
    ("off", 2 ** 63), ("len", 2 ** 63), ("off", 2 ** 64 - 1), ("len", 2 ** 64 - 1),
    ("len", 0),
])
def test_hostile_footer_extents_are_refused_cleanly(release_launcher, commented_payload,
                                                    tmp_path, field, value):
    """payloadOff/payloadLen come off disk and used to be cast straight to int and fed to
    setPosition/readStr. Refuse them by size, don't discover the problem by allocating."""
    exe = tmp_path / "app.exe"
    info = build_exe(release_launcher, commented_payload, exe)
    _footer_field(exe, info, field, value)
    r = run_exe(exe, tmp_path)
    assert r.returncode == EXIT_BAD_FOOTER, (r.returncode, r.stdout, r.stderr)
    assert "corrupt payload footer" in r.stderr
    assert "Traceback" not in r.stderr


@pytest.mark.invariant("INV-LAUNCH-05")
def test_payload_overlapping_its_own_footer_is_refused(release_launcher,
                                                       commented_payload, tmp_path):
    exe = tmp_path / "app.exe"
    info = build_exe(release_launcher, commented_payload, exe)
    _footer_field(exe, info, "len", info["payload_len"] + 40)   # eats into the footer
    r = run_exe(exe, tmp_path)
    assert r.returncode == EXIT_BAD_FOOTER, (r.returncode, r.stdout, r.stderr)
    assert "overlaps" in r.stderr


@pytest.mark.invariant("INV-LAUNCH-06")
def test_unparseable_manifest_gives_a_diagnostic_not_a_traceback(release_launcher, tmp_path):
    # built by hand: build_payload_zip validates the TOML, and the point here is what the
    # launcher does with a manifest that got past the builder (or was swapped afterwards).
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.toml", "this is not = = toml [[[\n")
        z.writestr("app/hello.py", "print('hi')\n")
    exe = tmp_path / "app.exe"
    build_exe(release_launcher, buf.getvalue(), exe)
    r = run_exe(exe, tmp_path)
    assert r.returncode == EXIT_INTERNAL, (r.returncode, r.stdout, r.stderr)
    assert "could not start the packaged application" in r.stderr
    # ".nim(" is what a raw Nim traceback frame looks like — `parsetoml.nim(1066)`.
    # Without the handler that is exactly what the end user of a shipped binary sees.
    assert ".nim(" not in r.stderr, "leaked a Nim traceback frame"
    assert "unhandled exception" not in r.stderr
    assert str(LAUNCHER_SRC.parent) not in r.stderr, "leaked a build-machine path"


@pytest.mark.invariant("INV-LAUNCH-06")
def test_empty_entrypoint_does_not_crash(release_launcher, tmp_path):
    src = make_payload_dir(tmp_path / "payload", uv_marker="PAYLOAD_UV_RAN", entrypoint="[]")
    exe = tmp_path / "app.exe"
    build_exe(release_launcher, build_payload_zip(src), exe)
    r = run_exe(exe, tmp_path)
    assert "no entrypoint" in r.stderr, (r.returncode, r.stdout, r.stderr)
    assert r.returncode == 1
    assert "Traceback" not in r.stderr

"""Staging cache (threat model B10) and the runtime uv fetch.

These tests drive the real Nim code. A tiny harness program is written into a temp dir
and compiled against `src/haru_pack/launcher`, so `stageZip`, `unsafeEntryPath`,
`isValidUvVersion`, `checkUvArchive` and `expectedUvSha` are exercised as compiled Nim —
not as text a Python test pattern-matched. Two things in here are source *inspection*
and say so in their names; everything else executes.

Red-paths (all four walked by hand on 2026-09-09, see the run report):
  INV-STAGE-01   make `stageZip` short-circuit on `dirExists(final)` again.
  INV-STAGE-02   make `unsafeEntryPath` return false.
  INV-SUPPLY-04  make `isValidUvVersion` return true.
  INV-SUPPLY-05  make `checkUvArchive` return "".
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
LAUNCHER = REPO / "src" / "haru_pack" / "launcher"

HARNESS_NIM = r'''
import std/[os, strutils]
import stage, uvfetch
import zippy/ziparchives

proc fail(msg: string) =
  stderr.writeLine msg
  quit(3)

proc main() =
  let a = commandLineParams()
  if a.len == 0: quit("usage: harness <cmd> [args]", 2)
  case a[0]
  of "stage":
    try:
      echo stageZip(readFile(a[1]), a[2])
    except CatchableError as e:
      fail("REFUSED: " & e.msg)
  of "extract":
    # zippy's own extractAll, with no haru-pack check in front of it: this is the
    # measurement of what the library does, not of what we hope it does.
    try:
      ziparchives.extractAll(a[1], a[2])
      echo "EXTRACTED"
    except CatchableError as e:
      fail("ZIPPY_REFUSED: " & e.msg)
  of "entrypath":
    if unsafeEntryPath(a[1]):
      fail("UNSAFE")
    echo "SAFE"
  of "uvversion":
    if not isValidUvVersion(a[1]):
      fail("INVALID")
    echo "VALID"
  of "uvcheck":
    let why = checkUvArchive(readFile(a[1]), a[2])
    if why.len > 0:
      fail("REFUSED: " & why)
    echo "OK"
  of "uvsize":
    let why = checkUvArchive(newString(parseInt(a[1])), "")
    if why.len > 0:
      fail("REFUSED: " & why)
    echo "OK"
  of "uvsha":
    echo expectedUvSha(a[1])
  else:
    quit("unknown command " & a[0], 2)

main()
'''


@pytest.fixture(scope="module")
def harness(tmp_path_factory) -> Path:
    """Compile the Nim harness once for the module."""
    if shutil.which("nim") is None:
        pytest.skip("nim not installed; the staging invariants are Nim-side")
    d = tmp_path_factory.mktemp("stageharness")
    src = d / "harness.nim"
    src.write_text(HARNESS_NIM, encoding="utf-8")
    out = d / "harness"
    r = subprocess.run(
        ["nim", "c", "--hints:off", "--warnings:off", f"--path:{LAUNCHER}",
         f"--nimcache:{d / 'nimcache'}", f"--out:{out}", str(src)],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, f"harness failed to compile:\n{r.stdout}\n{r.stderr}"
    return out


def run(harness: Path, *args: str, cache: Path | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if cache is not None:
        env["XDG_CACHE_HOME"] = str(cache)
        env["HOME"] = str(cache)          # belt and braces for the macOS/HOME branch
    return subprocess.run([str(harness), *args], capture_output=True, text=True, env=env)


def base_dir(cache: Path) -> Path:
    return cache / "haru-pack"


def make_zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return path


def make_traversal_zip(path: Path, name: str, data: bytes) -> Path:
    """zipfile.writestr sanitises nothing, but be explicit: write the raw name."""
    with zipfile.ZipFile(path, "w") as z:
        info = zipfile.ZipInfo(name)
        z.writestr(info, data)
    with zipfile.ZipFile(path) as z:
        assert z.namelist() == [name], f"zip does not actually contain {name!r}: {z.namelist()}"
    return path


GOOD_PAYLOAD = {
    "manifest.toml": b'name = "app"\nentrypoint = ["hello.py"]\n',
    "app/hello.py": b"print('hi')\n",
    "app/pkg/mod.py": b"X = 1\n",
}


# --------------------------------------------------------------------- zip slip


def test_zippy_rejects_a_parent_traversal_entry(harness, tmp_path):
    """The measurement the review asked for: does zippy defend, or did we assume it?

    Observed on zippy 0.10.12: it raises `ZippyError: Path ../ not allowed ../escape.txt`
    from `verifyPathIsSafeToExtract`, before writing anything. The assumption held — but
    it is now measured, and `unsafeEntryPath` covers shapes zippy's substring checks miss.
    """
    z = make_traversal_zip(tmp_path / "slip.zip", "../escape.txt", b"pwned\n")
    dest = tmp_path / "dest" / "root"
    dest.parent.mkdir()
    r = run(harness, "extract", str(z), str(dest))
    escape = tmp_path / "dest" / "escape.txt"
    assert not escape.exists(), (
        f"zippy wrote outside the destination: {escape} exists. zippy does NOT defend "
        f"against zip-slip and haru-pack must not rely on it."
    )
    assert r.returncode == 3 and "ZIPPY_REFUSED" in r.stderr, (
        f"zippy neither refused nor escaped; rc={r.returncode} out={r.stdout!r} err={r.stderr!r}"
    )


@pytest.mark.invariant("INV-STAGE-02")
@pytest.mark.parametrize("entry", [
    "../escape.txt",
    "..",
    "a/../../escape.txt",
    "/etc/cron.d/pwn",
    "C:evil.txt",
    "..\\escape.txt",
    "a\\..\\..\\escape.txt",
    "",
])
def test_unsafe_archive_entry_paths_are_rejected(harness, entry):
    r = run(harness, "entrypath", entry)
    assert r.returncode == 3, (
        f"unsafeEntryPath({entry!r}) said SAFE; an archive entry that can leave the "
        f"destination directory would be extracted"
    )


@pytest.mark.invariant("INV-STAGE-02")
@pytest.mark.parametrize("entry", ["manifest.toml", "app/hello.py", "app/pkg/mod.py",
                                   "vendor/python/bin/python3", "a..b/c"])
def test_ordinary_entry_paths_are_accepted(harness, entry):
    r = run(harness, "entrypath", entry)
    assert r.returncode == 0, f"unsafeEntryPath({entry!r}) rejected a legitimate payload path"


@pytest.mark.invariant("INV-STAGE-02")
def test_staging_a_traversal_payload_writes_nothing_outside_the_stage(harness, tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    z = make_traversal_zip(tmp_path / "slip.zip", "../escape.txt", b"pwned\n")
    r = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r.returncode == 3, f"stageZip accepted a traversal payload: {r.stdout!r}"
    assert "REFUSED" in r.stderr
    strays = [p for p in cache.rglob("escape.txt")] + [p for p in tmp_path.glob("escape.txt")]
    assert not strays, f"traversal entry escaped the stage: {strays}"


# ------------------------------------------------------------------ staging cache


@pytest.mark.invariant("INV-STAGE-01")
def test_first_stage_records_a_meaningful_ready_token(harness, tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    z = make_zip(tmp_path / "p.zip", GOOD_PAYLOAD)
    r = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r.returncode == 0, r.stderr
    staged = Path(r.stdout.strip())
    assert (staged / "app" / "hello.py").read_bytes() == GOOD_PAYLOAD["app/hello.py"]

    ready = (staged / ".ready").read_text()
    assert ready.splitlines()[0] == "haru-pack-stage/2", ready
    assert f"payload={hashlib.sha256(z.read_bytes()).hexdigest()}" in ready, ready
    assert f"uid={os.geteuid()}" in ready, ready
    files = (staged / ".stage-files").read_text().splitlines()
    assert {ln.split(" ", 1)[1] for ln in files} == set(GOOD_PAYLOAD), files
    assert f"tree={hashlib.sha256((staged / '.stage-files').read_bytes()).hexdigest()}" in ready

    # second run reuses the same tree and still verifies it
    r2 = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r2.returncode == 0, r2.stderr
    assert Path(r2.stdout.strip()) == staged


@pytest.mark.invariant("INV-STAGE-01")
def test_stage_directory_name_binds_the_payload_digest(harness, tmp_path):
    """64 bits of caller-supplied key is not a cache key you can trust. The directory
    name now carries 128 bits of the payload's own sha256, so two payloads under the
    same key cannot land in the same directory."""
    cache = tmp_path / "cache"
    cache.mkdir()
    key = "aabbccdd11223344"
    a = make_zip(tmp_path / "a.zip", GOOD_PAYLOAD)
    b = make_zip(tmp_path / "b.zip", {**GOOD_PAYLOAD, "app/hello.py": b"print('other')\n"})
    ra = run(harness, "stage", str(a), key, cache=cache)
    rb = run(harness, "stage", str(b), key, cache=cache)
    assert ra.returncode == 0 and rb.returncode == 0, (ra.stderr, rb.stderr)
    da, db = Path(ra.stdout.strip()), Path(rb.stdout.strip())
    assert da != db, "two different payloads shared one stage directory"
    for path, z in ((da, a), (db, b)):
        digest = hashlib.sha256(z.read_bytes()).hexdigest()
        assert path.name == f"{key}-{digest[:32]}", path.name


@pytest.mark.invariant("INV-STAGE-01")
def test_precreated_stage_dir_with_the_old_bare_sentinel_is_refused(harness, tmp_path):
    """The B10 attack: a same-user process pre-creates `<cache>/<key>/` with its own
    code and the one-byte `.ready` the old launcher accepted. The launcher used to
    execute it without looking."""
    cache = tmp_path / "cache"
    cache.mkdir()
    z = make_zip(tmp_path / "p.zip", GOOD_PAYLOAD)
    key = "aabbccdd11223344"
    digest = hashlib.sha256(z.read_bytes()).hexdigest()
    hostile = base_dir(cache) / f"{key}-{digest[:32]}"
    (hostile / "app").mkdir(parents=True)
    (hostile / "app" / "hello.py").write_bytes(b"import os; os.system('id')\n")
    (hostile / ".ready").write_text("1")

    r = run(harness, "stage", str(z), key, cache=cache)
    assert r.returncode == 3, f"the launcher accepted a pre-created stage tree: {r.stdout!r}"
    assert "REFUSED" in r.stderr
    assert (hostile / "app" / "hello.py").read_bytes().startswith(b"import os"), (
        "test bug: the hostile tree was overwritten, so nothing was proven"
    )


@pytest.mark.invariant("INV-STAGE-01")
def test_precreated_stage_dir_without_any_sentinel_is_refused(harness, tmp_path):
    """The sharper form of the same bug: the old `if not dirExists(final): moveDir`
    silently skipped the move and returned the attacker's directory, so the attack did
    not even need a `.ready`."""
    cache = tmp_path / "cache"
    cache.mkdir()
    z = make_zip(tmp_path / "p.zip", GOOD_PAYLOAD)
    key = "aabbccdd11223344"
    digest = hashlib.sha256(z.read_bytes()).hexdigest()
    hostile = base_dir(cache) / f"{key}-{digest[:32]}"
    (hostile / "app").mkdir(parents=True)
    (hostile / "app" / "hello.py").write_bytes(b"import os; os.system('id')\n")

    r = run(harness, "stage", str(z), key, cache=cache)
    assert r.returncode == 3, f"the launcher accepted an unsentinelled stage tree: {r.stdout!r}"
    assert "REFUSED" in r.stderr
    assert (hostile / "app" / "hello.py").read_bytes().startswith(b"import os")


@pytest.mark.invariant("INV-STAGE-01")
def test_modified_staged_file_is_refused_on_reuse(harness, tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    z = make_zip(tmp_path / "p.zip", GOOD_PAYLOAD)
    r = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r.returncode == 0, r.stderr
    staged = Path(r.stdout.strip())
    (staged / "app" / "pkg" / "mod.py").write_bytes(b"import os; os.system('id')\n")

    r2 = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r2.returncode == 3, f"a modified staged file was reused: {r2.stdout!r}"
    assert "modified since staging" in r2.stderr, r2.stderr


@pytest.mark.invariant("INV-STAGE-01")
def test_deleted_staged_file_is_refused_on_reuse(harness, tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    z = make_zip(tmp_path / "p.zip", GOOD_PAYLOAD)
    r = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r.returncode == 0, r.stderr
    staged = Path(r.stdout.strip())
    (staged / "app" / "pkg" / "mod.py").unlink()

    r2 = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r2.returncode == 3, f"an incomplete staged tree was reused: {r2.stdout!r}"
    assert "missing" in r2.stderr, r2.stderr


@pytest.mark.invariant("INV-STAGE-01")
def test_world_writable_stage_dir_is_refused(harness, tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    z = make_zip(tmp_path / "p.zip", GOOD_PAYLOAD)
    r = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r.returncode == 0, r.stderr
    staged = Path(r.stdout.strip())
    staged.chmod(0o777)

    r2 = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r2.returncode == 3, f"a world-writable stage dir was reused: {r2.stdout!r}"
    assert "group/world-writable" in r2.stderr, r2.stderr


@pytest.mark.invariant("INV-STAGE-01")
def test_stage_dir_replaced_by_a_symlink_is_refused(harness, tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    z = make_zip(tmp_path / "p.zip", GOOD_PAYLOAD)
    key = "aabbccdd11223344"
    digest = hashlib.sha256(z.read_bytes()).hexdigest()
    hostile = tmp_path / "elsewhere"
    (hostile / "app").mkdir(parents=True)
    (hostile / "app" / "hello.py").write_bytes(b"import os; os.system('id')\n")
    (hostile / ".ready").write_text("1")
    base_dir(cache).mkdir(parents=True)
    (base_dir(cache) / f"{key}-{digest[:32]}").symlink_to(hostile, target_is_directory=True)

    r = run(harness, "stage", str(z), key, cache=cache)
    assert r.returncode == 3, f"a symlinked stage dir was followed: {r.stdout!r}"
    assert "REFUSED" in r.stderr


@pytest.mark.invariant("INV-STAGE-01")
@pytest.mark.parametrize("key", ["../../etc", "aabb/ccdd", "", "zzzz", "aabb cc"])
def test_non_hex_stage_keys_are_refused(harness, tmp_path, key):
    cache = tmp_path / "cache"
    cache.mkdir()
    z = make_zip(tmp_path / "p.zip", GOOD_PAYLOAD)
    r = run(harness, "stage", str(z), key, cache=cache)
    assert r.returncode == 3, f"stageZip accepted key {key!r}"


def test_no_dead_key_helper_remains():
    """Source inspection, not behaviour: `stage.keyFor` was never called and advertised
    a 'fast non-crypto hash' for a security-adjacent purpose. Dead security-adjacent code
    is a trap for the next reader."""
    src = (LAUNCHER / "stage.nim").read_text(encoding="utf-8")
    assert "keyFor" not in src, "the unused keyFor helper is back in stage.nim"
    # Matched as the import, not as the bare word: `hashes` appears in ordinary prose about
    # what recordTree does, so the substring form failed on a comment that mentioned it.
    assert "std/hashes" not in src, "std/hashes (the non-crypto hash) is imported again"
    assert not re.search(r"^\s*import\s+.*\bhashes\b", src, re.M), (
        "std/hashes (the non-crypto hash) is imported again"
    )


# ---------------------------------------------------------------- runtime uv fetch


@pytest.mark.invariant("INV-SUPPLY-04")
@pytest.mark.parametrize("version", ["0.10.4", "v0.9.2", "1", "1.2.3.4", "0.4.30"])
def test_plain_uv_versions_are_accepted(harness, version):
    r = run(harness, "uvversion", version)
    assert r.returncode == 0, f"isValidUvVersion({version!r}) rejected a real uv version"


@pytest.mark.invariant("INV-SUPPLY-04")
@pytest.mark.parametrize("version", [
    "",
    "../../../../evil/releases/download/1.0",
    "0.10.4/../../../..",
    "0.10.4?x=1",
    "0.10.4#frag",
    "0.10.4 && curl evil.example",
    "@evil.example",
    "https://evil.example/x",
    "0.10.4\nHost: evil",
    "0.1.2.3.4",
    "latest",
    "0" * 40,
])
def test_hostile_uv_version_strings_are_refused(harness, version):
    r = run(harness, "uvversion", version)
    assert r.returncode == 3, (
        f"isValidUvVersion({version!r}) said VALID; it would be interpolated straight "
        f"into the uv download URL"
    )


@pytest.mark.invariant("INV-SUPPLY-05")
def test_uv_archive_matching_the_pinned_digest_is_accepted(harness, tmp_path):
    blob = tmp_path / "uv.tar.gz"
    blob.write_bytes(b"pretend-uv-archive")
    r = run(harness, "uvcheck", str(blob), hashlib.sha256(blob.read_bytes()).hexdigest())
    assert r.returncode == 0, r.stderr


@pytest.mark.invariant("INV-SUPPLY-05")
def test_uv_archive_failing_the_pinned_digest_is_refused(harness, tmp_path):
    blob = tmp_path / "uv.tar.gz"
    blob.write_bytes(b"a malicious uv build")
    pinned = hashlib.sha256(b"pretend-uv-archive").hexdigest()
    r = run(harness, "uvcheck", str(blob), pinned)
    assert r.returncode == 3, "a uv archive that does not match the manifest pin was accepted"
    assert "digest mismatch" in r.stdout + r.stderr


@pytest.mark.invariant("INV-SUPPLY-05")
@pytest.mark.parametrize("pin", ["deadbeef", "zz" * 32, "A" * 64])
def test_malformed_pins_are_refused_rather_than_ignored(harness, tmp_path, pin):
    blob = tmp_path / "uv.tar.gz"
    blob.write_bytes(b"pretend-uv-archive")
    r = run(harness, "uvcheck", str(blob), pin)
    assert r.returncode == 3, f"pin {pin!r} was silently treated as 'no pin'"


@pytest.mark.invariant("INV-SUPPLY-05")
def test_empty_download_is_refused(harness, tmp_path):
    blob = tmp_path / "empty"
    blob.write_bytes(b"")
    r = run(harness, "uvcheck", str(blob), "")
    assert r.returncode == 3


@pytest.mark.invariant("INV-SUPPLY-05")
def test_oversized_uv_archive_is_refused(harness):
    cap = 96 * 1024 * 1024
    ok = run(harness, "uvsize", str(cap))
    assert ok.returncode == 0, ok.stderr
    over = run(harness, "uvsize", str(cap + 1))
    assert over.returncode == 3, "an archive over the size cap was accepted"
    assert "over the" in over.stdout + over.stderr


@pytest.mark.invariant("INV-SUPPLY-05")
def test_expected_digest_travels_in_the_payload_manifest(harness, tmp_path):
    """The thin tier fetches uv on a machine we never see, so the pin has to ride along
    inside the payload. Nothing writes `uv_sha256` yet — that is build-side work — but
    the launcher reads and enforces it today."""
    pin = hashlib.sha256(b"pretend-uv-archive").hexdigest()
    with_pin = tmp_path / "with"
    with_pin.mkdir()
    (with_pin / "manifest.toml").write_text(f'name = "app"\nuv_sha256 = "{pin}"\n')
    assert run(harness, "uvsha", str(with_pin)).stdout.strip() == pin

    without = tmp_path / "without"
    without.mkdir()
    (without / "manifest.toml").write_text('name = "app"\n')
    assert run(harness, "uvsha", str(without)).stdout.strip() == ""


def test_uv_fetch_declares_a_timeout_and_a_cap():
    """Source inspection: a stalled or endless response cannot be provoked from a unit
    test without a network, so the timeout is read, not exercised. Said plainly so this
    is not mistaken for a behavioural proof."""
    src = (LAUNCHER / "uvfetch.nim").read_text(encoding="utf-8")
    assert "FetchTimeoutSecs" in src and "timeout = FetchTimeoutSecs" in src
    assert src.count("timeout = FetchTimeoutSecs") >= 2, "a request went out without a timeout"
    assert "MaxUvArchiveBytes" in src
    assert "fetch(url)" not in src, "the unbounded, untimed puppy fetch() is back"


# ------------------------------------------------------- .haru-links materialisation
#
# The build stores a file symlink's bytes once and lists the aliases in `.haru-links`
# (payload.build_payload_zip). `stage.materialiseLinks` re-creates them as COPIES, before
# `recordTree`, so the staged tree is byte-identical to one from a payload built before
# this existed and every name is inside the sealed manifest.
#
# Both halves of every entry come out of the payload, which is checked against a digest
# that is not a MAC — so the table is untrusted input, and a rewritten one must not become
# an arbitrary-file-write, or a read of something outside the stage.

LINKS = ".haru-links"


def linked_payload(links: bytes, extra: dict[str, bytes] | None = None) -> dict[str, bytes]:
    return {**GOOD_PAYLOAD, "vendor/real.bin": b"REALBYTES\n",
            **(extra or {}), LINKS: links}


def staged_root(out: str) -> Path:
    return Path(out.strip())


@pytest.mark.invariant("INV-PAYLOAD-06")
def test_a_link_entry_is_materialised_as_a_real_copy(harness, tmp_path):
    cache = tmp_path / "cache"; cache.mkdir()
    z = make_zip(tmp_path / "p.zip", linked_payload(b"vendor/alias.bin\tvendor/real.bin\n"))
    r = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r.returncode == 0, r.stderr
    root = staged_root(r.stdout)
    assert (root / "vendor" / "alias.bin").read_bytes() == b"REALBYTES\n"
    assert (root / "vendor" / "real.bin").read_bytes() == b"REALBYTES\n"
    assert not (root / LINKS).exists(), "the link table was left in the staged tree"


@pytest.mark.invariant("INV-PAYLOAD-06")
def test_a_materialised_copy_is_inside_the_recorded_manifest(harness, tmp_path):
    """The whole reason these are copies, not symlinks: walkDirRec skips pcLinkToFile, so a
    symlink here would be absent from .stage-files and verifyTree would never check it."""
    cache = tmp_path / "cache"; cache.mkdir()
    z = make_zip(tmp_path / "p.zip", linked_payload(b"vendor/alias.bin\tvendor/real.bin\n"))
    r = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r.returncode == 0, r.stderr
    recorded = (staged_root(r.stdout) / ".stage-files").read_text()
    assert "vendor/alias.bin" in recorded, (
        "the alias is not in .stage-files, so verifyTree would never check it:\n" + recorded)


@pytest.mark.invariant("INV-PAYLOAD-06")
@pytest.mark.parametrize("table", [
    b"../escape.bin\tvendor/real.bin\n",       # write outside the stage
    b"vendor/alias.bin\t../../etc/passwd\n",   # read outside the stage
    b"/etc/cron.d/x\tvendor/real.bin\n",       # absolute link path
    b"vendor/alias.bin\t/etc/passwd\n",        # absolute target
])
def test_a_link_table_cannot_reach_outside_the_stage(harness, tmp_path, table):
    cache = tmp_path / "cache"; cache.mkdir()
    z = make_zip(tmp_path / "p.zip", linked_payload(table))
    r = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r.returncode == 3, f"materialiseLinks accepted {table!r}: {r.stdout!r}"
    assert "REFUSED" in r.stderr
    assert not (tmp_path / "escape.bin").exists()


@pytest.mark.invariant("INV-PAYLOAD-06")
def test_a_link_to_a_member_the_payload_does_not_have_is_refused(harness, tmp_path):
    cache = tmp_path / "cache"; cache.mkdir()
    z = make_zip(tmp_path / "p.zip", linked_payload(b"vendor/alias.bin\tvendor/ghost.bin\n"))
    r = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r.returncode == 3 and "does not contain" in r.stderr, r.stderr


@pytest.mark.invariant("INV-PAYLOAD-06")
def test_a_link_colliding_with_a_real_member_is_refused(harness, tmp_path):
    """Same rule expandCompressedMembers uses: two sources for one path, refuse to choose."""
    cache = tmp_path / "cache"; cache.mkdir()
    z = make_zip(tmp_path / "p.zip",
                 linked_payload(b"vendor/dup.bin\tvendor/real.bin\n",
                                {"vendor/dup.bin": b"I WAS HERE FIRST\n"}))
    r = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r.returncode == 3 and "refusing to choose" in r.stderr, r.stderr


def test_a_malformed_link_line_is_refused(harness, tmp_path):
    cache = tmp_path / "cache"; cache.mkdir()
    z = make_zip(tmp_path / "p.zip", linked_payload(b"no-tab-here\n"))
    r = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r.returncode == 3 and "malformed" in r.stderr, r.stderr


def test_a_payload_with_no_link_table_still_stages(harness, tmp_path):
    cache = tmp_path / "cache"; cache.mkdir()
    z = make_zip(tmp_path / "p.zip", GOOD_PAYLOAD)
    r = run(harness, "stage", str(z), "aabbccdd11223344", cache=cache)
    assert r.returncode == 0, r.stderr

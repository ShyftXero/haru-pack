"""INV-SHRED-01 — --overwrite shred-on-reap: matching-length overwrite + fsync-before-unlink.

The launcher (Nim) half of --overwrite (docs/adr/0004 §5b). Two kinds of test, mirroring the
split in tests/test_stage_hardening.py (efficacy) and tests/test_stage_callsites.py (invocation):

  * EFFICACY — a tiny Nim harness compiles `stage.overwriteFile`, `stage.shredAndRemoveTree`
    and `stage.shredGuard` and RUNS them, so the overwrite is measured on real bytes on disk,
    not pattern-matched in source. This is the strongest test available: the reaper deletes the
    files, so the overwrite can only be observed by inspecting a file BEFORE the unlink, which
    is exactly what `overwriteFile` (overwrite without delete) lets a test do.
  * INVOCATION / ORDERING — source-shape assertions that the shipping code actually wires the
    shred path (fsync before close; overwrite before removeDir; reapDetached takes `overwrite`;
    main passes `sc.overwrite`; the Windows `--haru-shred` worker is guarded). A guard nothing
    calls is a guard that does not exist (the lesson tests/test_stage_callsites.py records).

The build (Python) half — that `--overwrite` bakes `overwrite = true` into the stub-config and
receipt, requires `--reap`, and stays out of the byte-corpus when off — is in tests/test_canary.py.

Red-path walked 2026-09-11 on this Linux host (neutralize → observe red → restore):
  * INV-SHRED-01  make `stage.overwriteFile` return true WITHOUT writing (`return true` before
                  the write loop) → `test_overwrite_covers_extent_and_changes_content` goes red
                  with CONTENT_UNCHANGED, because the file still holds its original bytes.

See docs/adr/0004-reap-ram-staging.md §5b and the INVARIANTS.md entry.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from _stage_helpers import build_payload_zip, make_payload, pack, run, stage_from, stub_toml2, wait_gone

REPO = Path(__file__).resolve().parent.parent
LAUNCHER = REPO / "src" / "haru_pack" / "launcher"
STAGE_NIM = LAUNCHER / "stage.nim"
MAIN_NIM = LAUNCHER / "main.nim"

VALID_NAME = "0123456789abcdef-0123456789abcdef0123456789abcdef"   # <hexkey>-<32-hex-digest>

HARNESS_NIM = r'''
import std/os
import stage

proc fail(msg: string) =
  stderr.writeLine msg
  quit(3)

proc main() =
  let a = commandLineParams()
  if a.len == 0: quit("usage: harness <cmd> [args]", 2)
  case a[0]
  of "overwrite":
    # Overwrite in place (no delete) so the test can inspect the result: prove the full logical
    # extent was covered, the length is unchanged, and the content is no longer the original.
    let before = readFile(a[1])
    let buf = newShredBuffer()
    let ok = overwriteFile(a[1], buf)
    let after = readFile(a[1])
    if not ok: fail("EXTENT_NOT_COVERED")
    if after.len != before.len: fail("LENGTH_CHANGED")
    if after == before and before.len > 0: fail("CONTENT_UNCHANGED")
    echo "SHREDDED " & $after.len
  of "shredtree":
    shredAndRemoveTree(a[1])
    if dirExists(a[1]): fail("TREE_REMAINS")
    echo "GONE"
  of "guard":
    let why = shredGuard(a[1])
    if why.len > 0: fail("REFUSED: " & why)
    echo "OK"
  else:
    quit("unknown command " & a[0], 2)

main()
'''


@pytest.fixture(scope="module")
def harness(tmp_path_factory) -> Path:
    if shutil.which("nim") is None:
        pytest.skip("nim not installed; the shred invariant is Nim-side")
    d = tmp_path_factory.mktemp("shredharness")
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


def _h(harness: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(harness), *args], capture_output=True, text=True)


# ───────────────────────────────────────────────────────────── efficacy (harness runs the code)

@pytest.mark.invariant("INV-SHRED-01")
def test_overwrite_covers_extent_and_changes_content(harness, tmp_path):
    """overwriteFile rewrites the whole file with random bytes, in place, preserving length.
    Red-path: `return true` at the top of overwriteFile (no write) → CONTENT_UNCHANGED."""
    f = tmp_path / "model.bin"
    f.write_bytes(b"A" * 5000)
    r = _h(harness, "overwrite", str(f))
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert r.stdout.strip() == "SHREDDED 5000"
    data = f.read_bytes()
    assert len(data) == 5000, "overwrite must preserve the logical length"
    # The overwrite is random, so the vast majority of bytes are no longer 'A' (0x41). A few
    # collisions (~1/256) are expected; require it to be overwhelmingly not-the-plaintext.
    assert sum(1 for b in data if b != 0x41) > 4800, "file was not meaningfully overwritten"


@pytest.mark.invariant("INV-SHRED-01")
@pytest.mark.parametrize("size", [1, 4095, 4096, 4097, 1048577])   # spans >1 reuse-buffer
def test_overwrite_preserves_length_across_sizes(harness, tmp_path, size):
    """The write loop covers the full extent for sizes that do and do not straddle the reused
    buffer boundary — the byte-count assertion (written == file length) is what INV-SHRED-01
    guarantees, so an off-by-one in the loop would surface here as EXTENT_NOT_COVERED."""
    f = tmp_path / "blob.bin"
    f.write_bytes(b"\x00" * size)
    r = _h(harness, "overwrite", str(f))
    assert r.returncode == 0, (size, r.stdout, r.stderr)
    assert r.stdout.strip() == f"SHREDDED {size}"
    assert f.stat().st_size == size


@pytest.mark.invariant("INV-SHRED-01")
def test_shredtree_overwrites_then_removes(harness, tmp_path):
    """shredAndRemoveTree overwrites every regular file, then removes the whole tree."""
    tree = tmp_path / "stage"
    (tree / "sub").mkdir(parents=True)
    (tree / "a.txt").write_bytes(b"secret-a\n")
    (tree / "sub" / "b.txt").write_bytes(b"secret-b\n")
    r = _h(harness, "shredtree", str(tree))
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert r.stdout.strip() == "GONE"
    assert not tree.exists()


# ───────────────────────────────────────────────────── shredGuard (the --haru-shred safety net)

@pytest.mark.invariant("INV-SHRED-01")
def test_shredguard_accepts_a_stage_shaped_subtree(harness, tmp_path):
    root = tmp_path / "root"
    sub = root / VALID_NAME
    sub.mkdir(parents=True)
    r = _h(harness, "guard", str(sub))
    assert r.returncode == 0 and r.stdout.strip() == "OK", (r.stdout, r.stderr)


@pytest.mark.invariant("INV-SHRED-01")
def test_shredguard_refuses_a_non_stage_name(harness, tmp_path):
    d = tmp_path / "root" / "notasubtree"
    d.mkdir(parents=True)
    r = _h(harness, "guard", str(d))
    assert r.returncode == 3 and "not a haru-pack stage subtree" in r.stderr, (r.stdout, r.stderr)


@pytest.mark.invariant("INV-SHRED-01")
def test_shredguard_refuses_a_root(harness):
    r = _h(harness, "guard", "/")
    assert r.returncode == 3 and "filesystem root" in r.stderr, (r.stdout, r.stderr)


@pytest.mark.invariant("INV-SHRED-01")
def test_shredguard_refuses_a_symlink(harness, tmp_path):
    """Never shred through a symlink (would reach a target outside the tree)."""
    (tmp_path / "root").mkdir()
    link = tmp_path / "root" / VALID_NAME     # correctly-shaped NAME, but it is a symlink
    link.symlink_to(tmp_path)
    r = _h(harness, "guard", str(link))
    assert r.returncode == 3 and "symlink" in r.stderr, (r.stdout, r.stderr)


@pytest.mark.invariant("INV-SHRED-01")
def test_shredguard_refuses_a_dev_stage_tree(harness, tmp_path):
    root = tmp_path / "root"
    sub = root / VALID_NAME
    sub.mkdir(parents=True)
    env = dict(os.environ, HARUPACK_DEV_STAGE=str(sub))
    r = subprocess.run([str(harness), "guard", str(sub)], capture_output=True, text=True, env=env)
    assert r.returncode == 3 and "DEV_STAGE" in r.stderr, (r.stdout, r.stderr)


# ─────────────────────────────────────────── invocation / ordering (source-shape, no nim needed)

def _body_of(src: str, proc_name: str) -> str:
    m = re.search(rf"^proc {re.escape(proc_name)}\b", src, re.M)
    assert m, f"proc {proc_name} not found — it was renamed or removed"
    rest = src[m.end():]
    nxt = re.search(r"^proc \w", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


@pytest.mark.invariant("INV-SHRED-01")
def test_overwritefile_fsyncs_before_it_closes():
    """fsync/FlushFileBuffers must run BEFORE close (and therefore before the caller unlinks),
    or the FS may drop the dirty overwrite and only the unlink lands. Red-path: delete the
    fsync line → the durability the invariant promises is gone."""
    body = _body_of(STAGE_NIM.read_text(), "overwriteFile")
    assert "fsync(" in body and "flushFileBuffers(" in body, "overwriteFile does not fsync at all"
    # `close(f)` lives in the finally; the fsync must precede it textually.
    fsync_at = body.index("fsync(")
    close_at = body.index("close(f)")
    assert fsync_at < close_at, "overwriteFile closes before it fsyncs"


@pytest.mark.invariant("INV-SHRED-01")
def test_shred_overwrites_before_removing():
    """shredAndRemoveTree must overwrite (fsync) every file BEFORE removeDir unlinks them."""
    body = _body_of(STAGE_NIM.read_text(), "shredAndRemoveTree")
    assert "overwriteFile(" in body and "removeDir(" in body
    assert body.index("overwriteFile(") < body.index("removeDir("), (
        "shredAndRemoveTree removes the tree before overwriting it")


@pytest.mark.invariant("INV-SHRED-01")
def test_reapdetached_wires_overwrite_through_to_the_shredder():
    """reapDetached must take an `overwrite` flag and, when set, drive the native shredder
    (POSIX inline shredAndRemoveTree / Windows --haru-shred re-exec) rather than a plain rm."""
    src = STAGE_NIM.read_text()
    assert re.search(r"proc reapDetached\*\(target: string; overwrite", src), (
        "reapDetached does not take an overwrite flag")
    body = _body_of(src, "reapDetached")
    assert "shredAndRemoveTree(target)" in body, "POSIX overwrite path does not shred natively"
    assert '"--haru-shred", target' in body, "Windows overwrite path does not re-exec --haru-shred"


@pytest.mark.invariant("INV-SHRED-01")
def test_main_reads_overwrite_and_passes_it_to_reap():
    """The launcher must read the baked `overwrite` and hand it to reapDetached with the target."""
    src = MAIN_NIM.read_text()
    assert "reapOverwrite = sc.overwrite" in src, "main does not read the baked overwrite knob"
    assert "reapDetached(reapTarget, reapOverwrite)" in src, (
        "main does not pass overwrite into the detached reaper")


@pytest.mark.invariant("INV-SHRED-01")
def test_windows_haru_shred_worker_is_guarded():
    """The `--haru-shred` re-exec surface is a delete primitive; it must call shredGuard before
    touching anything. Red-path: drop the shredGuard call → a hand-typed path is shredded."""
    src = MAIN_NIM.read_text()
    assert '"--haru-shred"' in src, "no --haru-shred dispatch in main"
    # the dispatch, its guard, and the shred call all appear, guard before the shred
    assert "shredGuard(shredArgs[1])" in src, "--haru-shred worker does not call shredGuard"
    assert src.index("shredGuard(shredArgs[1])") < src.index("shredAndRemoveTree(shredArgs[1])"), (
        "--haru-shred worker shreds before it guards")


# ───────────────────────────────────────────────────────────── end-to-end (real launcher)

@pytest.mark.invariant("INV-SHRED-01")
def test_reap_with_overwrite_removes_only_its_own_subtree(nim_launcher, tmp_path):
    """The shred-on-reap path, exercised through the real launcher: with reap+overwrite baked,
    after the app exits the detached worker overwrites-then-removes the staged subtree it created
    this run, and ONLY that — the base path and a sentinel beside it survive. This drives the
    POSIX inline-shred fork end to end (the overwrite branch of reapDetached)."""
    reapbase = tmp_path / "reapbase"; reapbase.mkdir()
    sentinel = reapbase / "KEEP_ME.txt"; sentinel.write_text("do not delete me\n")
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(reap=True, overwrite=True, base_path=str(reapbase)))
    r = run(exe, tmp_path)
    assert r.returncode == 0 and "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stderr)
    stage = Path(stage_from(r.stdout))
    assert stage.parent == reapbase, stage
    assert wait_gone(stage), f"shred-on-reap did not remove the staged subtree: {stage}"
    assert reapbase.exists(), "shred-on-reap deleted the base path itself"
    assert sentinel.exists(), "shred-on-reap deleted a sibling of its own subtree"

"""uv ships XZ-compressed and is expanded, byte-identical, at stage time (INV-PAYLOAD-04).

The property that makes this preferable to packing the executable with UPX is *byte
identity*: what lands in the stage is exactly the binary Astral published, so its own code
signature survives, its sha256 still matches the pin this repo verified at build time, and
no AV engine sees a packed executable. If that identity ever breaks, the size win is not
worth having — so it is the first thing asserted here.
"""
from __future__ import annotations

import hashlib
import inspect
import lzma
import re
from pathlib import Path

import pytest

from conftest import source_without_comments as code_of
from haru_pack import bundle

LAUNCHER = Path(__file__).resolve().parent.parent / "src/haru_pack/launcher"
XZ_DIR = LAUNCHER / "xz"


@pytest.mark.invariant("INV-PAYLOAD-04")
def test_compress_uv_round_trips_byte_identically(tmp_path):
    """Compress the way the build does, decompress the way the launcher's decoder will,
    and require the same bytes back. Red-path: change the filter chain in `compress_uv`
    (e.g. add a BCJ filter) and this still round-trips in Python but the *launcher* cannot
    read it — which is why the filter assertions below exist as well."""
    raw = bytes(range(256)) * 4096 + b"uv-ish padding" * 500
    uv = tmp_path / "uv"
    uv.write_bytes(raw)
    before = hashlib.sha256(raw).hexdigest()

    n_raw, n_comp, digest = bundle.compress_uv(uv, preset=1)

    assert n_raw == len(raw)
    assert digest == before
    assert not uv.exists(), "the uncompressed uv must not also ship"
    xz = tmp_path / "uv.xz"
    size = tmp_path / "uv.xz.size"
    assert xz.exists() and size.exists()
    assert int(size.read_text()) == len(raw), (
        "the sidecar size is what the launcher allocates; wrong here means a failed "
        "decode on the target"
    )
    assert lzma.decompress(xz.read_bytes()) == raw
    assert hashlib.sha256(lzma.decompress(xz.read_bytes())).hexdigest() == before


@pytest.mark.invariant("INV-PAYLOAD-04")
def test_the_stream_uses_only_filters_the_vendored_decoder_has(tmp_path):
    """`xz_dec_bcj.c` is deliberately NOT vendored, so a BCJ-filtered stream would be
    rejected at runtime — on a customer's machine, after a clean build. The filter chain is
    therefore pinned in code, not left to a preset's defaults.

    Red-path: add `{"id": lzma.FILTER_X86}` to the chain in `compress_uv`. This test goes
    red; without it, only a real target run would catch it.
    """
    src = inspect.getsource(bundle.compress_uv)
    assert "FILTER_LZMA2" in src, "the filter chain is no longer pinned to LZMA2"
    assert "FORMAT_XZ" in src and "CHECK_CRC32" in src
    for bad in ("FILTER_X86", "FILTER_ARM", "FILTER_ARMTHUMB", "FILTER_POWERPC",
                "FILTER_IA64", "FILTER_SPARC", "FILTER_DELTA"):
        assert bad not in src, (
            f"{bad} needs xz_dec_bcj.c (or the delta filter) vendored into "
            f"launcher/xz/; see its PROVENANCE.md"
        )
    # and the decoder really is built without BCJ
    assert not (XZ_DIR / "xz_dec_bcj.c").exists()
    assert "XZ_DEC_BCJ" not in code_of(LAUNCHER / "xzdec.nim")


@pytest.mark.invariant("INV-PAYLOAD-04")
def test_compression_is_cached_so_builds_do_not_pay_it_twice(tmp_path, monkeypatch):
    """Compressing uv at preset 9 takes ~100 s and is a pure function of (bytes, preset).
    Paying that on every build would be a gratuitous regression, so the result is cached.

    Red-path: drop the cache lookup and this goes red — `lzma.compress` gets called twice.
    """
    monkeypatch.setattr(bundle, "cache_calls", 0, raising=False)
    cache = tmp_path / "cache"
    monkeypatch.setattr("haru_pack.paths.user_cache_dir", lambda *a, **k: str(cache),
                        raising=False)
    import haru_pack.paths as paths
    monkeypatch.setattr(paths, "cache_dir", lambda: cache)

    calls = {"n": 0}
    real = lzma.compress

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(lzma, "compress", counting)

    raw = b"repeatable" * 20000
    for i in range(2):
        uv = tmp_path / f"uv{i}"
        uv.write_bytes(raw)
        bundle.compress_uv(uv, preset=1)
    assert calls["n"] == 1, f"compressed {calls['n']} times; the cache is not being used"


@pytest.mark.invariant("INV-PAYLOAD-04")
def test_the_launcher_expands_before_it_records_the_tree():
    """Ordering is the invariant, not an implementation detail.

    `recordTree` hashes every staged file into `.stage-files`, and `verifyTree` re-checks
    them on every reuse. Expanding uv BEFORE that means the expanded binary is inside the
    recorded set, exactly as an uncompressed payload's uv has always been. Expanding it
    lazily at first use would put the one file `main.findUv` executes straight into a tree
    that had already been sealed — i.e. outside the manifest that protects it. That exact
    exemption existed once before; INV-STAGE-01's note records why it was a hole.

    Red-path: move the `expandCompressedMembers(root)` call after `recordTree(root)`.
    """
    src = code_of(LAUNCHER / "stage.nim")
    expand = src.index("expandCompressedMembers(root)")
    record = src.index("let (mf, count) = recordTree(root)")
    assert expand < record, (
        "uv is expanded after the stage manifest is built, so the binary the launcher "
        "executes first is not covered by stage verification"
    )
    # and the compressed forms must not linger in the recorded set
    body = src[src.index("proc expandCompressedMembers"):expand]
    assert "removeFile(full)" in body and "removeFile(sizePath)" in body


@pytest.mark.invariant("INV-PAYLOAD-05")
def test_the_vendored_decoder_matches_its_recorded_digests():
    """The provenance file is the audit trail for third-party C inside a binary operators
    sign. If the files drift from the digests recorded next to them, the audit trail is
    fiction.

    Red-path: edit one byte of `xz_dec_lzma2.c` without updating PROVENANCE.md.
    """
    prov = (XZ_DIR / "PROVENANCE.md").read_text()
    recorded = dict(reversed(m) for m in
                    re.findall(r"^([0-9a-f]{64})  (\S+)$", prov, re.M))
    assert recorded, "PROVENANCE.md records no per-file digests"
    for name, want in recorded.items():
        p = XZ_DIR / name
        assert p.exists(), f"PROVENANCE.md records {name}, which is not vendored"
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        assert got == want, f"{name} does not match its recorded digest"
    on_disk = {p.name for p in XZ_DIR.iterdir() if p.suffix in (".c", ".h")}
    assert on_disk == set(recorded), (
        f"vendored files and PROVENANCE.md disagree: {on_disk ^ set(recorded)}"
    )


@pytest.mark.invariant("INV-PAYLOAD-04")
def test_the_include_path_survives_a_windows_cross_compile():
    """The bug that actually happened: `parentDir()` and `/` use the TARGET's separator, so
    under `-d:mingw` the include path came out as `-I\\home\\you\\...` and mingw could not
    find `xz.h`. A Linux-only build would never notice.

    Red-path: rewrite `xzInc` using `parentDir()` and `/`. This goes red, and
    `--target windows-x86_64` fails to compile.
    """
    src = code_of(LAUNCHER / "xzdec.nim")
    assert "parentDir()" not in src, (
        "xzdec.nim builds its include path with parentDir(), which emits backslashes when "
        "cross-compiling to Windows"
    )
    assert "replace(" in src and "'/'" in src, (
        "the include path is no longer normalised to forward slashes"
    )


@pytest.mark.slow
@pytest.mark.invariant("INV-PAYLOAD-04")
def test_the_real_launcher_compiles_for_host_and_windows(tmp_path):
    """Vendored C plus a cross-compiler is exactly where this breaks, so compile it. Skipped
    when the toolchain is absent rather than silently passing."""
    from haru_pack.bootstrap import find_nim, detect_c_toolchain
    from haru_pack.build import compile_launcher
    from haru_pack.targets import Target

    nim = find_nim()
    if not nim:
        pytest.skip("Nim not installed on this host")
    for name in ("host", "windows-x86_64"):
        tgt = Target.parse(name)
        if not detect_c_toolchain(tgt)["ok"]:
            pytest.skip(f"no C toolchain for {name}")
        out = compile_launcher(nim, tgt, tmp_path / name)
        assert out.exists() and out.stat().st_size > 0


# ------------------------------------ guards added by the adversarial review of 2026-09-11

@pytest.mark.invariant("INV-PAYLOAD-04")
def test_the_build_records_a_digest_of_the_original_bytes(tmp_path):
    """The launcher confirms the expansion produced what was compressed. Without the sidecar
    there is nothing to confirm against and INV-PAYLOAD-04's "byte-identical" is decoration.

    Red-path: drop the `.sha256` write from `compress_uv`. This goes red, and the launcher's
    check silently becomes a no-op (it skips when the sidecar is absent, so nothing else
    would fail).
    """
    raw = b"the original bytes" * 4096
    uv = tmp_path / "uv"
    uv.write_bytes(raw)
    _, _, digest = bundle.compress_uv(uv, preset=1)
    sha = tmp_path / "uv.xz.sha256"
    assert sha.exists(), "no digest sidecar was written"
    assert sha.read_text().strip() == digest == hashlib.sha256(raw).hexdigest()


@pytest.mark.invariant("INV-PAYLOAD-04")
def test_the_launcher_verifies_the_expansion_and_bounds_the_size():
    """Two guards the review found missing, both in code that runs on a recipient's machine.

    Verified by execution on 2026-09-11, not by reading:
      * an EMPTY `.xz` member hit `src[0].addr` on an empty string — an IndexDefect, which
        is not a CatchableError, so the launcher died with a Nim traceback rather than
        haru-pack's message. No attacker needed: a truncated write produces it.
      * a `.size` sidecar of `1 shl 50` reached `newString`, which aborts the process with a
        bare "out of memory" (an uncatchable Defect).
      * a one-character change to the `.sha256` sidecar is now refused with
        "does not match its recorded digest" and exit 7 — walked end to end against a real
        rebuilt binary.
    """
    stage = code_of(LAUNCHER / "stage.nim")
    xzdec = code_of(LAUNCHER / "xzdec.nim")

    assert "src.len == 0" in xzdec, (
        "xzDecode does not guard an empty input; an empty member aborts the launcher with "
        "an IndexDefect instead of a StageError"
    )
    assert "MaxExpandedBytes" in stage, (
        "the expanded size is unbounded; a corrupt .size sidecar becomes an uncatchable "
        "out-of-memory abort"
    )
    assert "does not match its recorded digest" in stage, (
        "the expansion is not checked against the digest the build recorded"
    )
    # the check has to run BEFORE the file is written, or it protects nothing
    assert stage.index("does not match its recorded digest") < stage.index("writeFile(dest"), (
        "the digest is checked after the expanded file is already written"
    )


@pytest.mark.invariant("INV-PAYLOAD-04")
def test_the_digest_claim_is_scoped_to_corruption_not_tampering():
    """The sidecar sits beside the member, so an attacker who can rewrite one can rewrite
    both. Saying otherwise would be exactly the overclaim this review was looking for, so
    both the code and the invariant have to say what the check really covers."""
    stage = (LAUNCHER / "stage.nim").read_text(encoding="utf-8")
    assert "not an authenticity one" in stage or "does NOT" in stage, (
        "stage.nim does not state the limit of the digest check"
    )
    inv = (Path(__file__).resolve().parent.parent / "INVARIANTS.md").read_text()
    body = inv.split("### INV-PAYLOAD-04")[1].split("### INV-PAYLOAD-05")[0]
    assert "corrupt" in body.lower(), (
        "INV-PAYLOAD-04 does not scope its digest claim to corruption"
    )

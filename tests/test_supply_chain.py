"""INV-SUPPLY-01 / INV-SUPPLY-02 — what we download and then execute.

These tests are deliberately offline. Every "download" here is a `file://` URL or a
stubbed `urlretrieve`, so the code path under test is the real one (`fetch_verified`
does the hashing and the refusing) while the bytes are ones the test controls.

Red-path, INV-SUPPLY-01: make `archives.verify_sha256` return without comparing, or
put `urllib.request.urlretrieve` back into `bootstrap.install_nim` /
`bundle.bundle_uv` / `bundle.bundle_python`. Every rejection test below goes red.

Red-path, INV-SUPPLY-02: restore `NIM_DEPS = ("zippy", "puppy", ...)` and pass the bare
package name to `nimble install`. `test_nimble_is_invoked_with_pinned_specs` goes red.
"""
from __future__ import annotations

import hashlib
import io
import re
import shutil
import tarfile
import urllib.request
from pathlib import Path

import pytest

from haru_pack import bootstrap, bundle
from haru_pack.archives import (DigestMismatch, UnpinnedArtifact, fetch_verified,
                                sha256_file, verify_sha256)

SRC = Path(bootstrap.__file__).resolve().parent
LAUNCHER = SRC / "launcher"

PIN_TABLES = {
    "bootstrap.NIM_SHA256": bootstrap.NIM_SHA256,
    "bundle.PBS_SHA256": bundle.PBS_SHA256,
    **{f"bundle.UV_SHA256[{v!r}]": t for v, t in bundle.UV_SHA256.items()},
}


# ---------- fixtures ----------
def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_tar(path: Path, entries: dict, mode: str) -> Path:
    """Write a tar containing {arcname: bytes}. Real archive, tiny."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, mode) as tf:
        for arcname, data in entries.items():
            info = tarfile.TarInfo(arcname)
            info.size = len(data)
            info.mode = 0o755
            tf.addfile(info, io.BytesIO(data))
    return path


def _file_url(p: Path) -> str:
    return "file://" + str(p.resolve())


@pytest.fixture
def nim_tarball(tmp_path):
    """A plausible Nim release archive: nim-<ver>/bin/nim inside a .tar.xz."""
    p = tmp_path / f"nim-{bootstrap.NIM_VERSION}-linux_x64.tar.xz"
    _make_tar(p, {f"nim-{bootstrap.NIM_VERSION}/bin/nim": b"#!/bin/sh\necho stub nim\n"}, "w:xz")
    return p


@pytest.fixture
def uv_tarball(tmp_path):
    p = tmp_path / "uv-release.tar.gz"
    _make_tar(p, {"uv-x.y.z/uv": b"#!/bin/sh\necho stub uv\n"}, "w:gz")
    return p


@pytest.fixture
def pbs_tarball(tmp_path):
    """python-build-standalone install_only layout: python/bin/python3 (+ .exe)."""
    p = tmp_path / "pbs.tar.gz"
    _make_tar(p, {"python/bin/python3": b"stub interpreter\n",
                  "python/python.exe": b"stub interpreter\n"}, "w:gz")
    return p


@pytest.fixture
def no_network(monkeypatch):
    """Any attempt to actually fetch is a test failure, not a slow test."""
    calls = []

    def boom(url, dest=None, *a, **kw):
        calls.append(url)
        raise AssertionError(f"download attempted for an artifact with no pin: {url}")

    monkeypatch.setattr(urllib.request, "urlretrieve", boom)
    return calls


# ---------- the primitive: fetch_verified ----------
@pytest.mark.invariant("INV-SUPPLY-01")
def test_a_tampered_artifact_is_rejected_and_deleted(tmp_path):
    """The whole invariant in one test: right URL, wrong bytes, refuse."""
    served = tmp_path / "served.bin"
    served.write_bytes(b"tampered payload -- one byte different\n")
    pinned = _sha(b"the bytes this repo pinned\n")
    dest = tmp_path / "downloaded.bin"

    with pytest.raises(DigestMismatch) as ei:
        fetch_verified(_file_url(served), dest, pinned, what="fixture artifact")

    assert "digest mismatch" in str(ei.value)
    assert pinned in str(ei.value)
    assert not dest.exists(), "a mismatching artifact was left on disk for a later step to pick up"


@pytest.mark.invariant("INV-SUPPLY-01")
def test_matching_bytes_are_accepted(tmp_path):
    data = b"the bytes this repo pinned\n"
    served = tmp_path / "served.bin"
    served.write_bytes(data)
    dest = tmp_path / "downloaded.bin"

    out = fetch_verified(_file_url(served), dest, _sha(data), what="fixture artifact")
    assert out.read_bytes() == data


@pytest.mark.invariant("INV-SUPPLY-01")
def test_missing_pin_refuses_before_the_network(tmp_path, no_network):
    for missing in (None, "", "   "):
        with pytest.raises(UnpinnedArtifact):
            fetch_verified("https://example.invalid/x.tar.gz", tmp_path / "x", missing)
    assert not no_network, "we hit the network for an artifact with no pinned digest"


@pytest.mark.invariant("INV-SUPPLY-01")
def test_a_placeholder_pin_is_not_a_pin(tmp_path, no_network):
    """A digest-shaped string that is not a digest must not satisfy the check."""
    for bogus in ("TODO", "sha256:deadbeef", "x" * 64, "0" * 63, "deadbeef"):
        with pytest.raises(UnpinnedArtifact):
            fetch_verified("https://example.invalid/x.tar.gz", tmp_path / "x", bogus)


@pytest.mark.invariant("INV-SUPPLY-01")
def test_verify_sha256_is_case_and_whitespace_tolerant_but_not_value_tolerant(tmp_path):
    data = b"abc"
    f = tmp_path / "f"
    f.write_bytes(data)
    assert verify_sha256(f, "  " + _sha(data).upper() + "\n") == _sha(data)
    with pytest.raises(DigestMismatch):
        verify_sha256(f, _sha(b"abd"))
    assert sha256_file(f) == _sha(data)


# ---------- site 1: the Nim toolchain ----------
def _nim_install_env(monkeypatch, tmp_path, tarball):
    """Point install_nim at a file:// 'release' and a throwaway toolchain dir."""
    monkeypatch.setattr(bootstrap, "nim_dir", lambda: tmp_path / "toolchain" / "nim")
    monkeypatch.setattr(bootstrap, "_nim_archive_url", lambda: (_file_url(tarball), "tar.xz"))
    return tarball.name


@pytest.mark.invariant("INV-SUPPLY-01")
def test_install_nim_refuses_a_tampered_toolchain(monkeypatch, tmp_path, nim_tarball):
    name = _nim_install_env(monkeypatch, tmp_path, nim_tarball)
    monkeypatch.setattr(bootstrap, "NIM_SHA256", {name: _sha(b"what the publisher shipped")})

    with pytest.raises(DigestMismatch):
        bootstrap.install_nim(force=True)

    assert not (tmp_path / "toolchain" / "nim" / "bin" / "nim").exists(), \
        "a Nim binary that failed verification was installed anyway"


@pytest.mark.invariant("INV-SUPPLY-01")
def test_install_nim_accepts_the_pinned_toolchain(monkeypatch, tmp_path, nim_tarball):
    name = _nim_install_env(monkeypatch, tmp_path, nim_tarball)
    monkeypatch.setattr(bootstrap, "NIM_SHA256", {name: sha256_file(nim_tarball)})

    nim = bootstrap.install_nim(force=True)
    assert Path(nim).exists()
    assert Path(nim).read_bytes().startswith(b"#!/bin/sh")


@pytest.mark.invariant("INV-SUPPLY-01")
def test_install_nim_refuses_a_platform_with_no_pinned_digest(monkeypatch, tmp_path,
                                                              nim_tarball, no_network):
    """The linux_arm64 case: Nim publishes no aarch64 build, so there is no digest."""
    _nim_install_env(monkeypatch, tmp_path, nim_tarball)
    monkeypatch.setattr(bootstrap, "NIM_SHA256", {})
    existing = tmp_path / "toolchain" / "nim" / "bin"
    existing.mkdir(parents=True)
    (existing / "nim").write_text("previously installed\n")

    with pytest.raises(UnpinnedArtifact):
        bootstrap.install_nim(force=True)

    assert (existing / "nim").exists(), "refusing to install should not delete the existing toolchain"


# ---------- site 2: uv ----------
@pytest.fixture
def uv_download(monkeypatch, uv_tarball):
    """Force bundle_uv down its download path and serve it the fixture archive."""
    monkeypatch.setattr(bundle.shutil, "which", lambda name: None)   # no local uv to copy
    from haru_pack.targets import Target
    asset = Target.parse("host").uv_asset()
    if asset.endswith(".zip"):
        pytest.skip("fixture archive is a tarball; host resolves a .zip asset")

    def fake_retrieve(url, dest=None, *a, **kw):
        shutil.copy2(uv_tarball, dest)
        return dest, None

    monkeypatch.setattr(urllib.request, "urlretrieve", fake_retrieve)
    return asset


@pytest.mark.invariant("INV-SUPPLY-01")
def test_bundle_uv_refuses_a_tampered_release(monkeypatch, tmp_path, uv_download):
    monkeypatch.setitem(bundle.UV_SHA256[bundle.UV_VERSION], uv_download,
                        _sha(b"the uv the publisher actually released"))
    with pytest.raises(DigestMismatch):
        bundle.bundle_uv("host", tmp_path / "vendor")
    assert not (tmp_path / "vendor" / "uv").exists(), "an unverified uv was staged anyway"


@pytest.mark.invariant("INV-SUPPLY-01")
def test_bundle_uv_accepts_the_pinned_release(monkeypatch, tmp_path, uv_download, uv_tarball):
    monkeypatch.setitem(bundle.UV_SHA256[bundle.UV_VERSION], uv_download, sha256_file(uv_tarball))
    out = bundle.bundle_uv("host", tmp_path / "vendor")
    assert out.exists() and out.read_bytes().startswith(b"#!/bin/sh")


@pytest.mark.invariant("INV-SUPPLY-01")
def test_bundle_uv_refuses_an_unpinned_version(monkeypatch, tmp_path, no_network):
    monkeypatch.setattr(bundle.shutil, "which", lambda name: None)
    with pytest.raises(UnpinnedArtifact):
        bundle.bundle_uv("host", tmp_path / "vendor", version="99.99.99")


# ---------- site 3: the standalone interpreter ----------
@pytest.mark.invariant("INV-SUPPLY-01")
def test_bundle_python_refuses_a_tampered_interpreter(monkeypatch, tmp_path, pbs_tarball):
    url = _file_url(pbs_tarball)
    monkeypatch.setattr(bundle, "_find_python_url", lambda os_, v, arch="x86_64": url)
    monkeypatch.setattr(bundle, "PBS_SHA256", {url: _sha(b"the interpreter upstream published")})

    with pytest.raises(DigestMismatch):
        bundle.bundle_python("windows", tmp_path / "vendor", version="3.12")

    staged = list((tmp_path / "vendor" / "python").rglob("*.exe"))
    assert not staged, f"an unverified interpreter was extracted into the payload: {staged}"


@pytest.mark.invariant("INV-SUPPLY-01")
def test_bundle_python_accepts_the_pinned_interpreter(monkeypatch, tmp_path, pbs_tarball):
    url = _file_url(pbs_tarball)
    monkeypatch.setattr(bundle, "_find_python_url", lambda os_, v, arch="x86_64": url)
    monkeypatch.setattr(bundle, "PBS_SHA256", {url: sha256_file(pbs_tarball)})

    out = bundle.bundle_python("windows", tmp_path / "vendor", version="3.12")
    assert out.name == "python.exe" and out.exists()


@pytest.mark.invariant("INV-SUPPLY-01")
def test_bundle_python_refuses_an_url_with_no_pin(monkeypatch, tmp_path, no_network):
    monkeypatch.setattr(bundle, "_find_python_url",
                        lambda os_, v, arch="x86_64": "https://example.invalid/cpython-9.9.9.tar.gz")
    with pytest.raises(UnpinnedArtifact):
        bundle.bundle_python("windows", tmp_path / "vendor", version="9.9")


# ---------- the pin tables themselves ----------
@pytest.mark.invariant("INV-SUPPLY-01")
def test_every_pin_is_a_real_sha256_digest():
    """Catches the failure this repo is trying to eliminate: an invented hash."""
    for table_name, table in PIN_TABLES.items():
        assert table, f"{table_name} is empty"
        for key, digest in table.items():
            where = f"{table_name}[{key!r}]"
            assert isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest), \
                f"{where} is not a lowercase sha256 hex digest: {digest!r}"
            assert len(set(digest)) > 4, f"{where} looks like a placeholder: {digest!r}"


@pytest.mark.invariant("INV-SUPPLY-01")
def test_pins_are_distinct():
    """Two artifacts sharing a digest means one was copy-pasted."""
    seen = {}
    for table_name, table in PIN_TABLES.items():
        for key, digest in table.items():
            assert digest not in seen, f"{table_name}[{key!r}] reuses the digest of {seen[digest]}"
            seen[digest] = f"{table_name}[{key!r}]"


@pytest.mark.invariant("INV-SUPPLY-01")
def test_the_pinned_versions_are_the_ones_with_pins():
    """A version bump without a digest bump must be caught here, not at build time."""
    assert bundle.UV_VERSION in bundle.UV_SHA256, \
        f"UV_VERSION {bundle.UV_VERSION} has no entry in UV_SHA256"
    from haru_pack.targets import KNOWN_TARGETS, Target
    for spec in KNOWN_TARGETS:
        asset = Target.parse(spec).uv_asset()
        assert asset in bundle.UV_SHA256[bundle.UV_VERSION], \
            f"no pinned digest for the {spec} uv asset {asset}"
    for name in bootstrap.NIM_SHA256:
        assert bootstrap.NIM_VERSION in name, \
            f"stale Nim pin {name!r} does not belong to NIM_VERSION {bootstrap.NIM_VERSION}"
    assert f"nim-{bootstrap.NIM_VERSION}-linux_x64.tar.xz" in bootstrap.NIM_SHA256
    assert f"nim-{bootstrap.NIM_VERSION}_x64.zip" in bootstrap.NIM_SHA256


@pytest.mark.invariant("INV-SUPPLY-01")
def test_no_unverified_download_in_the_source():
    """Every fetch must go through archives.fetch_verified.

    Grep-shaped, like the INV-SUPPLY-03 guard next door, and appropriate for the same
    reason: the danger is the call shape. `urlretrieve(url, dest)` anywhere else in
    src/ is a download with no digest behind it.
    """
    offenders = []
    for p in sorted(SRC.rglob("*.py")):
        if p.name == "archives.py":
            continue
        for i, line in enumerate(p.read_text().splitlines(), 1):
            if re.search(r"\b(urlretrieve|urlopen|requests\.(get|post))\s*\(", line):
                offenders.append(f"{p.relative_to(SRC.parent.parent)}:{i}: {line.strip()}")
    assert not offenders, f"unverified download outside archives.fetch_verified: {offenders}"


# ---------- INV-SUPPLY-02: the Nim libraries ----------
@pytest.mark.invariant("INV-SUPPLY-09")
def test_nim_deps_are_pinned_to_exact_versions():
    assert isinstance(bootstrap.NIM_DEPS, dict) and bootstrap.NIM_DEPS
    for pkg, ver in bootstrap.NIM_DEPS.items():
        assert re.fullmatch(r"\d+(\.\d+)+", ver), \
            f"{pkg} is not pinned to an exact version: {ver!r}"
    for spec in bootstrap.nim_dep_specs():
        pkg, _, ver = spec.partition("@")
        assert ver and bootstrap.NIM_DEPS[pkg] == ver, f"bad nimble spec {spec!r}"


@pytest.mark.invariant("INV-SUPPLY-09")
def test_nimble_is_invoked_with_pinned_specs(monkeypatch, tmp_path):
    """Efficacy, not shape: watch the argv that ensure_nim_deps actually builds."""
    calls = []

    class Done:
        returncode = 0
        stdout = stderr = ""

    def fake_run(cmd, **kw):
        calls.append(list(cmd))
        return Done()

    monkeypatch.setattr(bootstrap.subprocess, "run", fake_run)
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/nimble")
    assert bootstrap.ensure_nim_deps(str(tmp_path / "nim")) is True

    installed = [c[-1] for c in calls]
    assert installed, "ensure_nim_deps invoked nimble zero times"
    assert len(installed) == len(bootstrap.NIM_DEPS)
    for arg in installed:
        assert "@" in arg, f"nimble was asked to resolve {arg!r} freely -- that is not a pin"
        pkg, _, ver = arg.partition("@")
        assert bootstrap.NIM_DEPS[pkg] == ver
    assert set(installed) == set(bootstrap.nim_dep_specs())


@pytest.mark.invariant("INV-SUPPLY-09")
def test_every_third_party_nim_import_is_pinned():
    """A new `import somepkg` in the launcher must come with a version pin."""
    local = {p.stem for p in LAUNCHER.glob("*.nim")}
    unpinned = set()
    for p in sorted(LAUNCHER.glob("*.nim")):
        for line in p.read_text().splitlines():
            m = re.match(r"\s*import\s+(.+)$", line)
            if not m:
                continue
            rest = re.sub(r"\[[^\]]*\]", "", m.group(1))     # drop `std/[os, strutils]` groups
            for mod in rest.split(","):
                root = mod.strip().split("/")[0].strip()
                if not root or root == "std" or root in local:
                    continue
                if root not in bootstrap.NIM_DEPS:
                    unpinned.add(f"{p.name}: {root}")
    assert not unpinned, f"launcher imports with no pinned version in NIM_DEPS: {sorted(unpinned)}"


@pytest.mark.invariant("INV-SUPPLY-09")
def test_nimble_specs_would_survive_a_shell():
    """`pkg@ver` is nimble's exact-version syntax; nothing here needs quoting."""
    for spec in bootstrap.nim_dep_specs():
        assert not set(spec) & set(" \t'\"`$;&|<>*?"), f"unsafe nimble spec {spec!r}"


# ---------- pins live in data, not in code (INV-SUPPLY-01) ----------

@pytest.mark.invariant("INV-SUPPLY-01")
def test_pins_are_data_not_source_literals():
    """Digests belong in pins.toml, hand-editable, each with its provenance.

    Red-path: paste a `UV_SHA256 = {...}` literal back into bundle.py. A maintainer bumping
    uv should edit a table, and a reader auditing what a build trusted should not have to
    follow Python to find out what it trusted.
    """
    import inspect
    from haru_pack import pins
    src = inspect.getsource(bundle)
    body = src[:src.index("def _run(")]
    assert "pins.uv_digests()" in body and "pins.python_digests()" in body
    assert '"uv-x86_64-unknown-linux-gnu.tar.gz":' not in body, (
        "a digest literal is back in bundle.py"
    )
    assert pins.pins_path().exists()


@pytest.mark.invariant("INV-SUPPLY-01")
def test_every_pin_records_where_it_came_from():
    """A digest with no provenance is indistinguishable from an invented one."""
    from haru_pack import pins
    prov = pins.provenance()
    assert prov, "no provenance recorded at all"
    for key, where in prov.items():
        assert where, f"{key} has no provenance"
        assert ("sha256" in where or "release API" in where), (
            f"{key}: provenance {where!r} names neither a sidecar nor the release API — the "
            "two channels that carry the publisher's own statement"
        )


@pytest.mark.invariant("INV-SUPPLY-01")
def test_pins_file_is_packaged_with_the_wheel():
    """An installed haru-pack must pin exactly what the release pinned. Red-path: drop
    `src/haru_pack/pins.toml` from pyproject's hatch include list."""
    from pathlib import Path
    pyproject = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    assert "src/haru_pack/pins.toml" in pyproject, (
        "pins.toml is not packaged; an installed copy would fail to load its pins"
    )


@pytest.mark.invariant("INV-SUPPLY-01")
def test_a_malformed_pins_file_is_fatal_not_a_fallback(tmp_path):
    """Refusing beats degrading: a build that cannot read its pins must not proceed to
    download things unverified."""
    from haru_pack.pins import PinsError, load
    bad = tmp_path / "pins.toml"
    bad.write_text('schema_version = 1\n[[artifact]]\nkind = "uv"\nversion = "1"\n'
                   'asset = "a"\nsha256 = "nope"\n')
    load.cache_clear()
    with pytest.raises(PinsError):
        load(str(bad))
    load.cache_clear()

    bad.write_text('schema_version = 99\n')
    with pytest.raises(PinsError):
        load(str(bad))
    load.cache_clear()

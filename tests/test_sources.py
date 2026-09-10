"""INV-SUPPLY-06/07/08/10 — one verified download path, and mirrors that cannot weaken it.

The property that matters most here is the ORDER of two lookups:

    digest = PBS_SHA256[upstream_url]      # pinned in this repo, keyed by UPSTREAM
    url    = sources.python_url(upstream)  # only now is the download point rewritten

Get that backwards — key the pin by the mirrored URL — and a mirror silently becomes a
trust anchor, because whoever runs the mirror also chooses which pin is consulted. Several
tests below exist purely to hold that ordering in place.
"""
from __future__ import annotations

import ast
import hashlib
import inspect
import tarfile
import textwrap
from pathlib import Path

import pytest

from haru_pack import bundle
from haru_pack.archives import DigestMismatch, UnpinnedArtifact
from haru_pack.sources import (DEFAULT_PYTHON_BASE, DEFAULT_UV_BASE, MirrorError, Sources)

MIRROR = "https://mirror.example/pbs/releases/download"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _code_of(fn) -> str:
    """Source of `fn` with its docstring and every `#` comment removed.

    Source-shape assertions are only as good as what they read. The first draft of the
    tests below matched raw `inspect.getsource`, so a comment *explaining* that
    `--no-hashes` had been removed made the assertion fail — and, worse, a comment
    mentioning a guard would have made a "the guard is present" assertion PASS with the
    guard gone. Strip the prose and match the code.
    """
    src = inspect.getsource(fn)
    tree = ast.parse(textwrap.dedent(src))
    node = tree.body[0]
    if (node.body and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)):
        node.body = node.body[1:]          # drop the docstring
    return ast.unparse(node)               # comments do not survive unparse


def _file_url(p: Path) -> str:
    return "file://" + str(p)


@pytest.fixture
def pbs_tarball(tmp_path):
    """A tarball shaped like an install_only python-build-standalone archive."""
    src = tmp_path / "src"
    (src / "python" / "bin").mkdir(parents=True)
    (src / "python" / "bin" / "python3").write_text("#!/bin/sh\necho hi\n")
    arc = tmp_path / "py.tar.gz"
    with tarfile.open(arc, "w:gz") as tf:
        tf.add(src / "python", arcname="python")
    return arc


# ---------------------------------------------------------------- mirror mechanics

@pytest.mark.invariant("INV-SUPPLY-10")
def test_default_sources_leave_urls_untouched():
    s = Sources()
    assert s.uses_defaults
    up = DEFAULT_PYTHON_BASE + "/20260211/cpython-3.12.12-x86_64-unknown-linux-gnu.tar.gz"
    assert s.python_url(up) == up
    assert s.uv_url("0.10.4", "uv-x86_64-unknown-linux-gnu.tar.gz").startswith(DEFAULT_UV_BASE)


@pytest.mark.invariant("INV-SUPPLY-10")
def test_mirror_preserves_the_path_after_the_base():
    """A mirror is a path-preserving reverse proxy; the suffix is reused verbatim."""
    s = Sources(python_base=MIRROR)
    suffix = "/20260211/cpython-3.12.12%2B20260211-x86_64-unknown-linux-gnu.tar.gz"
    assert s.python_url(DEFAULT_PYTHON_BASE + suffix) == MIRROR + suffix


@pytest.mark.invariant("INV-SUPPLY-10")
def test_mirror_refuses_to_rewrite_an_unrecognised_host():
    """Refusing beats guessing: if we cannot see the upstream base we do not know what
    path the mirror would serve, and inventing one would fetch an unrelated file."""
    s = Sources(python_base=MIRROR)
    with pytest.raises(MirrorError):
        s.python_url("https://somewhere-else.invalid/cpython.tar.gz")


@pytest.mark.invariant("INV-SUPPLY-10")
def test_a_hostile_mirror_cannot_substitute_an_artifact(monkeypatch, tmp_path, pbs_tarball):
    """The whole point. Serve different bytes from the mirror and the build must fail.

    Red-path: key `PBS_SHA256` by the mirrored URL instead of the upstream one (or look the
    digest up after rewriting). Then the mirror operator picks the pin and this goes green
    while the build is compromised.
    """
    hostile = tmp_path / "hostile.tar.gz"
    hostile.write_bytes(b"not the interpreter you asked for")

    upstream = DEFAULT_PYTHON_BASE + "/20260211/cpython-3.12.12-x86_64-unknown-linux-gnu.tar.gz"
    honest_digest = _sha(pbs_tarball.read_bytes())      # what upstream really publishes

    monkeypatch.setattr(bundle, "_find_python_url", lambda os_, v, arch="x86_64": upstream)
    monkeypatch.setattr(bundle, "PBS_SHA256", {upstream: honest_digest})

    s = Sources(python_base="file://" + str(tmp_path))
    monkeypatch.setattr(Sources, "python_url", lambda self, up: _file_url(hostile))

    with pytest.raises(DigestMismatch):
        bundle.bundle_python("host", tmp_path / "vendor", version="3.12", sources=s)

    staged = list((tmp_path / "vendor" / "python").rglob("python3"))
    assert not staged, f"a substituted interpreter was extracted anyway: {staged}"


@pytest.mark.invariant("INV-SUPPLY-10")
def test_the_digest_is_looked_up_before_the_url_is_rewritten():
    """Source-order check backing the runtime test above: in `bundle_python`, the
    `PBS_SHA256` lookup must appear before the `sources.python_url(...)` rewrite."""
    src = _code_of(bundle.bundle_python)
    lookup = src.index("PBS_SHA256.get(")
    rewrite = src.index("sources.python_url(")
    assert lookup < rewrite, (
        "bundle_python rewrites the URL before looking the pin up. Whatever pin is consulted "
        "must be chosen by the UPSTREAM identity, never by the mirror."
    )


@pytest.mark.invariant("INV-SUPPLY-10")
def test_sources_resolution_prefers_declaration_then_env():
    env = {"HARUPACK_PYTHON_BASE": "https://from-env.example/pbs"}
    assert Sources.resolve({}, env).python_base == "https://from-env.example/pbs"
    decl = {"sources": {"python_base": "https://from-toml.example/pbs"}}
    assert Sources.resolve(decl, env).python_base == "https://from-toml.example/pbs"
    assert Sources.resolve({}, {}).python_base == DEFAULT_PYTHON_BASE


# ---------------------------------------------------------------- one download path

@pytest.mark.invariant("INV-SUPPLY-06")
def test_bundle_uv_never_ships_a_binary_off_the_build_hosts_path():
    """Red-path: restore the `shutil.which("uv")` copy shortcut at the top of bundle_uv.

    That shortcut put whatever was first on the operator's PATH into a payload that then
    gets signed and shipped — no digest, no version guarantee, and different bytes on every
    build host from the same commit.
    """
    src = _code_of(bundle.bundle_uv)
    assert "shutil.which" not in src, (
        "bundle_uv resolves uv from PATH again; a host build would ship an unverified binary"
    )
    assert "fetch_verified(" in src, "bundle_uv no longer downloads through fetch_verified"


@pytest.mark.invariant("INV-SUPPLY-07")
def test_bundle_python_has_no_unverified_host_branch():
    """Red-path: restore the `if target == "host": uv python install` branch.

    That branch was the DEFAULT path, and it delegated fetching to a subprocess whose bytes
    haru-pack never saw — while the cross path right next to it verified a digest.
    """
    src = _code_of(bundle.bundle_python)
    assert "uv\", \"python\", \"install\"" not in src and "'uv', 'python', 'install'" not in src, (
        "bundle_python shells out to `uv python install` again — that path is unverified"
    )
    assert "fetch_verified(" in src
    assert 'target == "host"' not in src, (
        "bundle_python has a host-specific branch again; host and cross must share one path"
    )


@pytest.mark.invariant("INV-SUPPLY-07")
def test_bundle_python_verifies_on_the_host_target(monkeypatch, tmp_path, pbs_tarball):
    """Efficacy, not shape: the host target must reject a tampered interpreter."""
    upstream = DEFAULT_PYTHON_BASE + "/20260211/cpython-3.12.12-x86_64-unknown-linux-gnu.tar.gz"
    monkeypatch.setattr(bundle, "_find_python_url", lambda os_, v, arch="x86_64": upstream)
    monkeypatch.setattr(bundle, "PBS_SHA256", {upstream: _sha(b"different bytes entirely")})
    monkeypatch.setattr(Sources, "python_url", lambda self, up: _file_url(pbs_tarball))

    with pytest.raises(DigestMismatch):
        bundle.bundle_python("host", tmp_path / "vendor", version="3.12")


@pytest.mark.invariant("INV-SUPPLY-07")
def test_bundle_python_refuses_an_unpinned_interpreter_on_host(monkeypatch, tmp_path):
    monkeypatch.setattr(bundle, "_find_python_url",
                        lambda os_, v, arch="x86_64": "https://example.invalid/cpython.tar.gz")
    monkeypatch.setattr(bundle, "PBS_SHA256", {})
    with pytest.raises(UnpinnedArtifact):
        bundle.bundle_python("host", tmp_path / "vendor", version="3.12")


# ---------------------------------------------------------------- wheel hashes

@pytest.mark.invariant("INV-SUPPLY-08")
def test_exported_requirements_keep_their_hashes():
    """Red-path: put `--no-hashes` back into `_export_reqs`.

    uv emits per-wheel hashes by default and the lockfile already has them; the old code
    explicitly asked uv to throw that integrity data away, then installed from the result.
    """
    src = _code_of(bundle._export_reqs)
    assert "--no-hashes" not in src, (
        "_export_reqs discards the lockfile's hashes again, so --require-hashes has nothing "
        "to check"
    )


@pytest.mark.invariant("INV-SUPPLY-08")
def test_cross_wheel_install_requires_hashes():
    """Red-path: drop `--require-hashes` from warm_cache_windows."""
    src = _code_of(bundle.warm_cache_windows)
    assert "--require-hashes" in src, (
        "warm_cache_windows installs the application's own wheels without hash verification"
    )


@pytest.mark.invariant("INV-SUPPLY-08")
def test_export_preserves_hash_continuation_lines():
    """A hashed requirement spans lines (`    --hash=sha256:...`). Stripping indented
    continuations would silently produce a hashless file that --require-hashes rejects."""
    src = _code_of(bundle._export_reqs)
    assert ".strip()" not in src.split("for line in")[1].split("out.append")[0].replace(
        "st = line.strip()", ""), "continuation lines must not be stripped away"
    assert "out.append(line.rstrip())" in src


# ---------------------------------------------------------------- receipt

@pytest.mark.invariant("INV-SUPPLY-10")
def test_sources_are_recorded_on_the_build_receipt():
    """An operator auditing a signed artifact should not have to guess whether a mirror
    was in play. Red-path: drop `sources=sources.describe()` from build()'s info.update."""
    from haru_pack import build as build_mod
    src = _code_of(build_mod.build)
    assert "sources=sources.describe()" in src
    assert Sources().describe() == "upstream defaults (github.com)"
    assert "mirror.example" in Sources(python_base=MIRROR).describe()

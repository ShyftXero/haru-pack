"""INV-CANARY-02 / INV-INJECT-01 (+ INV-SECRET-02) — the BUILD (Python) half of ADR 0003.

The Nim launcher's reader is claimed by tests/test_stub_config.py. This file claims the build
side: resolving the per-knob canary map with the documented precedence, emitting the cleartext
stub-config section into a v2 binary, recording the map (never the secret) in the receipt,
threading --env-append into the payload manifest, and the build-time refusals + the
secret-shaped honesty warning.

Red-paths walked 2026-09-10 (neutralize -> observe red -> restore) are noted per test group;
see the INVARIANTS.md entries INV-CANARY-02 / INV-INJECT-01.
"""
from __future__ import annotations

import io
import re
import zipfile

import pytest

from haru_pack.build import BuildError, resolve_canary, resolve_injects, stub_config_bytes
from haru_pack.overlay import verify

CANARY_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


# ── canary map resolution (INV-CANARY-02) ────────────────────────────────────────────────

@pytest.mark.invariant("INV-CANARY-02")
def test_default_canary_is_haru_for_every_knob():
    assert resolve_canary() == {"secret": "HARU", "uv_ver": "HARU",
                                "source_url": "HARU", "base_path": "HARU"}


@pytest.mark.invariant("INV-CANARY-02")
def test_env_canary_sets_all_knobs():
    assert set(resolve_canary(env_canary="MARK").values()) == {"MARK"}


@pytest.mark.invariant("INV-CANARY-02")
def test_per_knob_override_touches_only_that_knob():
    c = resolve_canary(per_knob={"uv_ver": "MARK"})
    assert c == {"secret": "HARU", "uv_ver": "MARK",
                 "source_url": "HARU", "base_path": "HARU"}


@pytest.mark.invariant("INV-CANARY-02")
def test_per_knob_beats_all_knobs_default():
    """Precedence: --stub-env-<knob>-canary > --env-canary > built-in HARU."""
    c = resolve_canary(env_canary="BASE", per_knob={"secret": "MARK"})
    assert c["secret"] == "MARK"
    assert c["uv_ver"] == c["source_url"] == c["base_path"] == "BASE"


@pytest.mark.invariant("INV-CANARY-02")
def test_random_canary_is_valid_and_recorded():
    log: list[str] = []
    c = resolve_canary(env_canary_random=True, log=log.append)
    for tok in c.values():
        assert re.fullmatch(r"[A-Z][A-Z0-9]{7}", tok), tok
    # Every knob shares the one random default here...
    assert len(set(c.values())) == 1
    # ...and the packager is told exactly what env name to set at runtime.
    logged = "\n".join(log)
    for knob in ("SECRET", "UV_VER", "SOURCE_URL", "BASE_PATH"):
        assert f"{c['secret']}_{knob}" in logged


@pytest.mark.invariant("INV-CANARY-02")
def test_conflicting_all_knob_defaults_refused():
    with pytest.raises(BuildError, match="conflicting"):
        resolve_canary(env_canary="MARK", env_canary_random=True)


@pytest.mark.invariant("INV-CANARY-02")
@pytest.mark.parametrize("kwargs", [
    {"env_canary": "9bad"},              # bad all-knobs default
    {"env_canary": "has space"},
    {"per_knob": {"secret": "bad-dash"}},  # bad per-knob override
    {"per_knob": {"uv_ver": ""}},          # empty is NOT a valid token... falls to HARU
])
def test_invalid_canary_token_refused(kwargs):
    if kwargs.get("per_knob", {}).get("uv_ver") == "":
        # An empty per-knob value is 'not given' -> falls back to the valid default.
        assert resolve_canary(**kwargs)["uv_ver"] == "HARU"
        return
    with pytest.raises(BuildError, match="not a valid env-name prefix"):
        resolve_canary(**kwargs)


@pytest.mark.invariant("INV-CANARY-02")
def test_stub_config_bytes_shape_matches_the_launcher_reader():
    b = stub_config_bytes({"secret": "HARU", "uv_ver": "MARK",
                           "source_url": "HARU", "base_path": "HARU"})
    assert b == (b'stub_config_version = 1\n\n[canary]\n'
                 b'secret = "HARU"\nuv_ver = "MARK"\n'
                 b'source_url = "HARU"\nbase_path = "HARU"\n')


# ── inject / env-append (INV-INJECT-01) ───────────────────────────────────────────────────

@pytest.mark.invariant("INV-INJECT-01")
def test_plain_inject_is_kept_verbatim_and_unwarned():
    log: list[str] = []
    out = resolve_injects(["LICENSE_TIER=pro", "URL=https://x/y?a=b"],
                          encrypted=False, log=log.append)
    assert out == ["LICENSE_TIER=pro", "URL=https://x/y?a=b"]  # split-on-first-'=' safe
    assert not any("WARNING" in m for m in log)


@pytest.mark.invariant("INV-INJECT-01")
@pytest.mark.parametrize("bad", ["NOEQUALS", "=novalue"])
def test_malformed_inject_refused(bad):
    with pytest.raises(BuildError):
        resolve_injects([bad], encrypted=False)


@pytest.mark.invariant("INV-INJECT-01")
@pytest.mark.parametrize("key", ["HARUPACK_STAGE", "UV_PYTHON", "PYTHONPATH",
                                 "PYTHONPYCACHEPREFIX", "UV_OFFLINE"])
def test_reserved_inject_key_refused(key):
    with pytest.raises(BuildError, match="reserved key"):
        resolve_injects([f"{key}=x"], encrypted=False)


@pytest.mark.invariant("INV-INJECT-01")
@pytest.mark.parametrize("entry", [
    "API_TOKEN=whatever",                       # key marker: TOKEN
    "DB_PASSWORD=hunter2",                       # key marker: PASSWORD
    "SIGNING_KEY=x",                             # key ends with _KEY
    "GREETING=abcdefghij0123456789KLMN",         # value: 20+ token-shaped chars
])
def test_secret_shaped_inject_warns_on_unencrypted_build(entry):
    log: list[str] = []
    resolve_injects([entry], encrypted=False, log=log.append)
    assert any("WARNING" in m and "secret-shaped" in m for m in log), log


@pytest.mark.invariant("INV-INJECT-01")
def test_secret_shaped_inject_is_silent_on_encrypted_build():
    """The payload hides an encrypted inject, so the honesty warning is not warranted."""
    log: list[str] = []
    resolve_injects(["API_TOKEN=abcdefghij0123456789KLMN"], encrypted=True, log=log.append)
    assert not any("WARNING" in m for m in log)


# ── end-to-end through build() (stubbed toolchain, no Nim) ─────────────────────────────────

def _payload_zip(exe):
    info = verify(exe)
    data = exe.read_bytes()
    body = data[info["payload_off"]:info["payload_off"] + info["payload_len"]]
    return zipfile.ZipFile(io.BytesIO(body))


@pytest.mark.invariant("INV-CANARY-02")
def test_build_emits_a_v2_binary_carrying_the_canary_map(stub_toolchain, script_project,
                                                         tmp_path):
    out = tmp_path / "app"
    info = stub_toolchain.build(script_project, out, tier="thin",
                                stub_env_secret_canary="MARK")
    v = verify(out)
    assert v["format_ver"] == 2 and v["stub_ok"] is True
    assert 'secret = "MARK"' in v["stub_config"]
    assert 'uv_ver = "HARU"' in v["stub_config"]
    assert info["canary"] == {"secret": "MARK", "uv_ver": "HARU",
                              "source_url": "HARU", "base_path": "HARU"}


@pytest.mark.invariant("INV-INJECT-01")
def test_build_writes_inject_into_the_payload_manifest(stub_toolchain, script_project,
                                                       tmp_path):
    out = tmp_path / "app"
    stub_toolchain.build(script_project, out, tier="thin",
                         env_append=["LICENSE_TIER=pro", "FEATURE=on"])
    manifest = _payload_zip(out).read("manifest.toml").decode()
    assert 'inject = [' in manifest
    assert '"LICENSE_TIER=pro"' in manifest
    assert '"FEATURE=on"' in manifest


@pytest.mark.invariant("INV-SECRET-02")
def test_receipt_records_the_canary_map_but_not_the_secret(stub_toolchain, script_project,
                                                           tmp_path):
    secret = b"correct-horse-battery-staple"
    out = tmp_path / "app"
    info = stub_toolchain.build(script_project, out, tier="thin", secret=secret,
                                encrypt=True, stub_env_secret_canary="MARK")
    # The canary map (env-name prefixes) is fine to record; the secret VALUE is not.
    assert info["canary"]["secret"] == "MARK"
    assert secret.decode() not in repr(info)
    assert secret not in out.read_bytes()
    # The cleartext stub-config publishes only the prefix, never the key.
    assert secret.decode() not in verify(out)["stub_config"]


# ── Phase-2 staging: reap / ram-only / base-path (docs/adr/0004) ───────────────────────────
# The build (Python) half of INV-BASE-01 / INV-RAM-01 / INV-REAP-01: the stub-config bytes and
# receipt. The launcher (Nim) half — precedence, /dev/shm, the detached reap — is claimed
# end-to-end in tests/test_reap.py and tests/test_ram_only.py; the --base-path build-time
# refusal (resolve_base_path) is claimed in tests/test_ram_only.py. See the INVARIANTS.md entries.


@pytest.mark.invariant("INV-BASE-01")
def test_default_build_stub_config_is_byte_identical():
    """No reap/ram-only/base-path -> the Phase-1 bytes exactly, so the v1 corpus and the
    'no version bump' claim (docs/adr/0004 §2.2) hold. Red-path: emit the keys unconditionally
    and this diverges from the Phase-1 shape asserted above."""
    c = {"secret": "HARU", "uv_ver": "HARU", "source_url": "HARU", "base_path": "HARU"}
    assert stub_config_bytes(c) == stub_config_bytes(c, reap=False, ram_only=False, base_path="")
    assert b"reap" not in stub_config_bytes(c)
    assert b"ram_only" not in stub_config_bytes(c)


@pytest.mark.invariant("INV-REAP-01")
def test_stub_config_emits_reap_only_when_set():
    c = {"secret": "HARU", "uv_ver": "HARU", "source_url": "HARU", "base_path": "HARU"}
    out = stub_config_bytes(c, reap=True).decode()
    assert "\nreap = true\n" in out
    # top-level key precedes the [canary] table (TOML)
    assert out.index("reap = true") < out.index("[canary]")


@pytest.mark.invariant("INV-RAM-01")
def test_stub_config_emits_ram_only_when_set():
    c = {"secret": "HARU", "uv_ver": "HARU", "source_url": "HARU", "base_path": "HARU"}
    out = stub_config_bytes(c, ram_only=True).decode()
    assert "\nram_only = true\n" in out
    assert out.index("ram_only = true") < out.index("[canary]")


@pytest.mark.invariant("INV-BASE-01")
def test_stub_config_emits_and_escapes_base_path():
    c = {"secret": "HARU", "uv_ver": "HARU", "source_url": "HARU", "base_path": "HARU"}
    win_path = "C:" + chr(92) + "stage" + chr(92) + "app"
    out = stub_config_bytes(c, base_path=win_path).decode()
    # base_path is a TOML basic string with the backslashes escaped so a Windows path round-trips
    expected = 'base_path = "C:' + chr(92) * 2 + "stage" + chr(92) * 2 + 'app"'
    assert expected in out


@pytest.mark.invariant("INV-REAP-01")
def test_build_bakes_reap_into_stub_and_receipt(stub_toolchain, script_project, tmp_path):
    out = tmp_path / "app"
    info = stub_toolchain.build(script_project, out, tier="thin", reap=True)
    assert "reap = true" in verify(out)["stub_config"]
    assert info["staging"]["reap"] is True


@pytest.mark.invariant("INV-RAM-01")
def test_build_bakes_ram_only_into_stub_and_receipt(stub_toolchain, script_project, tmp_path):
    out = tmp_path / "app"
    info = stub_toolchain.build(script_project, out, tier="thin", ram_only=True)
    assert "ram_only = true" in verify(out)["stub_config"]
    assert info["staging"]["ram_only"] is True


@pytest.mark.invariant("INV-BASE-01")
def test_build_bakes_base_path_into_stub_and_receipt(stub_toolchain, script_project, tmp_path):
    base = str(tmp_path / "stage")
    out = tmp_path / "app"
    info = stub_toolchain.build(script_project, out, tier="thin", base_path=base)
    assert f'base_path = "{base}"' in verify(out)["stub_config"]
    assert info["staging"]["base_path"] == base

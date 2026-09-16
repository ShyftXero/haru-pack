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
from pathlib import Path

import pytest

from haru_pack.build import BuildError, resolve_canary, resolve_injects, stub_config_bytes
from haru_pack.overlay import verify

CANARY_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


# ── canary map resolution (INV-CANARY-02) ────────────────────────────────────────────────

@pytest.mark.invariant("INV-CANARY-02")
def test_default_canary_is_haru_for_every_knob():
    assert resolve_canary() == {"secret": "HARU", "uv_ver": "HARU",
                                "source_url": "HARU", "base_path": "HARU",
                                "ephemeral": "HARU"}


@pytest.mark.invariant("INV-CANARY-02")
def test_env_canary_sets_all_knobs():
    assert set(resolve_canary(env_canary="MARK").values()) == {"MARK"}


@pytest.mark.invariant("INV-CANARY-02")
def test_per_knob_override_touches_only_that_knob():
    c = resolve_canary(per_knob={"uv_ver": "MARK"})
    assert c == {"secret": "HARU", "uv_ver": "MARK",
                 "source_url": "HARU", "base_path": "HARU", "ephemeral": "HARU"}


@pytest.mark.invariant("INV-CANARY-02")
def test_per_knob_beats_all_knobs_default():
    """Precedence: --stub-env-<knob>-canary > --env-canary > built-in HARU."""
    c = resolve_canary(env_canary="BASE", per_knob={"secret": "MARK"})
    assert c["secret"] == "MARK"
    assert c["uv_ver"] == c["source_url"] == c["base_path"] == c["ephemeral"] == "BASE"


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
    for knob in ("SECRET", "UV_VER", "SOURCE_URL", "BASE_PATH", "EPHEMERAL"):
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


## ── INV-CANARY-03 scanner ────────────────────────────────────────────────────────────────
##
## Hardened 2026-09-12 against an adversarial re-review of the first version (which scanned
## LINE BY LINE with a fixed `getEnv\(\s*"(HARU...)"` regex): that version missed a getEnv
## call whose string argument was pushed to the next line, any spelling of the proc name
## other than the exact case `getEnv`, and a "HARU..." literal assembled from more than one
## quoted token (`"HAR" & "U_PACK_GEO"`). This version scans the WHOLE FILE as one string
## (so a multi-line call is still one match), matches the call name by Nim's own
## style-insensitivity rule (first char case-sensitive, the rest case-insensitive with
## underscores ignored — `getEnv`/`getenv`/`get_env`/`getENV` are all the SAME identifier to
## the compiler), and joins every quoted token inside the call's first (key) argument before
## checking for the HARU substring, so a literal split across a `&` concatenation is still
## caught. Recurses subdirectories (`rglob`), not just the launcher's top level.

GETENV_ISH_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
STRING_LIT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
CANARY_SCAN_ALLOWED = {"HARUPACK_DEV_STAGE"}    # dev-only, guarded by -d:haruDev (INV-LAUNCH-02)


def _is_getenv_ident(name: str) -> bool:
    """True for every spelling Nim itself resolves to the SAME identifier as `getEnv`: the
    first character compares case-sensitively (Nim identifier-equality rule), every other
    character compares case-insensitively with underscores ignored. `GetEnv` (capital G) is
    a genuinely DIFFERENT identifier to Nim and would not compile as a call to `getEnv`, so
    it is deliberately NOT matched here."""
    return len(name) >= 2 and name[0] == "g" and name[1:].replace("_", "").lower() == "etenv"


def _matching_paren(s: str, open_at: int) -> int:
    """Index of the ')' matching the '(' at s[open_at], honouring nested parens and string
    literals (a stray '(' or ')' inside a quoted string must not desync the depth count)."""
    depth, in_str, i = 0, False, open_at
    while i < len(s):
        c = s[i]
        if in_str:
            if c == "\\":
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(s)          # unterminated call — never valid Nim, but must not raise


def _split_top_level_args(s: str) -> list[str]:
    """Split `s` on commas that are not nested inside (), [] or a "..." string — i.e. the
    call's own argument boundaries, so a `getEnv(key, "HARU-shaped default")` only inspects
    `key` (argument 0) and does not false-positive on a HARU-shaped DEFAULT value."""
    parts: list[str] = []
    depth, in_str, start, i = 0, False, 0, 0
    while i < len(s):
        c = s[i]
        if in_str:
            if c == "\\":
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(s[start:i])
            start = i + 1
        i += 1
    parts.append(s[start:])
    return parts


def _strip_line_comments(text: str) -> str:
    """Drop everything from a `#` to end of line, on EVERY original line independently (a
    described read is not a read), then rejoin with spaces into one blob so a call spanning
    multiple lines becomes one contiguous match."""
    return " ".join(line.split("#", 1)[0] for line in text.splitlines())


def haru_getenv_offenders(nim_root) -> dict[str, list[str]]:
    """Scan every `*.nim` file under `nim_root` (recursively) for a getEnv-family call whose
    first argument contains a HARU-prefixed literal — the honor-system bypass class (e.g. the
    removed HARUPACK_GEO geo bypass) — outside the `CANARY_SCAN_ALLOWED` dev whitelist.
    Returns {filename: [offending literal, ...]}, empty when clean."""
    offenders: dict[str, list[str]] = {}
    for nim in sorted(Path(nim_root).rglob("*.nim")):
        code = _strip_line_comments(nim.read_text(encoding="utf-8"))
        for m in GETENV_ISH_RE.finditer(code):
            if not _is_getenv_ident(m.group(1)):
                continue
            open_at = m.end() - 1                          # index of the call's own '('
            close_at = _matching_paren(code, open_at)
            call_args = code[open_at + 1: close_at]
            if not call_args.strip():
                continue
            key_arg = _split_top_level_args(call_args)[0]
            literal = "".join(STRING_LIT_RE.findall(key_arg))
            if "HARU" not in literal or literal in CANARY_SCAN_ALLOWED:
                continue
            offenders.setdefault(nim.name, []).append(literal)
    return offenders


@pytest.mark.invariant("INV-CANARY-03")
def test_no_plain_haru_named_input_env_read():
    """Every haru-named runtime INPUT must resolve through the canary model (envForKnob's dynamic
    `<canary>_<KNOB>` name), so the launcher source carries no `getEnv("HARU…")` string LITERAL —
    the honor-system bypass class (e.g. the removed HARUPACK_GEO geo bypass). The one exception is
    the dev-only HARUPACK_DEV_STAGE (guarded by -d:haruDev, never in a release binary). Child-facing
    vars are set with putEnv (outputs), so they never match this getEnv scan.

    Red-path: add `getEnv("HARUPACK_FOO")` to any launcher .nim, or restore the HARUPACK_GEO read,
    and this goes red naming the offending var."""
    launcher = Path(__file__).resolve().parent.parent / "src/haru_pack/launcher"
    offenders = haru_getenv_offenders(launcher)
    assert not offenders, (
        f"launcher reads haru-named env INPUT outside the canary model: {offenders}. "
        f"Route it through stubconfig.envForKnob, or (for a security gate) do not read env at all.")


@pytest.mark.invariant("INV-CANARY-03")
def test_canary_scan_catches_multiline_getenv(tmp_path):
    """Red-path for the FIRST bypass in the adversarial re-review: a getEnv call whose string
    argument sits on the next line defeated the old per-line regex entirely. Confirmed red before
    this fix (the pre-fix per-line scanner found nothing here)."""
    (tmp_path / "evil.nim").write_text(
        'let g = getEnv(\n    "HARUPACK_GEO"\n  )\n', encoding="utf-8")
    offenders = haru_getenv_offenders(tmp_path)
    assert offenders == {"evil.nim": ["HARUPACK_GEO"]}


@pytest.mark.invariant("INV-CANARY-03")
@pytest.mark.parametrize("spelling", ["getenv", "get_env", "getENV", "g_e_t_E_n_v"])
def test_canary_scan_catches_getenv_casing(tmp_path, spelling):
    """Red-path for the SECOND bypass: any spelling Nim itself resolves to the same identifier
    as `getEnv` (case-insensitive after the first char, underscores ignored) defeated the old
    scanner's exact-string `getEnv(` match."""
    (tmp_path / "evil.nim").write_text(f'let g = {spelling}("HARUPACK_GEO")\n', encoding="utf-8")
    offenders = haru_getenv_offenders(tmp_path)
    assert offenders == {"evil.nim": ["HARUPACK_GEO"]}


@pytest.mark.invariant("INV-CANARY-03")
@pytest.mark.parametrize("expr", ['"HAR" & "U_PACK_GEO"', '"HARU" & x', '"HARU"&x'])
def test_canary_scan_catches_concat_split_literal(tmp_path, expr):
    """Red-path for the THIRD bypass: a HARU-prefixed literal assembled from more than one
    quoted token via string concatenation defeated the old scanner's single-literal regex."""
    (tmp_path / "evil.nim").write_text(f"let g = getEnv({expr})\n", encoding="utf-8")
    offenders = haru_getenv_offenders(tmp_path)
    assert offenders, f"concat-split literal {expr!r} was not caught"


@pytest.mark.invariant("INV-CANARY-03")
def test_canary_scan_recurses_subdirectories(tmp_path):
    """Red-path for the FOURTH bypass: a violation in a subdirectory of the launcher tree (the
    old scanner used a non-recursive `glob('*.nim')`)."""
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "evil.nim").write_text('let g = getEnv("HARUPACK_GEO")\n', encoding="utf-8")
    offenders = haru_getenv_offenders(tmp_path)
    assert offenders == {"evil.nim": ["HARUPACK_GEO"]}


@pytest.mark.invariant("INV-CANARY-03")
def test_canary_scan_dev_stage_whitelist_still_allowed(tmp_path):
    """The one intentional exception (HARUPACK_DEV_STAGE, dev-only) must still pass clean —
    including when the scan is hardened to whole-file / concat-aware matching."""
    (tmp_path / "ok.nim").write_text(
        'when defined(haruDev):\n  let dev = getEnv(\n    "HARUPACK_DEV_STAGE")\n',
        encoding="utf-8")
    assert haru_getenv_offenders(tmp_path) == {}


@pytest.mark.invariant("INV-CANARY-03")
def test_canary_scan_ignores_haru_shaped_default_value(tmp_path):
    """A HARU-shaped literal in a getEnv DEFAULT-VALUE argument (not the key) is not a bypass —
    only the first (key) argument is inspected."""
    (tmp_path / "ok.nim").write_text(
        'let g = getEnv("SOME_UNRELATED_VAR", "HARU_shaped_default")\n', encoding="utf-8")
    assert haru_getenv_offenders(tmp_path) == {}


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
                              "source_url": "HARU", "base_path": "HARU",
                              "ephemeral": "HARU"}


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
    assert stub_config_bytes(c) == stub_config_bytes(
        c, reap=False, overwrite=False, ram_only=False, base_path="")
    assert b"reap" not in stub_config_bytes(c)
    assert b"overwrite" not in stub_config_bytes(c)
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


# ── Phase-2b: --overwrite (shred-on-reap) build half (docs/adr/0004 5b, INV-SHRED-01) ────────
# The launcher (Nim) half — the actual overwrite + fsync + guarded --haru-shred worker — is
# claimed end-to-end and by harness in tests/test_shred.py. Here: the stub-config bytes, the
# receipt, the corpus discipline, and the --overwrite-requires---reap build refusal.


@pytest.mark.invariant("INV-SHRED-01")
def test_stub_config_emits_overwrite_only_when_set():
    c = {"secret": "HARU", "uv_ver": "HARU", "source_url": "HARU", "base_path": "HARU"}
    assert b"overwrite" not in stub_config_bytes(c)
    out = stub_config_bytes(c, reap=True, overwrite=True).decode()
    assert "\noverwrite = true\n" in out
    # top-level key precedes the [canary] table (TOML)
    assert out.index("overwrite = true") < out.index("[canary]")


@pytest.mark.invariant("INV-SHRED-01")
def test_build_bakes_overwrite_into_stub_and_receipt(stub_toolchain, script_project, tmp_path):
    out = tmp_path / "app"
    info = stub_toolchain.build(script_project, out, tier="thin", reap=True, overwrite=True)
    assert "overwrite = true" in verify(out)["stub_config"]
    assert info["staging"]["overwrite"] is True


@pytest.mark.invariant("INV-SHRED-01")
def test_overwrite_requires_reap(stub_toolchain, script_project, tmp_path):
    """--overwrite is shred-ON-reap: without --reap nothing deletes the stage, so it is refused
    at build rather than silently ignored. Red-path: drop the `overwrite and not reap` raise in
    build.build → the build succeeds and ships a binary that never shreds."""
    out = tmp_path / "app"
    with pytest.raises(BuildError, match="reap"):
        stub_toolchain.build(script_project, out, tier="thin", overwrite=True)


# ── Part A: --ram-only renamed to --ephemeral (surface only; wire key `ram_only` unchanged) ──


def test_ephemeral_is_the_surface_name_and_ram_only_is_a_hidden_alias():
    """--ephemeral is the honest name; --ram-only stays a hidden, deprecated alias for one
    release. The stub-config WIRE key is deliberately still `ram_only` (ADR 0004 §2.2 pins the
    v1 corpus), so renaming the flag must not move the key."""
    from typer.main import get_command

    import haru_pack.cli as cli

    cmd = get_command(cli.app).commands["build"]
    opts = {}
    for param in cmd.params:
        for name in getattr(param, "opts", []):
            opts[name] = param
    assert "--ephemeral" in opts and not opts["--ephemeral"].hidden
    assert "--ram-only" in opts and opts["--ram-only"].hidden, "--ram-only must be a hidden alias"
    # the wire key never moved: RAM-backed staging still bakes `ram_only`, not `ephemeral`
    c = {"secret": "HARU", "uv_ver": "HARU", "source_url": "HARU", "base_path": "HARU"}
    out = stub_config_bytes(c, ram_only=True).decode()
    assert "ram_only = true" in out and "ephemeral" not in out

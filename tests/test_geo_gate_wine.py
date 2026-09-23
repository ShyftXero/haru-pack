"""The Windows online-path parity leg for the geo/ip execution gate (INV-GATE-01 / INV-GEO-01).

The native geo tests (tests/test_geo_gate.py) prove the gate on a Linux launcher. scripts/self-build.sh
only ever runs the Windows binary's `version` under wine — which reaches NEITHER `checkGeoGate` nor
the uv fetch — so "geo works on Windows" was asserted (the code cross-compiles and the .exe boots)
but never EXECUTED. This module closes that gap: it cross-compiles the REAL launcher for
windows-x86_64 (Nim + zig, exactly as `build.compiler.compile_launcher` does for a release), attaches
an encrypted geo-gated payload, and runs it UNDER WINE against a localhost resolver — so the
Windows transport (WinHTTP) and the gate decision both actually run.

WHAT THIS PROVES, AND WHAT IT DOES NOT:
  * The resolver here speaks PLAIN HTTP on 127.0.0.1. That deliberately sidesteps wine's bundled
    crypt32 root store, which cannot validate a live public-CA HTTPS handshake — the caveat in the
    issue. So this exercises WinHTTP TRANSPORT + the gate logic under a real Windows binary; it does
    NOT exercise a live TLS handshake against a public resolver. That last mile needs a real-Windows
    CI runner (see the PR / INV-SUPPLY-13 note).
  * DENY: the resolver reports a location the policy forbids -> the gate reaches `not licensed to run
    in this location` and quits 3. That message (as opposed to `cannot verify … location`) is the
    proof that WinHTTP REACHED the resolver under wine — an unreachable resolver fails closed with a
    different message. This is the load-bearing assertion.
  * ALLOW: the resolver reports an allowed location -> the gate PASSES and the launcher proceeds
    PAST it into staging (which then fails under wine because the test payload ships a POSIX `uv`
    shell script, not `uv.exe`). "past the gate, not `not licensed`" is the allow-side proof.

No cacert.pem is shipped or needed: puppy on Windows uses WinHTTP, and for plain HTTP no CA is
consulted at all. The build sets no `-d:puppyLibcurl` (INV-SUPPLY-13), so this is the real backend.
"""
from __future__ import annotations

import http.server
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from haru_pack import crypto
from haru_pack.build import stub_config_bytes

from _stage_helpers import build_payload_zip, make_payload

EXIT_LICENSE = 3
SECRET = "s3cret-build-key"
_CANARY = {"secret": "HARU", "uv_ver": "HARU", "source_url": "HARU", "base_path": "HARU"}

NIM = shutil.which("nim")
WINE = shutil.which("wine")


class _Resolver:
    """A localhost resolver serving one ipwho.is-shaped JSON body over PLAIN HTTP."""

    def __init__(self, body: dict):
        raw = json.dumps(body).encode()

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw)

            do_HEAD = do_GET

        self._httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.port = self._httpd.server_address[1]
        self._t = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *a):
        self._httpd.shutdown()
        self._httpd.server_close()

    def url(self) -> str:
        # 127.0.0.1 inside the wine process maps to the host loopback, so the launcher reaches
        # this server via WinHTTP.
        return f"http://127.0.0.1:{self.port}/"


@pytest.fixture(scope="module")
def windows_launcher(tmp_path_factory) -> Path:
    if NIM is None:
        pytest.skip("nim not installed; the launcher cannot be cross-compiled")
    if WINE is None:
        pytest.skip("wine not installed; the Windows geo parity leg needs it")
    from haru_pack import toolchain
    if toolchain.find_managed_zig() is None:
        pytest.skip("managed zig not installed; needed to cross-compile the Windows launcher")
    from haru_pack.build.compiler import compile_launcher
    d = tmp_path_factory.mktemp("geo-win")
    return compile_launcher(NIM, "windows-x86_64", d)


def _geo_exe(tmp_path: Path, launcher: Path, geo_policy: dict, name: str) -> Path:
    from haru_pack.overlay import attach
    payload = build_payload_zip(make_payload(tmp_path / ("asm-" + name)))
    container = crypto.encrypt(payload, SECRET.encode(), geo=geo_policy)
    out = tmp_path / (name + ".exe")
    attach(launcher, container, out, flags=1, stub_config=stub_config_bytes(_CANARY))
    return out


def _run_wine(exe: Path, tmp_path: Path) -> subprocess.CompletedProcess:
    prefix = tmp_path / "wineprefix"
    prefix.mkdir(exist_ok=True)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = dict(os.environ)
    env.update({
        "WINEPREFIX": str(prefix),
        "WINEDEBUG": "-all",
        "HOME": str(home),
        "HARU_SECRET": SECRET,
    })
    return subprocess.run([WINE, str(exe)], capture_output=True, text=True, env=env,
                          cwd=tmp_path, stdin=subprocess.DEVNULL, timeout=300, check=False)


@pytest.mark.invariant("INV-GEO-01")
def test_windows_geo_gate_denies_a_forbidden_location_under_wine(tmp_path, windows_launcher):
    """The load-bearing parity assertion: a Windows binary, under wine, reaches its resolver via
    WinHTTP, sees a forbidden location, and fails closed with `not licensed` (exit 3).

    If wine's WinHTTP could NOT reach the resolver, the gate would fail closed with `cannot verify
    … location` instead — so asserting the `not licensed` message is what proves the transport
    actually ran, not merely that the gate fails closed."""
    with _Resolver({"success": True, "country_code": "FR"}) as r:
        exe = _geo_exe(tmp_path, windows_launcher,
                       {"endpoints": [r.url()], "consensus": 1,
                        "allow": [{"country_code": "US"}]}, "deny")
        res = _run_wine(exe, tmp_path)
    assert res.returncode == EXIT_LICENSE, (res.returncode, res.stderr)
    assert "not licensed" in res.stderr, (
        "the gate did not reach the 'not licensed' verdict; if it says 'cannot verify' then "
        "WinHTTP under wine could not reach the resolver and this leg needs a real-Windows "
        f"runner. stderr:\n{res.stderr}"
    )
    assert "PAYLOAD_UV_RAN" not in res.stdout


@pytest.mark.invariant("INV-GATE-01")
def test_windows_geo_gate_allows_an_allowed_location_under_wine(tmp_path, windows_launcher):
    """The allow side: same binary, resolver now reports an allowed location, so the gate PASSES
    and the launcher proceeds PAST it. Under wine it then fails in staging (the test payload ships
    a POSIX `uv` shell script, not `uv.exe`), which is exactly the proof the gate did not deny:
    the failure is downstream of the gate, not `not licensed` / `cannot verify`."""
    with _Resolver({"success": True, "country_code": "US"}) as r:
        exe = _geo_exe(tmp_path, windows_launcher,
                       {"endpoints": [r.url()], "consensus": 1,
                        "allow": [{"country_code": "US"}]}, "allow")
        res = _run_wine(exe, tmp_path)
    # The gate passed: neither fail-closed verdict was printed, and the exit is not the license code.
    assert "not licensed" not in res.stderr, res.stderr
    assert "cannot verify" not in res.stderr, res.stderr
    assert res.returncode != EXIT_LICENSE, (res.returncode, res.stderr)
    # Positive evidence it reached the post-gate staging phase.
    assert "uv" in res.stderr.lower(), (
        f"expected the launcher to proceed past the gate into uv staging; stderr:\n{res.stderr}"
    )

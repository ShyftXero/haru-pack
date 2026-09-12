"""Phase 4 execution gates: online geo/ip (INV-GATE-01 fail-closed uniform gate, INV-GEO-01 no
env bypass + online consensus).

These compile the REAL Nim launcher, build an ENCRYPTED binary whose hidden policy carries a geo
gate pointed at a throwaway localhost resolver that speaks ipwho.is's shape ({"success":true,
"country_code":...}), and RUN it. The gate resolves online, matches an allow-policy, and FAILS
CLOSED — and no environment variable can satisfy or bypass it. Red-paths are walked, not asserted
from a comment:

  * resolver says an allowed location   -> runs
  * resolver says a denied location     -> fail closed (exit 3), app never runs
  * resolver unreachable / success=false -> fail closed, app never runs
  * HARUPACK_GEO (the retired bypass) set to an allowed value while the resolver denies -> STILL
    denied: the env cannot decide the gate (this is the security gap that Phase 4 closes)
  * consensus K unmet (one of two endpoints down) -> fail closed
"""
from __future__ import annotations

import http.server
import json
import socket
import threading
from pathlib import Path

import pytest

from haru_pack import crypto
from haru_pack.build import stub_config_bytes
from haru_pack.overlay import attach

from _stage_helpers import build_payload_zip, compile_launcher, make_payload, run

EXIT_LICENSE = 3           # cryptbox / execgate: expired or not-licensed-for-location, fail-closed
SECRET = "s3cret-build-key"
_CANARY = {"secret": "HARU", "uv_ver": "HARU", "source_url": "HARU", "base_path": "HARU"}


class _Resolver:
    """A localhost resolver. Serves a JSON body (ipwho.is shape) or a status; can be started
    'dead' (never listens) by not entering the context."""

    def __init__(self, body: dict | None = None, status: int = 200):
        raw = json.dumps(body).encode() if body is not None else b""
        srv_raw, srv_status = raw, status

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if srv_status != 200:
                    self.send_response(srv_status)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(srv_raw)))
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(srv_raw)

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
        return f"http://127.0.0.1:{self.port}/"


def _dead_url() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}/"


def _geo_exe(tmp_path: Path, launcher: Path, geo_policy: dict, name: str = "app-geo") -> Path:
    """An encrypted binary whose hidden policy carries `geo_policy`."""
    payload = build_payload_zip(make_payload(tmp_path / ("asm-" + name)))
    container = crypto.encrypt(payload, SECRET.encode(), geo=geo_policy)
    out = tmp_path / name
    attach(launcher, container, out, flags=1, stub_config=stub_config_bytes(_CANARY))
    out.chmod(0o755)
    return out


def _run(exe: Path, tmp_path: Path, env_extra: dict | None = None):
    env = {"HARU_SECRET": SECRET}
    env.update(env_extra or {})
    return run(exe, tmp_path, env_extra=env)


@pytest.fixture(scope="module")
def launcher(tmp_path_factory) -> Path:
    return compile_launcher(tmp_path_factory.mktemp("nim") / "launcher")


def _allowed(fields: dict) -> dict:
    return {"success": True, **fields}


@pytest.mark.invariant("INV-GATE-01")
def test_geo_allowed_location_runs(tmp_path, launcher):
    with _Resolver(_allowed({"country_code": "US", "region": "Texas"})) as r:
        exe = _geo_exe(tmp_path, launcher,
                       {"endpoints": [r.url()], "consensus": 1,
                        "allow": [{"country_code": "US"}]})
        res = _run(exe, tmp_path)
    assert res.returncode == 0, res.stderr
    assert "PAYLOAD_UV_RAN" in res.stdout


@pytest.mark.invariant("INV-GATE-01")
def test_geo_denied_location_fails_closed(tmp_path, launcher):
    """RED-PATH: the resolver reports a location the policy does not allow -> the app must not
    run (exit 3)."""
    with _Resolver(_allowed({"country_code": "FR"})) as r:
        exe = _geo_exe(tmp_path, launcher,
                       {"endpoints": [r.url()], "consensus": 1,
                        "allow": [{"country_code": "US"}]})
        res = _run(exe, tmp_path)
    assert res.returncode == EXIT_LICENSE, (res.returncode, res.stderr)
    assert "PAYLOAD_UV_RAN" not in res.stdout
    assert "not licensed" in res.stderr


@pytest.mark.invariant("INV-GATE-01")
def test_geo_resolver_unreachable_fails_closed(tmp_path, launcher):
    """RED-PATH: nothing answers -> fewer than consensus resolve -> fail closed, do not run."""
    exe = _geo_exe(tmp_path, launcher,
                   {"endpoints": [_dead_url()], "consensus": 1,
                    "allow": [{"country_code": "US"}]})
    res = _run(exe, tmp_path)
    assert res.returncode == EXIT_LICENSE, (res.returncode, res.stderr)
    assert "PAYLOAD_UV_RAN" not in res.stdout


@pytest.mark.invariant("INV-GATE-01")
def test_geo_success_false_is_not_a_resolution(tmp_path, launcher):
    """RED-PATH: a resolver that answers 200 but with success=false has NOT resolved; the gate
    must fail closed rather than read stale/garbage fields."""
    with _Resolver({"success": False, "message": "quota", "country_code": "US"}) as r:
        exe = _geo_exe(tmp_path, launcher,
                       {"endpoints": [r.url()], "consensus": 1,
                        "allow": [{"country_code": "US"}]})
        res = _run(exe, tmp_path)
    assert res.returncode == EXIT_LICENSE, (res.returncode, res.stderr)
    assert "PAYLOAD_UV_RAN" not in res.stdout


@pytest.mark.invariant("INV-GEO-01")
def test_env_cannot_bypass_the_geo_gate(tmp_path, launcher):
    """The security gap Phase 4 closes: the retired HARUPACK_GEO env (and any other) must NOT be
    able to satisfy the gate. Resolver denies (FR); env claims US; result stays denied."""
    with _Resolver(_allowed({"country_code": "FR"})) as r:
        exe = _geo_exe(tmp_path, launcher,
                       {"endpoints": [r.url()], "consensus": 1,
                        "allow": [{"country_code": "US"}]})
        res = _run(exe, tmp_path, env_extra={"HARUPACK_GEO": "US", "HARU_GEO": "US",
                                             "GEO": "US", "country_code": "US"})
    assert res.returncode == EXIT_LICENSE, (res.returncode, res.stderr)
    assert "PAYLOAD_UV_RAN" not in res.stdout


@pytest.mark.invariant("INV-GEO-01")
def test_consensus_requires_k_endpoints(tmp_path, launcher):
    """With two endpoints and consensus 2, one endpoint down means consensus is unmet -> fail
    closed, even though the reachable endpoint would allow."""
    with _Resolver(_allowed({"country_code": "US"})) as up:
        exe = _geo_exe(tmp_path, launcher,
                       {"endpoints": [up.url(), _dead_url()], "consensus": 2,
                        "allow": [{"country_code": "US"}]})
        res = _run(exe, tmp_path)
    assert res.returncode == EXIT_LICENSE, (res.returncode, res.stderr)
    assert "PAYLOAD_UV_RAN" not in res.stdout


@pytest.mark.invariant("INV-GEO-01")
def test_consensus_met_by_two_agreeing_endpoints_runs(tmp_path, launcher):
    """Two endpoints both resolve and agree the caller is allowed, consensus 2 -> runs."""
    with _Resolver(_allowed({"country_code": "US"})) as a, \
         _Resolver(_allowed({"country_code": "US", "city": "Austin"})) as b:
        exe = _geo_exe(tmp_path, launcher,
                       {"endpoints": [a.url(), b.url()], "consensus": 2,
                        "allow": [{"country_code": "US"}]})
        res = _run(exe, tmp_path)
    assert res.returncode == 0, res.stderr
    assert "PAYLOAD_UV_RAN" in res.stdout

"""Phase 3 remote-fetch (INV-REMOTE-01): the payload is FETCHED over HTTP at runtime instead
of appended, but runs through the SAME pipeline — verify → decrypt → license → stage — so the
build-baked footer digest is the one trust anchor no matter where the bytes come from.

These compile the REAL Nim launcher, build a remote binary (attach(remote=True): digest baked,
NO payload embedded), host the payload on a throwaway localhost HTTP server, and RUN the exe.
The red-paths are walked, not asserted from a comment:

  * tampered remote bytes  -> digest mismatch -> fail closed (ExitDigestMismatch)
  * server down / non-200  -> fail closed (ExitRemoteFetch), the app never runs
  * SOURCE_URL env mirror  -> a good mirror still runs (digest-anchored override)
  * an APPENDED build      -> ignores SOURCE_URL env, never flips to a network fetch
"""
from __future__ import annotations

import http.server
import socket
import threading
from pathlib import Path

import pytest

from haru_pack.build import stub_config_bytes
from haru_pack.overlay import attach

from _stage_helpers import (build_payload_zip, compile_launcher, make_payload, run,
                            stage_from)

EXIT_DIGEST_MISMATCH = 6   # main.nim ExitDigestMismatch — fetched bytes != baked digest
EXIT_REMOTE_FETCH = 11     # main.nim ExitRemoteFetch — transport failure, fail-closed

_CANARY = {"secret": "HARU", "uv_ver": "HARU", "source_url": "HARU", "base_path": "HARU"}


class _Server:
    """A localhost HTTP server that serves one body at /p (or a chosen status)."""

    def __init__(self, body: bytes, status: int = 200):
        self.body = body
        self.status = status
        srv_body, srv_status = self.body, self.status

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):  # keep the test output quiet
                pass

            def _send(self):
                if srv_status != 200:
                    self.send_response(srv_status)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(srv_body)))
                self.end_headers()
                self.wfile.write(srv_body)

            def do_HEAD(self):
                self._send() if srv_status == 200 else self.send_error(srv_status)

            def do_GET(self):
                self._send()

        self._httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.port = self._httpd.server_address[1]
        self._t = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *a):
        self._httpd.shutdown()
        self._httpd.server_close()

    def url(self, path: str = "/p") -> str:
        return f"http://127.0.0.1:{self.port}{path}"


def _dead_url() -> str:
    """A URL on a closed port — bind, read the port, close, so nothing is listening."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}/p"


def _payload_bytes(tmp_path: Path) -> bytes:
    return build_payload_zip(make_payload(tmp_path / "asm"))


def _remote_exe(tmp_path: Path, launcher: Path, payload: bytes, source_url: str) -> Path:
    """Build a remote-fetch binary: the footer bakes sha256(payload) but embeds NO payload."""
    out = tmp_path / "app-remote"
    attach(launcher, payload, out,
           stub_config=stub_config_bytes(_CANARY, source_url=source_url), remote=True)
    out.chmod(0o755)
    return out


@pytest.fixture(scope="module")
def launcher(tmp_path_factory) -> Path:
    return compile_launcher(tmp_path_factory.mktemp("nim") / "launcher")


@pytest.mark.invariant("INV-REMOTE-01")
def test_remote_fetch_happy_path_runs(tmp_path, launcher):
    """A remote binary fetches its payload and runs it — no bytes embedded in the exe."""
    payload = _payload_bytes(tmp_path)
    with _Server(payload) as srv:
        exe = _remote_exe(tmp_path, launcher, payload, srv.url())
        # Proof it embeds none of the payload: the payload's bytes do not appear in the exe.
        assert payload not in exe.read_bytes()
        r = run(exe, tmp_path)
    assert r.returncode == 0, r.stderr
    assert "PAYLOAD_UV_RAN" in r.stdout
    assert stage_from(r.stdout)


@pytest.mark.invariant("INV-REMOTE-01")
def test_remote_tampered_bytes_fail_closed(tmp_path, launcher):
    """RED-PATH: the server returns bytes that do not match the baked digest. The launcher must
    refuse them (ExitDigestMismatch) and NOT run — this is the whole point of INV-REMOTE-01."""
    payload = _payload_bytes(tmp_path)
    tampered = payload + b"\x00evil"          # a valid zip prefix, wrong digest
    exe = _remote_exe(tmp_path, launcher, payload, "http://placeholder/p")
    with _Server(tampered) as srv:
        # Point the env override at the tampering server (mirror path), baked URL is a placeholder.
        r = run(exe, tmp_path, env_extra={"HARU_SOURCE_URL": srv.url()})
    assert r.returncode == EXIT_DIGEST_MISMATCH, (r.returncode, r.stderr)
    assert "PAYLOAD_UV_RAN" not in r.stdout
    assert "integrity check FAILED" in r.stderr


@pytest.mark.invariant("INV-REMOTE-01")
def test_remote_server_down_fail_closed(tmp_path, launcher):
    """RED-PATH: nothing is listening. A remote build with no reachable payload must fail
    closed (ExitRemoteFetch), never fall back to running something else."""
    payload = _payload_bytes(tmp_path)
    exe = _remote_exe(tmp_path, launcher, payload, _dead_url())
    r = run(exe, tmp_path)
    assert r.returncode == EXIT_REMOTE_FETCH, (r.returncode, r.stderr)
    assert "PAYLOAD_UV_RAN" not in r.stdout
    assert "remote-fetch of the payload failed" in r.stderr


@pytest.mark.invariant("INV-REMOTE-01")
def test_remote_server_404_fail_closed(tmp_path, launcher):
    """RED-PATH: the server answers but with a non-200. Fail closed, do not run."""
    payload = _payload_bytes(tmp_path)
    with _Server(b"", status=404) as srv:
        exe = _remote_exe(tmp_path, launcher, payload, srv.url())
        r = run(exe, tmp_path)
    assert r.returncode == EXIT_REMOTE_FETCH, (r.returncode, r.stderr)
    assert "PAYLOAD_UV_RAN" not in r.stdout


@pytest.mark.invariant("INV-REMOTE-01")
def test_remote_env_override_to_good_mirror_runs(tmp_path, launcher):
    """The SOURCE_URL knob (env) overrides the baked URL for mirror/failover — and because the
    bytes are digest-anchored, a good mirror runs even when the baked URL is dead."""
    payload = _payload_bytes(tmp_path)
    exe = _remote_exe(tmp_path, launcher, payload, _dead_url())     # baked URL: nothing there
    with _Server(payload) as mirror:
        r = run(exe, tmp_path, env_extra={"HARU_SOURCE_URL": mirror.url()})
    assert r.returncode == 0, r.stderr
    assert "PAYLOAD_UV_RAN" in r.stdout


@pytest.mark.invariant("INV-REMOTE-01")
def test_appended_build_ignores_source_url_env(tmp_path, launcher):
    """An APPENDED build (the default) must NEVER flip to a network fetch because someone set
    SOURCE_URL in the environment: the delivery mode is fixed at build time by the footer flag.
    Here the env points at a server serving garbage; the exe must still run the appended payload."""
    payload = _payload_bytes(tmp_path)
    out = tmp_path / "app-appended"
    attach(launcher, payload, out, stub_config=stub_config_bytes(_CANARY))  # remote=False
    out.chmod(0o755)
    with _Server(b"garbage-not-a-payload") as srv:
        r = run(out, tmp_path, env_extra={"HARU_SOURCE_URL": srv.url()})
    assert r.returncode == 0, r.stderr
    assert "PAYLOAD_UV_RAN" in r.stdout

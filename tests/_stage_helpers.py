"""Shared end-to-end machinery for the Phase-2 staging tests (docs/adr/0004).

tests/test_reap.py (INV-REAP-01) and tests/test_ram_only.py (INV-RAM-01 / INV-BASE-01) both
compile the REAL Nim launcher, attach a real payload plus a v2 stub-config carrying the
Phase-2 keys, and RUN the resulting executable. Nothing on the launcher side is stubbed —
these are the launcher (Nim) half of the invariants; the build (Python) half lives in
tests/test_canary.py.

`uv` is a shell script that echoes HARUPACK_STAGE, so a test can see exactly where the payload
was staged (and, for reap, poll for that subtree to vanish).
"""
from __future__ import annotations

import stat
import subprocess
from pathlib import Path

import pytest

from haru_pack.overlay import attach
from haru_pack.payload import build_payload_zip  # re-exported for the test modules

__all__ = [
    "DEV_SHM",
    "EXIT_BAD_STUB",
    "LAUNCHER_SRC",
    "REPO",
    "UV_ECHO_STAGE",
    "build_payload_zip",
    "compile_launcher",
    "make_payload",
    "pack",
    "run",
    "stage_from",
    "stub_toml2",
    "wait_gone",
]

REPO = Path(__file__).resolve().parent.parent
LAUNCHER_SRC = REPO / "src/haru_pack/launcher/main.nim"

EXIT_BAD_STUB = 10          # main.nim ExitBadStub — a malformed/unsafe stub-config
DEV_SHM = Path("/dev/shm")

# The bundled `uv` echoes the stage dir the launcher exported, so a test can assert exactly
# where staging landed and, for reap, poll for that subtree to disappear.
UV_ECHO_STAGE = 'echo "PAYLOAD_UV_RAN"\necho "STAGE=$HARUPACK_STAGE"\nexit 0'


def compile_launcher(out: Path, *defines: str) -> Path:
    args = ["nim", "c", "-d:release", f"--nimcache:{out.parent / ('nc-' + out.name)}",
            f"--out:{out}", *[f"-d:{d}" for d in defines], str(LAUNCHER_SRC)]
    r = subprocess.run(args, capture_output=True, text=True, cwd=REPO, check=False)
    if r.returncode != 0 or not out.exists():
        pytest.fail("nim compile failed:\n" + (r.stderr or r.stdout)[-3000:])
    return out


def _uv(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def make_payload(root: Path, *, uv_body: str = UV_ECHO_STAGE,
                 extra_files: dict | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "app").mkdir(exist_ok=True)
    (root / "app" / "hello.py").write_text("print('hi')\n")
    (root / "manifest.toml").write_text(
        'name = "t"\nkind = "script"\napp_subdir = "app"\n'
        'entrypoint = ["hello.py"]\ntier = "default"\n'
        "fetch_uv = false\noffline = false\n")
    _uv(root / "vendor" / "uv", uv_body)
    # Extra stage-relative files, e.g. a bundled data seed the app rewrites in place ({"data/app.db":
    # b"seed"}). Lets a test exercise the #4 declared-writable path end to end.
    for rel, data in (extra_files or {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return root


def stub_toml2(*, secret: str = "HARU", uv_ver: str = "HARU", source_url: str = "HARU",
               base_path_canary: str = "HARU", ephemeral_canary: str = "HARU",
               reap: bool = False, overwrite: bool = False,
               ram_only: bool = False, base_path: str = "", unpacked_bytes: int = 0,
               writable: list | tuple = ()) -> bytes:
    """A v2 stub-config carrying the Phase-2/3 staging keys (ADR 0004 + 0005). Optional keys are
    emitted only when set, exactly as build.stub_config_bytes does - so the bytes a test feeds the
    launcher are the same shape a real build produces. `ephemeral_canary` and `unpacked_bytes`
    are the ADR-0005 additions; the ephemeral canary line is written only when non-default, so the
    four-key v1 corpus is preserved."""
    lines = ["stub_config_version = 1"]
    if reap:
        lines.append("reap = true")
    if overwrite:
        lines.append("overwrite = true")
    if ram_only:
        lines.append("ram_only = true")
    if base_path:
        lines.append(f'base_path = "{base_path}"')
    if unpacked_bytes:
        lines.append(f"unpacked_bytes = {int(unpacked_bytes)}")
    if writable:
        items = ", ".join('"' + w.replace("\\", "\\\\").replace('"', '\\"') + '"' for w in writable)
        lines.append(f"writable = [{items}]")
    lines += ["", "[canary]",
              f'secret = "{secret}"', f'uv_ver = "{uv_ver}"',
              f'source_url = "{source_url}"', f'base_path = "{base_path_canary}"']
    if ephemeral_canary != "HARU":
        lines.append(f'ephemeral = "{ephemeral_canary}"')
    return ("\n".join(lines) + "\n").encode()


def pack(launcher: Path, payload: bytes, out: Path, *, stub_config: bytes) -> dict:
    """Attach a payload + stub-config onto the compiled launcher, producing a runnable exe."""
    info = attach(launcher, payload, out, flags=0, stub_config=stub_config)
    out.chmod(0o755)
    return info


def run(exe: Path, tmp_path: Path, *,
        env_extra: dict | None = None,
        args: list | tuple = ()) -> subprocess.CompletedProcess:
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    (tmp_path / "home").mkdir(exist_ok=True)
    # PATH="" on purpose: the detached reaper sets its OWN known-good PATH inside its script,
    # so `rm` must resolve even when the launcher inherited an empty PATH (INV-REAP-01).
    env = {"HOME": str(tmp_path / "home"), "XDG_CACHE_HOME": str(cache), "PATH": ""}
    env.update(env_extra or {})
    # umask 022 because stage.nim refuses a group-writable stage dir on this 002 box.
    return subprocess.run([str(exe), *args], capture_output=True, text=True, cwd=tmp_path,
                          env=env, umask=0o022, stdin=subprocess.DEVNULL, timeout=60,
                          check=False)


def stage_from(stdout: str) -> str | None:
    for line in stdout.splitlines():
        if line.startswith("STAGE="):
            return line[len("STAGE="):]
    return None


def wait_gone(path: Path, timeout: float = 15.0) -> bool:
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not path.exists():
            return True
        time.sleep(0.05)
    return not path.exists()

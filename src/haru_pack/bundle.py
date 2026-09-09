from __future__ import annotations
import os, shutil, subprocess, sys, tarfile, tempfile, urllib.request, zipfile
from pathlib import Path

UV_VERSION = "0.10.4"

_UV_ASSET = {
    "windows": "uv-x86_64-pc-windows-msvc.zip",
    "linux":   "uv-x86_64-unknown-linux-gnu.tar.gz",
    "darwin":  "uv-x86_64-apple-darwin.tar.gz",
}

def _host_os() -> str:
    if sys.platform == "win32": return "windows"
    if sys.platform == "darwin": return "darwin"
    return "linux"

def _target_os(target: str) -> str:
    return _host_os() if target == "host" else target  # target is "windows" for cross

def _extract_find(archive: Path, name: str, dest: Path) -> None:
    with tempfile.TemporaryDirectory() as td:
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as z: z.extractall(td)
        else:
            with tarfile.open(archive) as t: t.extractall(td)
        for root, _, files in os.walk(td):
            if name in files:
                shutil.move(os.path.join(root, name), dest)
                return
    raise RuntimeError(f"{name} not found inside {archive.name}")

def bundle_uv(target: str, vendor_dir: Path, version: str = UV_VERSION) -> Path:
    """Place a uv binary for the target OS into vendor_dir. Host: copy local uv if present,
    else download; cross: download the target-OS release."""
    vendor_dir.mkdir(parents=True, exist_ok=True)
    tos = _target_os(target)
    exe = "uv.exe" if tos == "windows" else "uv"
    dest = vendor_dir / exe
    if target == "host":
        local = shutil.which("uv")
        if local:
            shutil.copy2(local, dest)
            if tos != "windows": dest.chmod(0o755)
            return dest
    url = f"https://github.com/astral-sh/uv/releases/download/{version}/{_UV_ASSET[tos]}"
    with tempfile.TemporaryDirectory() as td:
        arc = Path(td) / _UV_ASSET[tos]
        urllib.request.urlretrieve(url, arc)
        _extract_find(arc, exe, dest)
    if tos != "windows": dest.chmod(0o755)
    return dest

def bundle_python(target: str, vendor_dir: Path, version: str = "3.12") -> Path:
    """thick: stage a standalone Python into vendor/python. Returns the ABS interpreter
    path (build-time use; the launcher rediscovers it at runtime). Host-only for now."""
    if target != "host":
        raise RuntimeError("thick cross-compile Python bundling not supported yet — "
                           "build --thick on the target OS (uv can't stage a runnable "
                           "foreign-OS interpreter from here)")
    pydir = vendor_dir / "python"
    pydir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, UV_PYTHON_INSTALL_DIR=str(pydir))
    subprocess.run(["uv", "python", "install", version], env=env, check=True,
                   capture_output=True, text=True)
    cands = [c for c in list(pydir.rglob("python3")) + list(pydir.rglob("python.exe"))
             if c.parent.name == "bin" or c.name == "python.exe"]
    for c in sorted({c.resolve() for c in cands}):
        if c.is_file():
            return c
    raise RuntimeError("staged Python interpreter not found")


def warm_cache_and_lock(app_dir: Path, py: Path, cache_dir: Path, tmp_env: Path) -> None:
    """Populate a bundled uv cache with the project's deps (+ write uv.lock) using a
    THROWAWAY env outside the payload, so the runtime can build its venv offline."""
    env = dict(os.environ, UV_CACHE_DIR=str(cache_dir), UV_PYTHON=str(py),
               UV_PYTHON_DOWNLOADS="never", UV_PROJECT_ENVIRONMENT=str(tmp_env))
    subprocess.run(["uv", "sync", "--project", str(app_dir)], env=env, check=True,
                   capture_output=True, text=True)


def install_browsers(tmp_env: Path, browsers: list, dest: Path) -> None:
    """Install Playwright browsers into `dest` via the throwaway env's playwright."""
    pw = tmp_env / ("Scripts/playwright.exe" if sys.platform == "win32" else "bin/playwright")
    env = dict(os.environ, PLAYWRIGHT_BROWSERS_PATH=str(dest))
    subprocess.run([str(pw), "install", *browsers], env=env, check=True,
                   capture_output=True, text=True)

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

def bundle_python(target: str, vendor_dir: Path, version: str = "3.12") -> str:
    """thick: stage a standalone Python into vendor/python. Returns the manifest-relative
    interpreter path. Host-only for now (cross-OS python staging is a known gap)."""
    if target != "host":
        raise RuntimeError("thick cross-compile Python bundling not supported yet — "
                           "build --thick on the target OS (uv can't stage a runnable "
                           "foreign-OS interpreter from here)")
    pydir = vendor_dir / "python"
    pydir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, UV_PYTHON_INSTALL_DIR=str(pydir))
    subprocess.run(["uv", "python", "install", version], env=env, check=True,
                   capture_output=True, text=True)
    # locate the interpreter
    for pat in ("bin/python3", "bin/python", "python.exe", "python"):
        hits = list(pydir.glob(f"*/{pat}"))
        if hits:
            rel = hits[0].relative_to(vendor_dir.parent)  # relative to payload root
            return str(rel).replace(os.sep, "/")
    raise RuntimeError("staged Python interpreter not found")

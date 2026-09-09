from __future__ import annotations
import os, platform, shutil, subprocess, sys, tarfile, tempfile, urllib.request
from pathlib import Path
from .paths import nim_dir, toolchain_dir
from .archives import safe_extract_tar

NIM_VERSION = "2.2.6"  # pinned; bump deliberately

# ---------- Nim ----------
def find_nim() -> str | None:
    """Prefer a managed Nim, then one on PATH."""
    managed = nim_dir() / "bin" / ("nim.exe" if sys.platform == "win32" else "nim")
    if managed.exists():
        return str(managed)
    return shutil.which("nim")

def nim_version(nim: str) -> str | None:
    try:
        out = subprocess.run([nim, "--version"], capture_output=True, text=True, timeout=30)
        return out.stdout.splitlines()[0] if out.returncode == 0 else None
    except Exception:
        return None

def _nim_archive_url() -> tuple[str, str]:
    m = platform.machine().lower()
    if sys.platform.startswith("linux"):
        arch = {"x86_64": "linux_x64", "aarch64": "linux_arm64"}.get(m)
        if not arch:
            raise RuntimeError(f"no prebuilt Nim for linux/{m}; install Nim manually or via choosenim")
        return f"https://nim-lang.org/download/nim-{NIM_VERSION}-{arch}.tar.xz", "tar.xz"
    if sys.platform == "win32":
        return f"https://nim-lang.org/download/nim-{NIM_VERSION}_x64.zip", "zip"
    raise RuntimeError("macOS: install Nim via `brew install nim` or choosenim (https://nim-lang.org/install.html)")

def install_nim(force: bool = False) -> str:
    """Download + extract a pinned Nim into the managed toolchain dir."""
    existing = find_nim()
    if existing and not force:
        return existing
    url, kind = _nim_archive_url()
    dest = nim_dir()
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        arc = Path(td) / f"nim.{kind}"
        urllib.request.urlretrieve(url, arc)
        extract_to = Path(td) / "x"
        if kind == "tar.xz":
            safe_extract_tar(arc, extract_to)       # INV-SUPPLY-03
        else:
            import zipfile
            with zipfile.ZipFile(arc) as z:
                z.extractall(extract_to)
        inner = next(p for p in extract_to.iterdir() if p.is_dir())
        shutil.move(str(inner), str(dest))
    nim = find_nim()
    if not nim:
        raise RuntimeError("Nim install failed (binary not found after extract)")
    return nim

NIM_DEPS = ("zippy", "puppy", "parsetoml", "nimcrypto")   # launcher imports these (puppy pulls webby)

def ensure_nim_deps(nim: str) -> bool:
    """The launcher imports zippy + puppy; make sure nimble has them."""
    nimble = str(Path(nim).with_name("nimble" + (".exe" if sys.platform == "win32" else "")))
    if not Path(nimble).exists():
        nimble = shutil.which("nimble") or "nimble"
    ok = True
    for pkg in NIM_DEPS:
        try:
            r = subprocess.run([nimble, "install", "-y", pkg], capture_output=True, text=True, timeout=600)
            ok = ok and r.returncode == 0
        except Exception:
            ok = False
    return ok

# ---------- C toolchain (esp. lin->win cross) ----------
def _distro_mingw_cmd() -> str:
    info = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1); info[k] = v.strip().strip('"')
    except Exception:
        pass
    ident = (info.get("ID", "") + " " + info.get("ID_LIKE", "")).lower()
    if any(d in ident for d in ("debian", "ubuntu")):
        return "sudo apt install mingw-w64"
    if any(d in ident for d in ("fedora", "rhel", "centos")):
        return "sudo dnf install mingw64-gcc"
    if "arch" in ident:
        return "sudo pacman -S mingw-w64-gcc"
    if any(d in ident for d in ("suse", "opensuse")):
        return "sudo zypper install mingw64-cross-gcc"
    if sys.platform == "darwin":
        return "brew install mingw-w64"
    return "install the 'mingw-w64' cross toolchain from your package manager"

def detect_c_toolchain(target: str) -> dict:
    """target: 'host' or 'windows'. Returns {ok, compiler, advice}."""
    if target == "windows" and sys.platform != "win32":
        cc = shutil.which("x86_64-w64-mingw32-gcc")
        if cc:
            return {"ok": True, "compiler": cc, "advice": ""}
        return {"ok": False, "compiler": None,
                "advice": ("cross-compiling Linux->Windows needs the mingw-w64 toolchain "
                           f"(provides x86_64-w64-mingw32-gcc):\n    {_distro_mingw_cmd()}")}
    # host target
    for c in ("cc", "gcc", "clang"):
        p = shutil.which(c)
        if p:
            return {"ok": True, "compiler": p, "advice": ""}
    if sys.platform == "win32":
        return {"ok": False, "compiler": None,
                "advice": "no C compiler found; run `choosenim` (bundles mingw) or install MSVC Build Tools"}
    return {"ok": False, "compiler": None,
            "advice": "no C compiler found; install gcc/clang from your package manager"}

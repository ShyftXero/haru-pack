"""Toolchain discovery and the Nim library pins.

Installing Nim lives in `toolchain.py` — one path, choosenim. This module finds what is
already there and pins the Nim libraries the launcher links against.
"""
from __future__ import annotations
import shutil, subprocess, sys
from pathlib import Path

from .toolchain import (CHOOSENIM_VERSION, NIM_VERSION, ToolchainError,  # noqa: F401
                        find_managed_nim, install_nim, sudo_command, system_packages)

def find_nim() -> str | None:
    """haru-pack's own Nim first, then one on PATH.

    A system Nim is accepted as a courtesy for people who already have one, but haru-pack
    never installs there and never upgrades it.
    """
    managed = find_managed_nim()
    if managed:
        return str(managed)
    return shutil.which("nim")


def nim_version(nim: str) -> str | None:
    try:
        out = subprocess.run([nim, "--version"], capture_output=True, text=True, timeout=30)
        return out.stdout.splitlines()[0] if out.returncode == 0 else None
    except Exception:
        return None

NIM_DEPS = {
    "zippy": "0.10.12",
    "puppy": "2.1.2",
    "parsetoml": "0.7.2",
    "nimcrypto": "0.7.3",
}

def nim_dep_specs() -> list:
    """`nimble install` arguments. `pkg@version` is nimble's exact-version syntax."""
    return [f"{pkg}@{ver}" for pkg, ver in NIM_DEPS.items()]

def ensure_nim_deps(nim: str) -> bool:
    """The launcher imports zippy + puppy; make sure nimble has them, at pinned versions."""
    nimble = str(Path(nim).with_name("nimble" + (".exe" if sys.platform == "win32" else "")))
    if not Path(nimble).exists():
        nimble = shutil.which("nimble") or "nimble"
    ok = True
    for spec in nim_dep_specs():                                    # INV-SUPPLY-02
        try:
            r = subprocess.run([nimble, "install", "-y", spec], capture_output=True, text=True, timeout=600)
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

def detect_c_toolchain(target) -> dict:
    """Is there a C compiler that can produce a binary for `target`? Returns {ok, compiler, advice}.

    Cross-compiling is the whole reason this project uses Nim, so a missing toolchain has to
    produce a sentence the operator can act on — the package name for their distro — rather
    than a link error from deep inside a Nim build.
    """
    from .targets import Target, TargetError
    try:
        tgt = target if hasattr(target, "os") else Target.parse(target)
    except TargetError as e:
        return {"ok": False, "compiler": None, "advice": str(e)}

    if tgt.is_host:
        for c in ("cc", "gcc", "clang"):
            p = shutil.which(c)
            if p:
                return {"ok": True, "compiler": p, "advice": ""}
        if sys.platform == "win32":
            return {"ok": False, "compiler": None,
                    "advice": "no C compiler found; run `choosenim` (bundles mingw) or install "
                              "MSVC Build Tools"}
        return {"ok": False, "compiler": None,
                "advice": "no C compiler found; install gcc/clang from your package manager"}

    cc, pkg = tgt.cross_cc()
    if cc is None:
        return {"ok": False, "compiler": None,
                "advice": f"haru-pack has no cross-compiler mapping for {tgt}. Build natively on "
                          f"a {tgt} machine, or add one to targets._CROSS_CC."}
    found = shutil.which(cc)
    if found:
        return {"ok": True, "compiler": found, "advice": ""}
    return {"ok": False, "compiler": None,
            "advice": (f"cross-compiling to {tgt} needs {cc}:\n"
                       f"    {_install_hint(pkg)}\n"
                       f"Alternatively, build natively on a {tgt} machine.")}


def _install_hint(pkg: str) -> str:
    """Best-effort package-manager line for this host. Wrong guesses are cheap; a bare
    package name with no command is not actionable."""
    info = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1); info[k] = v.strip().strip('"')
    except Exception:
        pass
    ident = (info.get("ID", "") + " " + info.get("ID_LIKE", "")).lower()
    if sys.platform == "darwin":
        return f"brew install {pkg}"
    if any(d in ident for d in ("debian", "ubuntu", "raspbian")):
        return f"sudo apt install {pkg}"
    if any(d in ident for d in ("fedora", "rhel", "centos")):
        return f"sudo dnf install {pkg}"
    if "arch" in ident:
        return f"sudo pacman -S {pkg}"
    if any(d in ident for d in ("suse", "opensuse")):
        return f"sudo zypper install {pkg}"
    return f"install '{pkg}' with your package manager"

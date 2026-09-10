"""Getting a Nim compiler, without making the user set one up first.

Goal: `pip install haru-pack && haru-pack bootstrap`, then pack projects. No system Nim, no
install guide, and **at most one sudo prompt** — for the C compiler, the only thing that has
to come from the system.

**choosenim is the only way haru-pack installs Nim.** It is the official toolchain manager,
it is what upstream recommends, and one path means one thing to test, document and debug.
There is deliberately no "download the prebuilt archive" path and no "build from source"
fallback: each would be a second and third way for this to behave differently on someone
else's machine, which is exactly the failure mode this project keeps finding in itself.

Nim goes into haru-pack's own data directory, with `CHOOSENIM_DIR` and `NIMBLE_DIR` pointed
there too. The system's Nim is ignored, and the user's `~/.nimble` is left alone: a
packaging tool should not quietly take over a global toolchain, and it should not behave
differently depending on what the host happens to have lying around.

## Build hosts vs targets — these are not the same list

choosenim publishes binaries for **linux x86_64, macOS x86_64, macOS arm64, and Windows
x86_64** (checked 2026-09-09). Those are the machines you can *build on*.

ARM Linux — a Raspberry Pi — is a **target**, not a build host. You do not need Nim on the
Pi at all: build on an x86_64 machine with `--target linux-aarch64`, which needs the
aarch64 cross-compiler and nothing else. That is one `apt install` on the build host, and it
is why dropping the source-build fallback costs nothing: the Pi never needed it.

If you genuinely must build ON an ARM Linux box, install Nim yourself (choosenim from
source, or your distro) and haru-pack will use it — but that is your toolchain to maintain,
not one haru-pack manages.

## What is verified, and what is delegated

haru-pack verifies the **choosenim binary** against a digest pinned in `pins.toml`
(INV-SUPPLY-01). It does **not** verify what choosenim then downloads — that is choosenim's
business, and using a toolchain manager means trusting it to manage the toolchain. Stated
here rather than left implied, because "we pin everything" would be an overclaim.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from . import pins
from .archives import fetch_verified
from .paths import toolchain_dir
from .targets import Target, host_arch, host_os

__all__ = ["ToolchainError", "NIM_VERSION", "CHOOSENIM_VERSION", "install_nim",
           "choosenim_asset", "find_managed_nim", "system_packages", "sudo_command",
           "SUPPORTED_BUILD_HOSTS"]

NIM_VERSION = "2.2.6"
CHOOSENIM_VERSION = "0.8.16"

# (os, arch) -> choosenim release asset. This table IS the list of supported build hosts.
_CHOOSENIM_ASSETS = {
    ("linux", "x86_64"):  f"choosenim-{CHOOSENIM_VERSION}_linux_amd64",
    ("macos", "x86_64"):  f"choosenim-{CHOOSENIM_VERSION}_macosx_amd64",
    ("macos", "aarch64"): f"choosenim-{CHOOSENIM_VERSION}_macosx_arm",
    ("windows", "x86_64"): f"choosenim-{CHOOSENIM_VERSION}_windows_amd64.exe",
}
SUPPORTED_BUILD_HOSTS = tuple(f"{o}-{a}" for (o, a) in sorted(_CHOOSENIM_ASSETS))


class ToolchainError(RuntimeError):
    """Could not obtain a Nim compiler."""


def choosenim_asset(os_: str | None = None, arch: str | None = None) -> str | None:
    """The choosenim release asset for a build host, or None if upstream ships none."""
    return _CHOOSENIM_ASSETS.get((os_ or host_os(), arch or host_arch()))


def find_managed_nim() -> Path | None:
    """The Nim haru-pack installed, if any. Never the system's."""
    exe = "nim.exe" if host_os() == "windows" else "nim"
    root = toolchain_dir() / "choosenim" / "toolchains"
    if root.is_dir():
        for d in sorted(root.iterdir(), reverse=True):     # newest version first
            c = d / "bin" / exe
            if c.exists():
                return c
    return None


# ---------------------------------------------------------------- system packages

def system_packages(targets=()) -> list:
    """OS packages still missing for these build targets. Empty means nothing to install.

    Only compilers belong here. Everything else haru-pack installs into its own directory
    without sudo.
    """
    need = []
    if not any(shutil.which(c) for c in ("cc", "gcc", "clang")):
        need.append({"linux": "build-essential", "macos": "gcc"}.get(host_os(), "gcc"))
    for t in targets:
        tgt = t if isinstance(t, Target) else Target.parse(t)
        cc, pkg = tgt.cross_cc()
        if cc and not shutil.which(cc):
            need.append(pkg)
    return sorted(set(need))


def _package_manager() -> tuple:
    if sys.platform == "darwin":
        return (["brew", "install"], "brew")
    info = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v.strip().strip('"')
    except OSError:
        pass
    ident = (info.get("ID", "") + " " + info.get("ID_LIKE", "")).lower()
    if any(d in ident for d in ("debian", "ubuntu", "raspbian")):
        return (["sudo", "apt", "install", "-y"], "apt")
    if any(d in ident for d in ("fedora", "rhel", "centos")):
        return (["sudo", "dnf", "install", "-y"], "dnf")
    if "arch" in ident:
        return (["sudo", "pacman", "-S", "--noconfirm"], "pacman")
    if any(d in ident for d in ("suse", "opensuse")):
        return (["sudo", "zypper", "install", "-y"], "zypper")
    return ([], "")


def sudo_command(packages) -> list:
    """The ONE command that installs everything missing. Empty if we cannot name one.

    Deliberately a single invocation: a setup guide listing six commands is a guide people
    skip; one line is a line they run.
    """
    prefix, _ = _package_manager()
    return (prefix + list(packages)) if (prefix and packages) else []


# ---------------------------------------------------------------- installation

def install_nim(force: bool = False, log=print) -> str:
    """Ensure haru-pack has a Nim compiler; return its path. choosenim, or nothing."""
    if not force:
        have = find_managed_nim()
        if have:
            return str(have)

    asset = choosenim_asset()
    if not asset:
        raise ToolchainError(
            f"choosenim publishes no binary for this machine ({host_os()}-{host_arch()}), so "
            f"haru-pack cannot install Nim here.\n"
            f"Supported build hosts: {', '.join(SUPPORTED_BUILD_HOSTS)}.\n\n"
            f"If you are trying to produce a binary FOR this machine, build it on a "
            f"supported host instead — e.g. on linux-x86_64:\n"
            f"    haru-pack build ./yourproject --target {host_os()}-{host_arch()}\n"
            f"Cross-compiling needs only the target's C cross-compiler on that host; "
            f"`haru-pack bootstrap --target {host_os()}-{host_arch()}` prints the one "
            f"command that installs it.")

    entry = pins.choosenim_digests().get(CHOOSENIM_VERSION, {}).get(asset)
    if not entry:
        raise ToolchainError(
            f"no pinned digest for {asset}; haru-pack will not download an unverified "
            f"toolchain installer. Add it with:\n"
            f"    python tools/add-pin.py choosenim {CHOOSENIM_VERSION}")

    home = toolchain_dir() / "choosenim"
    home.mkdir(parents=True, exist_ok=True)
    exe = home / ("choosenim.exe" if host_os() == "windows" else "choosenim")
    if force or not exe.exists():
        log(f"downloading {asset} …")
        fetch_verified(entry["url"], exe, entry["sha256"],
                       what=f"choosenim {CHOOSENIM_VERSION}")
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    env = dict(os.environ, CHOOSENIM_DIR=str(home), CHOOSENIM_NO_ANALYTICS="1",
               NIMBLE_DIR=str(home / "nimble"))
    log(f"choosenim: installing Nim {NIM_VERSION} (a minute or two, once) …")
    r = subprocess.run([str(exe), NIM_VERSION, "--yes", "--noColor"],
                       env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise ToolchainError("choosenim failed:\n" + (r.stderr or r.stdout)[-1200:])

    got = find_managed_nim()
    if not got:
        raise ToolchainError(
            f"choosenim reported success but no nim binary appeared under {home}. "
            f"Inspect that directory; nothing was installed system-wide.")
    log(f"Nim ready: {got}")
    return str(got)

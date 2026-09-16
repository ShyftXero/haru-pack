"""What machine are we building *for*? — os and architecture, in one place.

haru-pack used to say "target" and mean the OS: `host` or `windows`, with x86_64 assumed
everywhere. That assumption is baked into a binary a customer runs, and it is wrong in the
most ordinary case we have — a Raspberry Pi. The **default** tier bundles a `uv` binary, so
an unnoticed arch mismatch does not degrade gracefully: it ships an executable the target
cannot run at all, and the failure appears on the customer's machine.

A target is therefore always `(os, arch)`. Accepted spellings:

    host              this machine, both fields detected
    linux-aarch64     explicit; the Raspberry Pi case
    windows           legacy alias for windows-x86_64, kept so old commands keep working
    macos-aarch64     Apple silicon

The arch vocabulary is uv's and python-build-standalone's — `x86_64`, `aarch64`, `armv7` —
not Python's `platform.machine()`, which spells the same chips differently on different
systems (`arm64` on macOS, `aarch64` on Linux, `AMD64` on Windows). `normalize_arch` maps
into that vocabulary so there is exactly one spelling in the codebase.
"""
from __future__ import annotations

import platform
import sys
from dataclasses import dataclass

__all__ = ["Target", "TargetError", "normalize_arch", "host_os", "host_arch", "KNOWN_TARGETS"]

OSES = ("linux", "windows", "macos")
ARCHES = ("x86_64", "aarch64", "armv7")

# platform.machine() spellings -> our vocabulary. Keys are lowercased.
_ARCH_ALIASES = {
    "x86_64": "x86_64", "amd64": "x86_64", "x64": "x86_64",
    "aarch64": "aarch64", "arm64": "aarch64", "armv8": "aarch64", "armv8l": "aarch64",
    "armv7l": "armv7", "armv7": "armv7", "armv6l": "armv7", "arm": "armv7",
}

# uv release assets, per (os, arch). Names come from the uv release page; every one of
# these has a published `<asset>.sha256` sidecar pinned in bundle.UV_SHA256.
_UV_ASSETS = {
    ("linux", "x86_64"):    "uv-x86_64-unknown-linux-gnu.tar.gz",
    ("linux", "aarch64"):   "uv-aarch64-unknown-linux-gnu.tar.gz",
    ("linux", "armv7"):     "uv-armv7-unknown-linux-gnueabihf.tar.gz",
    ("macos", "x86_64"):    "uv-x86_64-apple-darwin.tar.gz",
    ("macos", "aarch64"):   "uv-aarch64-apple-darwin.tar.gz",
    ("windows", "x86_64"):  "uv-x86_64-pc-windows-msvc.zip",
    ("windows", "aarch64"): "uv-aarch64-pc-windows-msvc.zip",
}

# Nim's --cpu vocabulary.
_NIM_CPU = {"x86_64": "amd64", "aarch64": "arm64", "armv7": "arm"}

# The C compiler Nim needs to cross-compile there, and how to install it. Cross-compiling
# is the whole reason this project uses Nim, so a missing toolchain must produce an
# actionable sentence, not a compiler error.
_CROSS_CC = {
    ("linux", "aarch64"): ("aarch64-linux-gnu-gcc", "gcc-aarch64-linux-gnu"),
    ("linux", "armv7"):   ("arm-linux-gnueabihf-gcc", "gcc-arm-linux-gnueabihf"),
    ("windows", "x86_64"): ("x86_64-w64-mingw32-gcc", "mingw-w64"),
}

KNOWN_TARGETS = tuple(f"{o}-{a}" for (o, a) in sorted(_UV_ASSETS))


class TargetError(ValueError):
    """An unusable --target."""


def normalize_arch(machine: str) -> str:
    a = _ARCH_ALIASES.get((machine or "").strip().lower())
    if not a:
        raise TargetError(
            f"unsupported architecture {machine!r}. haru-pack knows: {', '.join(ARCHES)}.")
    return a


def host_os() -> str:
    if sys.platform == "win32": return "windows"
    if sys.platform == "darwin": return "macos"
    return "linux"


def host_arch() -> str:
    return normalize_arch(platform.machine())


@dataclass(frozen=True)
class Target:
    os: str
    arch: str

    # ---------------------------------------------------------------- construction
    @classmethod
    def parse(cls, spec: str) -> "Target":
        spec = (spec or "host").strip().lower()
        if spec == "host":
            return cls(host_os(), host_arch())
        # Legacy: bare OS names meant "that OS, x86_64". Kept so documented commands and
        # existing scripts keep working; new code should be explicit.
        if spec in OSES:
            return cls(spec, "x86_64")
        if spec == "win": spec = "windows"
        if "-" not in spec:
            raise TargetError(
                f"unknown target {spec!r}. Use 'host', or '<os>-<arch>' — one of: "
                f"{', '.join(KNOWN_TARGETS)}.")
        os_, _, arch = spec.partition("-")
        if os_ == "darwin": os_ = "macos"
        if os_ not in OSES:
            raise TargetError(f"unknown target OS {os_!r}; expected one of {', '.join(OSES)}.")
        t = cls(os_, normalize_arch(arch))
        if (t.os, t.arch) not in _UV_ASSETS:
            raise TargetError(
                f"no uv release for {t}; haru-pack cannot bundle a uv there. "
                f"Known targets: {', '.join(KNOWN_TARGETS)}.")
        return t

    def __str__(self) -> str:
        return f"{self.os}-{self.arch}"

    # ---------------------------------------------------------------- properties
    @property
    def is_host(self) -> bool:
        return self.os == host_os() and self.arch == host_arch()

    @property
    def exe_suffix(self) -> str:
        return ".exe" if self.os == "windows" else ""

    @property
    def uv_exe(self) -> str:
        return "uv.exe" if self.os == "windows" else "uv"

    @property
    def python_exe(self) -> str:
        return "python.exe" if self.os == "windows" else "python3"

    def uv_asset(self) -> str:
        try:
            return _UV_ASSETS[(self.os, self.arch)]
        except KeyError:
            raise TargetError(f"no uv release asset for {self}") from None

    # ---------------------------------------------------------------- nim
    def nim_flags(self) -> list:
        """Extra `nim c` flags to cross-compile for this target.

        Empty for a native build. Nim needs both --os/--cpu and an explicit cross C
        compiler; naming only the CPU makes it emit ARM code and then link it with the
        host gcc, which fails late and confusingly.
        """
        if self.is_host:
            return []
        flags = [f"--cpu:{_NIM_CPU[self.arch]}"]
        if self.os == "windows":
            flags += ["-d:mingw"]                 # nim's own mingw preset picks the cross gcc
        else:
            cc = _CROSS_CC.get((self.os, self.arch), (None, None))[0]
            flags += [f"--os:{'macosx' if self.os == 'macos' else self.os}"]
            if cc:
                flags += [f"--gcc.exe:{cc}", f"--gcc.linkerexe:{cc}"]
        return flags

    @property
    def nim_cpu(self) -> str:
        """Nim's name for this architecture — the `--cpu:` value."""
        return _NIM_CPU[self.arch]

    @property
    def nim_os(self) -> str:
        """Nim's name for this OS — the `--os:` value. Nim says `macosx`, not `macos`."""
        return {"macos": "macosx"}.get(self.os, self.os)

    def zig_triple(self) -> str:
        """This target as a `zig cc -target` triple.

        zig covers every target haru-pack builds for from one download, which is why it is
        the default compiler provider (docs/ZIG_TOOLCHAIN.md). macOS is the exception and is
        deliberately absent: zig's bundled macOS headers lack `fstore_t`, which Nim's posix
        module needs, so a Mac target still requires the real Apple SDK.
        """
        arch = {"x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64",
                "armv7": "arm"}.get(self.arch, self.arch)
        if self.os == "linux":
            return f"{arch}-linux-gnueabihf" if arch == "arm" else f"{arch}-linux-gnu"
        if self.os == "windows":
            return f"{arch}-windows-gnu"
        raise TargetError(
            f"zig cannot build for {self}: only linux and windows targets are supported by "
            f"the bundled compiler. Use `--cc system` with a real cross toolchain.")

    def zig_can_build(self) -> bool:
        try:
            self.zig_triple()
            return True
        except TargetError:
            return False

    def cross_cc(self) -> tuple:
        """(compiler-name, install-hint) for this target, or (None, None) if native."""
        if self.is_host:
            return (None, None)
        return _CROSS_CC.get((self.os, self.arch), (None, None))

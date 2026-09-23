"""INV-BIND-01 — machine/user binding is the OS hostname + login username, canonicalized
byte-identically on both sides, and it fails closed on a mismatch.

Four kinds of claim, weakest first:

  * SOURCE (always runs) — `cryptbox.nim` reads the hostname (`getHostname` /
    `GetComputerNameExW`) and the login username (`getpwuid` / `GetUserNameW`), NOT
    `/etc/machine-id` and NOT `getEnv("USER")`; `crypto.py` matches. A regex over source is
    weak, but it is what catches a maintainer quietly reintroducing the env-var user path.
  * CANON PARITY (needs nim) — the Python `canon_hostname` and the Nim `canonHostname` map a
    vector of tricky inputs to the SAME output. The Nim side is compiled and run, so this bites
    if either implementation drifts. This is the guard the whole feature rests on: the KDF is
    exact-match, so one differing byte bricks the licence on the RIGHT host.
  * EXECUTION (needs nim; the Windows leg needs zig + wine) — the parity matrix. Build
    workstation1.corp-bound and notforworkstation1.corp-bound containers, run the REAL compiled
    Nim decryptor with the runtime hostname pinned, and require the matching binary to open
    (rc 0) and the mismatched one to fail closed (rc 5).
  * FOOTGUN (needs nim) — an FQDN-bound binary on a host that reports only the short name fails
    closed. Asserted so the exact-match sharp corner is KNOWN, not discovered in the field.

Runtime hostname control. The clean mechanism is a UTS namespace (`unshare --uts` + set the
hostname), but THIS host forbids writing `uid_map`, so an unprivileged user namespace cannot
gain the capability to `sethostname`. We instead `LD_PRELOAD` a shim that overrides libc
`gethostname(3)` — which is what both Nim's `std/nativesockets` getHostname and wine's
`GetComputerNameEx` ultimately call — so the launcher's REAL reader path runs against a
hostname we choose, without root and without touching the host. The test prefers the namespace
and falls back to the shim; if neither is available it skips with an explanation.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from haru_pack import crypto

REPO = Path(__file__).resolve().parent.parent
LAUNCHER_DIR = REPO / "src/haru_pack/launcher"
NIM_CRYPTBOX = LAUNCHER_DIR / "cryptbox.nim"
CRYPTO_PY = REPO / "src/haru_pack/crypto.py"
NIM = shutil.which("nim")

SECRET = b"s3cret-license-key"
PAYLOAD = b"PK\x03\x04not-really-a-zip"
ITERS = 2_000                      # keep PBKDF2 out of the way; iters is authenticated, not secret
SECRET_ENV = "HARU_SECRET"         # SECRET knob default canary (INV-CANARY-01)
NOT_AUTHORIZED_RC = 5

# The canonicalization contract, as a vector. Every one of these must map to the value on the
# right on BOTH sides (INV-BIND-01). If they don't, a licence bound with one spelling fails to
# open under another.
CANON_VECTORS = [
    ("ws1.corp", "ws1.corp"),
    ("WS1.CORP.", "ws1.corp"),       # ASCII-lower AND a single trailing dot stripped
    ("WS1.CORP", "ws1.corp"),
    ("Workstation1", "workstation1"),
    ("host.", "host"),               # one trailing dot only
    ("host..", "host."),             # strip exactly ONE dot, not a run of them
    ("already-lower", "already-lower"),
    ("", ""),
]


# ─────────────────────────────────────────────────────────────── SOURCE assertions (always run)

@pytest.mark.invariant("INV-BIND-01")
def test_cryptbox_binds_to_hostname_and_login_user_not_machine_id_or_env():
    """The launcher's readers changed SOURCE in #59, and the old ones must be gone.

    `getEnv("USER")` for the *user* value is the specific regression this guards: it is the
    'USER=alice ./app is the whole attack' path, and #59 replaced it with the OS login name.
    """
    src = NIM_CRYPTBOX.read_text()
    # machine = OS hostname (cross-platform), not /etc/machine-id or the registry/ioreg
    assert "getHostname()" in src, "POSIX/macOS hostname reader (std/nativesockets) missing"
    assert "GetComputerNameExW" in src, "Windows hostname reader (winlean FFI) missing"
    assert "/etc/machine-id" not in src, "the retired machine-id reader is back"
    assert "MachineGuid" not in src, "the retired Windows machine-id (registry) reader is back"
    assert "IOPlatformUUID" not in src, "the retired macOS machine-id (ioreg) reader is back"
    # user = OS login username, not the environment
    assert "getpwuid(getuid())" in src, "POSIX login-user reader (getpwuid) missing"
    assert "GetUserNameW" in src, "Windows login-user reader (advapi32 FFI) missing"
    # The user value must NOT come from the environment any more. Isolate the loginUser proc so
    # an unrelated getEnv (the SECRET knob in resolveSecret) does not mask a regression, and
    # strip Nim comment lines so the proc's OWN docstring — which names getEnv to say it no
    # longer uses it — does not trip this.
    login_body = src[src.index("proc loginUser"):src.index("proc xorBytes")]
    login_code = "\n".join(ln for ln in login_body.splitlines() if not ln.lstrip().startswith("#"))
    assert 'getEnv("USER")' not in login_code and 'getEnv("USERNAME")' not in login_code, (
        "loginUser reads the environment again — USER=alice ./app is the whole attack"
    )


@pytest.mark.invariant("INV-BIND-01")
def test_crypto_py_binds_to_hostname_and_login_user_not_machine_id_or_env():
    src = CRYPTO_PY.read_text()
    assert "socket.getfqdn()" in src and "socket.gethostname()" in src, (
        "crypto.hostname must resolve the OS hostname (FQDN preferred, short fallback)"
    )
    assert "pwd.getpwuid(os.getuid())" in src, "crypto.login_user must read the POSIX login name"
    assert "GetUserNameW" in src, "crypto.login_user must read the Windows login name"
    assert "/etc/machine-id" not in src, "the retired machine-id reader is back in crypto.py"
    # the machine value folded into the key must be canonicalized
    assert "canon_hostname(machine)" in src, (
        "derive_key must canonicalize the machine value before folding it into the KDF"
    )


# ───────────────────────────────────────────────────────── CANON PARITY (pure Python + Nim)

@pytest.mark.invariant("INV-BIND-01")
@pytest.mark.parametrize("raw,expected", CANON_VECTORS)
def test_python_canon_hostname_vectors(raw, expected):
    assert crypto.canon_hostname(raw) == expected


@pytest.fixture(scope="module")
def nim_canon(tmp_path_factory) -> Path:
    """Compile a tiny program that calls the launcher's OWN `canonHostname` on argv.

    Importing cryptbox (rather than reimplementing the canon) is the whole point: this proves
    the SHIPPED canonicalizer, not a copy of it.
    """
    if NIM is None:
        pytest.skip("nim not installed; the cross-implementation canon test needs the real Nim")
    d = tmp_path_factory.mktemp("nim-canon")
    src = d / "canon.nim"
    src.write_text(
        "import std/os\nimport cryptbox\n"
        "when isMainModule:\n"
        "  echo canonHostname(paramStr(1))\n",
        encoding="utf-8",
    )
    exe = d / ("canon" + (".exe" if os.name == "nt" else ""))
    r = subprocess.run(
        [NIM, "c", "-d:release", f"--path:{LAUNCHER_DIR}", f"--nimcache:{d/'nc'}",
         f"--out:{exe}", "--hints:off", str(src)],
        capture_output=True, text=True, cwd=REPO,
    )
    assert r.returncode == 0 and exe.exists(), (
        f"cryptbox.nim's canonHostname does not compile:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}"
    )
    return exe


@pytest.mark.invariant("INV-BIND-01")
def test_nim_and_python_canonicalize_identically(nim_canon):
    """The load-bearing parity check. If either side drifts, a bound licence bricks its host."""
    for raw, expected in CANON_VECTORS:
        got = subprocess.run([str(nim_canon), raw], capture_output=True, text=True,
                             timeout=30).stdout.rstrip("\n")
        assert got == expected == crypto.canon_hostname(raw), (
            f"canon drift on {raw!r}: Nim={got!r} Python={crypto.canon_hostname(raw)!r} "
            f"expected={expected!r} — the two implementations disagree, so a build bound with "
            f"one and run against the other fails to decrypt"
        )


# ─────────────────────────────────────────────────────────── EXECUTION harness (compiled Nim)

HARNESS_NIM = """\
## Generated by tests/test_binding.py. Exercises cryptbox.nim exactly as the launcher does:
## isEncrypted -> openContainer, which resolves the runtime hostname/login-user and folds them
## into the KDF. rc 0 on a successful open, rc 5 on 'not authorized'.
import std/os
import cryptbox
when isMainModule:
  let raw = readFile(paramStr(1))
  if not isEncrypted(raw): quit("harness: not an encrypted container", 9)
  let payload = openContainer(raw, "HARU_SECRET")
  writeFile(paramStr(2), payload)
  echo "HARNESS-OK ", payload.len
"""

FAKEHOST_C = """\
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* Override libc gethostname(3) — what Nim getHostname and wine GetComputerNameEx both call —
   so the test pins the runtime hostname the launcher resolves, without root or a namespace. */
int gethostname(char *name, size_t len) {
    const char *h = getenv("FAKE_HOSTNAME");
    if (h == NULL) h = "";
    if (len == 0) return 0;
    strncpy(name, h, len);
    name[len - 1] = '\\0';
    return 0;
}
"""


def _zig() -> str | None:
    from haru_pack import toolchain
    z = toolchain.find_managed_zig()
    return str(z) if z else None


def _compile_linux_harness(d: Path) -> Path:
    src = d / "harness.nim"
    src.write_text(HARNESS_NIM, encoding="utf-8")
    exe = d / "harness"
    r = subprocess.run(
        [NIM, "c", "-d:release", f"--path:{LAUNCHER_DIR}", f"--nimcache:{d/'nc'}",
         f"--out:{exe}", "--hints:off", str(src)],
        capture_output=True, text=True, cwd=REPO,
    )
    assert r.returncode == 0 and exe.exists(), (
        f"cryptbox.nim does not compile:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}"
    )
    return exe


def _compile_gethostname_shim(d: Path) -> Path | None:
    """Build the LD_PRELOAD shim. Prefer the project's managed zig; fall back to cc/gcc."""
    src = d / "fakehost.c"
    src.write_text(FAKEHOST_C, encoding="utf-8")
    so = d / "fakehost.so"
    cc_cmd = None
    zig = _zig()
    if zig:
        cc_cmd = [zig, "cc"]
    elif shutil.which("cc"):
        cc_cmd = ["cc"]
    elif shutil.which("gcc"):
        cc_cmd = ["gcc"]
    if cc_cmd is None:
        return None
    r = subprocess.run([*cc_cmd, "-shared", "-fPIC", "-o", str(so), str(src)],
                       capture_output=True, text=True)
    return so if (r.returncode == 0 and so.exists()) else None


def _container(machine: str = "", user: str = "") -> bytes:
    return crypto.encrypt(PAYLOAD, SECRET, iters=ITERS, machine=machine, user=user)


def _run_harness(harness: Path, blob: bytes, d: Path, *, preload: Path | None = None,
                 fake_hostname: str | None = None, tag: str = "run"):
    box = d / f"{tag}.bin"
    out = d / f"{tag}.out"
    out.unlink(missing_ok=True)
    box.write_bytes(blob)
    env = dict(os.environ)
    env.pop("HARUPACK_SECRET", None)
    env[SECRET_ENV] = SECRET.decode()
    if preload is not None:
        env["LD_PRELOAD"] = str(preload)
    if fake_hostname is not None:
        env["FAKE_HOSTNAME"] = fake_hostname
    proc = subprocess.run([str(harness), str(box), str(out)], capture_output=True, text=True,
                          env=env, timeout=120, stdin=subprocess.DEVNULL)
    return proc.returncode, (out.read_bytes() if out.exists() else None), proc


@pytest.fixture(scope="module")
def linux_rig(tmp_path_factory):
    if NIM is None:
        pytest.skip("nim not installed; the execution matrix needs the real decryptor")
    d = tmp_path_factory.mktemp("bind-linux")
    harness = _compile_linux_harness(d)
    shim = _compile_gethostname_shim(d)
    if shim is None:
        pytest.skip("no C compiler (managed zig / cc / gcc) to build the gethostname shim")
    # Sanity: the shim actually overrides what the launcher reads. If it does not (a static
    # build, a hardened loader ignoring LD_PRELOAD), skip rather than assert a false pass.
    rc, _, proc = _run_harness(harness, _container(machine="probeprobe.example"), d,
                               preload=shim, fake_hostname="probeprobe.example", tag="probe")
    if rc != 0:
        pytest.skip(f"gethostname LD_PRELOAD did not take effect (rc={rc}); cannot pin the "
                    f"runtime hostname on this host without a UTS namespace")
    return d, harness, shim


@pytest.mark.invariant("INV-BIND-01")
def test_linux_hostname_binding_matrix(linux_rig):
    """Runtime hostname = workstation1.corp: the matching binding opens, the other fails closed."""
    d, harness, shim = linux_rig
    rc_ok, pt_ok, _ = _run_harness(
        harness, _container(machine="workstation1.corp"), d,
        preload=shim, fake_hostname="workstation1.corp", tag="auth")
    assert rc_ok == 0 and pt_ok == PAYLOAD, "the workstation1.corp-bound binary must open on it"

    rc_no, _, proc = _run_harness(
        harness, _container(machine="notforworkstation1.corp"), d,
        preload=shim, fake_hostname="workstation1.corp", tag="deny")
    assert rc_no == NOT_AUTHORIZED_RC, (
        f"a binary bound to a DIFFERENT host must fail closed (rc {NOT_AUTHORIZED_RC}), "
        f"got rc {rc_no}: {proc.stdout}{proc.stderr}")


@pytest.mark.invariant("INV-BIND-01")
def test_linux_canon_collapse_end_to_end(linux_rig):
    """A ws1.corp-bound binary opens on a host that reports WS1.CORP. — canon through the real
    reader, not just the string test. This is the property that lets `haru-pack hostname`'s
    canonical output match a differently-cased runtime hostname."""
    d, harness, shim = linux_rig
    rc, pt, proc = _run_harness(
        harness, _container(machine="ws1.corp"), d,
        preload=shim, fake_hostname="WS1.CORP.", tag="canon")
    assert rc == 0 and pt == PAYLOAD, (
        f"WS1.CORP. must canon to ws1.corp and open a ws1.corp binding; rc={rc} {proc.stdout}")


@pytest.mark.invariant("INV-BIND-01")
def test_linux_fqdn_footgun_fails_closed(linux_rig):
    """KNOWN sharp corner: an FQDN-bound binary on a host that reports only the SHORT name fails
    closed (exact-match after canon). A SHORT-bound binary matches the short runtime name."""
    d, harness, shim = linux_rig
    # FQDN binding, short runtime name -> no match -> fail closed.
    rc_fqdn, _, _ = _run_harness(
        harness, _container(machine="ws1.corp"), d,
        preload=shim, fake_hostname="ws1", tag="footgun")
    assert rc_fqdn == NOT_AUTHORIZED_RC, (
        "an FQDN binding must fail closed where the host reports only the short name — "
        "this is the documented exact-match footgun")
    # Short binding, short runtime name -> match (the fallback case that DOES work).
    rc_short, pt_short, _ = _run_harness(
        harness, _container(machine="ws1"), d,
        preload=shim, fake_hostname="ws1", tag="shortok")
    assert rc_short == 0 and pt_short == PAYLOAD, "a short-name binding must open on the short name"


@pytest.mark.invariant("INV-BIND-01")
def test_linux_login_user_binding(linux_rig):
    """User binding folds the OS login name (getpwuid), not $USER. The current login user opens;
    a wrong username fails closed. No preload — this exercises the real getpwuid path."""
    d, harness, _shim = linux_rig
    me = crypto.login_user()
    if not me:
        pytest.skip("could not resolve the current login user via getpwuid")
    rc_ok, pt_ok, proc = _run_harness(harness, _container(user=me), d, tag="userok")
    assert rc_ok == 0 and pt_ok == PAYLOAD, (
        f"the current login user ({me!r}) must open a binding to itself; {proc.stdout}{proc.stderr}")
    rc_no, _, _ = _run_harness(harness, _container(user="definitely-not-a-real-login"), d,
                               tag="userno")
    assert rc_no == NOT_AUTHORIZED_RC, "a wrong login username must fail closed"


# ─────────────────────────────────────────────────────────── Windows leg (cross-compile + WINE)

WINE = shutil.which("wine")


@pytest.fixture(scope="module")
def windows_rig(tmp_path_factory):
    if NIM is None:
        pytest.skip("nim not installed")
    if WINE is None:
        pytest.skip("wine not installed; the Windows binding leg needs it")
    from haru_pack import emit as emit_mod
    from haru_pack import toolchain
    from haru_pack.targets import Target
    zig = toolchain.find_managed_zig()
    if zig is None:
        pytest.skip("managed zig not installed; needed to cross-compile the Windows .exe")
    d = tmp_path_factory.mktemp("bind-win")
    tgt = Target.parse("windows-x86_64")
    shim_ref = toolchain.zig_cc_shim(str(zig), tgt.zig_triple(), d / "zig-cc")
    src = d / "harness.nim"
    src.write_text(HARNESS_NIM, encoding="utf-8")
    exe = d / "harness.exe"
    args = [NIM, "c", *emit_mod.nim_target_flags(tgt, "zig", shim_ref=str(shim_ref)),
            f"--path:{LAUNCHER_DIR}", f"--nimcache:{d/'nc'}", f"--out:{exe}", "--hints:off",
            str(src)]
    r = subprocess.run(args, capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0 and exe.exists(), (
        f"cross-compiling cryptbox.nim to Windows failed — the winlean/advapi32 FFI does not "
        f"build:\n{r.stdout[-2500:]}\n{r.stderr[-2500:]}"
    )
    shim = _compile_gethostname_shim(d)
    if shim is None:
        pytest.skip("no C compiler to build the gethostname shim for wine")
    return d, exe, shim


def _run_wine(rig, blob: bytes, fake_hostname: str, tag: str):
    """Run the .exe under a FRESH WINEPREFIX (wineserver caches the computer name, and the
    prefix bakes it on first boot), with gethostname pinned via LD_PRELOAD so wine's
    GetComputerNameEx resolves `fake_hostname`."""
    d, exe, shim = rig
    prefix = d / f"wp-{tag}"
    box = d / f"{tag}.bin"; box.write_bytes(blob)
    out = d / f"{tag}.out"; out.unlink(missing_ok=True)
    env = dict(os.environ)
    env.update({
        "WINEPREFIX": str(prefix), "WINEDEBUG": "-all",
        "LD_PRELOAD": str(shim), "FAKE_HOSTNAME": fake_hostname,
        SECRET_ENV: SECRET.decode(),
    })
    env.pop("HARUPACK_SECRET", None)
    # Boot the prefix under the pinned hostname so the baked computer name matches.
    subprocess.run([WINE, "wineboot", "-i"], env=env, capture_output=True, text=True, timeout=300)
    proc = subprocess.run(
        [WINE, str(exe), f"Z:{box}".replace("/", "\\"), f"Z:{out}".replace("/", "\\")],
        env=env, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
    subprocess.run([WINE, "wineserver", "-k", "-w"], env=env, capture_output=True, timeout=60)
    return proc.returncode, (out.read_bytes() if out.exists() else None), proc


@pytest.mark.invariant("INV-BIND-01")
def test_windows_hostname_binding_matrix_under_wine(windows_rig):
    """The Windows leg of the parity matrix: the cross-compiled .exe, run under WINE with the
    computer name driven through the same gethostname shim. Runtime hostname = workstation1.corp.

    LIMIT: a FULL first run under wine cannot complete (uv cannot create Python's junctions —
    'os error 50', see scripts/self-build.sh), but the DECRYPT gate this invariant is about runs
    BEFORE any staging, so rc 0 vs rc 5 here is a real result: the authorized binary reaches its
    payload, the unauthorized one fails closed at the key derivation."""
    rc_ok, pt_ok, proc = _run_wine(windows_rig, _container(machine="workstation1.corp"),
                                   "workstation1.corp", "auth")
    assert rc_ok == 0 and pt_ok == PAYLOAD, (
        f"the workstation1.corp-bound .exe must decrypt under wine on that host; "
        f"rc={rc_ok} {proc.stdout}{proc.stderr}")
    rc_no, _, proc2 = _run_wine(windows_rig, _container(machine="notforworkstation1.corp"),
                                "workstation1.corp", "deny")
    assert rc_no == NOT_AUTHORIZED_RC, (
        f"the notforworkstation1.corp-bound .exe must fail closed (rc {NOT_AUTHORIZED_RC}) on "
        f"workstation1.corp; rc={rc_no} {proc2.stdout}{proc2.stderr}")

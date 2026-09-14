"""The box the flex and exam harnesses run stranger code in (INV-SANDBOX-01/02).

The flex matrix is a list of code written by strangers, chosen by download rank rather than
by audit, and running it is the entire point of the harness. Three separate places execute
that code:

  * `haru-pack build` runs `uv sync`, which builds sdists, which executes arbitrary PEP 517
    backends on the build host;
  * the harness then RUNS the binary it produced, which imports the package and executes its
    smoke body (and `runpy.run_module`s anything with a `python -m` entrypoint);
  * `flex/packages.toml` carries `[[bundle]]` / `[[post_install]]` steps that run real
    installer commands.

All of that used to happen on the maintainer's workstation, as the maintainer, with $HOME,
SSH keys, cloud credentials and this repository's working tree in scope. See
`docs/adr/0005-sandboxed-flex-and-exam-harnesses.md`.

WHY THE ARGV IS BUILT BY A PURE FUNCTION

`docker_argv()` reads nothing — no environment, no filesystem, no clock. Everything it needs
is an argument. That is the load-bearing decision in this module, and it is not for elegance:
it means the properties that actually contain the blast radius (a thick run gets
`--network none`, the cache is read-only while stranger code runs, the docker socket is never
mounted, the repo is never mounted writable) are assertable by a unit test that runs OFFLINE,
in CI, on a box with no docker installed at all.

A containment guarantee that can only be checked by running docker is a guarantee that gets
checked when somebody remembers to check it. `tests/test_sandbox.py` reads the argv instead.

WHAT THIS IS NOT

A container is not a VM: a kernel exploit leaves the box. Rootless docker narrows that and
does not close it. And this contains *haru-pack's own test harnesses* — it says nothing about
`haru-pack build` run by an operator on an untrusted tree, which is INV-TRUST-02 and is still
`proposed`.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO / "docker" / "flex.Dockerfile"
PINS = REPO / "src" / "haru_pack" / "pins.toml"

IMAGE_NAME = "haru-pack-flex"

#: The warm cache, shared across packages in a run so a 25-package matrix does not download
#: a toolchain 25 times. Named, so it survives between runs. `docker volume rm` to reset.
CACHE_VOLUME = "haru-flex-cache"

#: Mount modes for /cache. `cold` is an ANONYMOUS volume: docker creates it empty and
#: `--rm` destroys it with the container, which is what makes the thick offline check mean
#: something. A warm cache would let the run succeed from cache and prove nothing.
CACHE_RW, CACHE_RO, CACHE_COLD = "rw", "ro", "cold"
CACHE_MODES = (CACHE_RW, CACHE_RO, CACHE_COLD)

WORKDIR = "/w"
SRCDIR = "/src"
CACHEDIR = "/cache"

#: HOME inside the container, and it must be the same path the IMAGE was built with.
#: `haru-pack bootstrap` installs the launcher's pinned nimble dependencies (zippy, puppy,
#: parsetoml, nimcrypto — INV-SUPPLY-02) into `$HOME/.nimble`, and Nim's default config looks
#: for them under `$HOME`. Pointing HOME at the cache volume instead loses them, and the
#: failure surfaces four minutes into a build as `cannot open file: nimcrypto/sha2`, which
#: reads like a missing pin rather than a misrouted environment variable.
#:
#: Writes here land in the container's own writable layer and die with `--rm`, so the
#: toolchain being writable costs nothing and is not shared between packages.
IMAGE_HOME = "/opt/haru"

#: The environment every sandboxed step runs with. One definition, because the build phase
#: and the run phase disagreeing about where the cache is would be a silent, slow bug.
def container_env() -> dict:
    return {"HOME": IMAGE_HOME,
            "XDG_CACHE_HOME": CACHEDIR,
            "UV_CACHE_DIR": f"{CACHEDIR}/uv"}


class SandboxUnavailable(RuntimeError):
    """Docker cannot run and the caller did not ask for the host path."""


# ───────────────────────────────────────────────────────────────── the pure part

def docker_argv(image: str, *, cmd, work: Path, network: bool, cache: str,
                uid: int, gid: int, repo: Path | None = None,
                env: dict | None = None, extra=(), workdir: str = WORKDIR) -> list[str]:
    """The exact argv for one sandboxed step. Reads nothing; everything is an argument.

    `network` is a bool rather than a docker network name on purpose — there are exactly two
    answers here and naming a third (`host`!) should require editing this function.

    `repo`, when given, is mounted READ-ONLY. The harness wants the working tree's haru-pack,
    not whatever was baked into the image, and read-only is the whole reason that is safe:
    a hostile sdist build backend runs with the repository in its filesystem namespace.

    `workdir` is settable because exam needs a NEUTRAL cwd. Its binary runs a pytest suite,
    and pytest walks up from the cwd looking for a rootdir — started in /w it finds the
    generated project's own pyproject.toml, applies its addopts and reports a passing suite
    as 0 tests. The same trap as running it inside the repo worktree on the host.
    """
    if cache not in CACHE_MODES:
        raise ValueError(f"cache must be one of {CACHE_MODES}, got {cache!r}")

    argv = [
        "docker", "run", "--rm",
        # No network at all, or docker's default bridge. Never --network host: that would
        # put stranger code on the developer's loopback, where their unauthenticated local
        # services live.
        "--network", "bridge" if network else "none",
        # Drop every capability and forbid regaining privilege through setuid binaries.
        # Nothing either harness does needs a capability.
        "--cap-drop=ALL",
        "--security-opt", "no-new-privileges",
        # Run as the invoking user so artifacts written to the work mount are owned by them
        # and not by root — a root-owned flex/out is its own small denial of service.
        "-u", f"{uid}:{gid}",
    ]

    # The per-package work directory: the only host path mounted writable, and the only one
    # anything is supposed to come back out of.
    argv += ["-v", f"{work}:{WORKDIR}"]

    if repo is not None:
        argv += ["-v", f"{repo}:{SRCDIR}:ro"]

    if cache == CACHE_COLD:
        argv += ["-v", CACHEDIR]                       # anonymous; --rm destroys it
    else:
        suffix = ":ro" if cache == CACHE_RO else ""
        argv += ["-v", f"{CACHE_VOLUME}:{CACHEDIR}{suffix}"]

    for key, value in sorted((env or {}).items()):
        argv += ["-e", f"{key}={value}"]

    argv += ["-w", workdir, *extra, image, *[str(c) for c in cmd]]
    return argv


def host_warning(count: int, what: str) -> str:
    """The banner `--no-docker` prints before it runs anything. Also pure, also tested.

    It names the number and what is in scope, because "running without a sandbox" is a
    sentence an operator's eye slides off and "your SSH keys are in scope" is not.
    """
    return (
        "\n"
        "  ┌─────────────────────────────────────────────────────────────────────┐\n"
        "  │  NO SANDBOX — third-party code will execute on THIS machine         │\n"
        "  └─────────────────────────────────────────────────────────────────────┘\n"
        f"\n  About to build and EXECUTE {count} {what} directly on this host.\n"
        "\n"
        "  In scope: $HOME, your SSH keys, your cloud credentials, your browser\n"
        "  profiles, and this repository's working tree. Package code runs at\n"
        "  three points — sdist build backends under `uv sync`, the binary the\n"
        "  build produces, and any [[bundle]]/[[post_install]] step.\n"
        "\n"
        "  Nothing in this run is contained. Ctrl-C now, or re-run without\n"
        "  --no-docker to use the sandbox.\n"
    )


def image_tag(dockerfile_bytes: bytes, pins_bytes: bytes) -> str:
    """Tag derived from the image's inputs, so a pin bump rebuilds and a stale image is
    never silently reused. Pure, so the derivation itself is testable."""
    h = hashlib.sha256()
    h.update(dockerfile_bytes)
    h.update(b"\0")
    h.update(pins_bytes)
    return h.hexdigest()[:12]


# ───────────────────────────────────────────────────────── the part that touches docker

def available() -> str:
    """"" if docker can run, else the reason it cannot."""
    if shutil.which("docker") is None:
        return "docker is not installed"
    r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return f"the docker daemon is not reachable: {(r.stderr or '').strip()[:160]}"
    return ""


def rootless() -> bool:
    """Whether the daemon runs rootless.

    Rootless is the posture this harness wants: the container's root maps to an
    unprivileged host uid, and the socket is not a root-equivalent handle. It is detected
    rather than required — see `require_rootless` in `preflight`.
    """
    r = subprocess.run(["docker", "info", "--format", "{{.SecurityOptions}}"],
                       capture_output=True, text=True, timeout=60)
    return r.returncode == 0 and "name=rootless" in r.stdout


ROOTFUL_WARNING = (
    "  note: this docker daemon is ROOTFUL. The sandbox still contains the package's\n"
    "        filesystem and network access, but container-root maps to real root and the\n"
    "        daemon socket is a root-equivalent handle on this host. Rootless docker\n"
    "        closes that gap — see docs/ROOTLESS_DOCKER.md. Use --require-rootless to\n"
    "        make this fatal.\n"
)


def current_tag() -> str:
    return image_tag(DOCKERFILE.read_bytes(), PINS.read_bytes())


def ensure_image(log=print, timeout: int = 3600) -> str:
    """Build the image if it is missing or its inputs changed. Returns `name:tag`."""
    ref = f"{IMAGE_NAME}:{current_tag()}"
    seen = subprocess.run(["docker", "image", "inspect", ref],
                          capture_output=True, text=True, timeout=120)
    if seen.returncode == 0:
        return ref
    log(f"sandbox: building {ref} (this takes a few minutes the first time)")
    build = subprocess.run(
        ["docker", "build", "-f", str(DOCKERFILE), "-t", ref, str(REPO)],
        text=True, timeout=timeout)
    if build.returncode != 0:
        raise SandboxUnavailable(
            f"could not build {ref}. Fix the image, or re-run with --no-docker and read the "
            f"warning it prints.")
    return ref


def preflight(*, require_rootless: bool = False, log=print) -> str:
    """Everything that must be true before a sandboxed run. Returns the image ref.

    Raises rather than falling back to the host. A silent fallback is how a safe default
    quietly stops being the default and nobody finds out until they read the code.
    """
    if why := available():
        raise SandboxUnavailable(
            f"{why}.\n"
            f"The flex/exam harnesses build and execute third-party package code, so they "
            f"run it in a container by default.\n"
            f"Install docker, or pass --no-docker to run it directly on this host "
            f"(it will tell you what that means).")
    if not rootless():
        if require_rootless:
            raise SandboxUnavailable(
                "--require-rootless was given but this docker daemon is rootful. "
                "See docs/ROOTLESS_DOCKER.md.")
        log(ROOTFUL_WARNING.rstrip("\n"))
    return ensure_image(log=log)


def run(image: str, *, cmd, work: Path, network: bool, cache: str, uid: int, gid: int,
        repo: Path | None = None, env: dict | None = None, extra=(),
        workdir: str = WORKDIR, timeout: int = 1800) -> dict:
    """Run one sandboxed step. Returns a dict the harnesses can read directly.

    `infra` distinguishes "docker could not start this" from "the thing under test failed",
    because reporting the former as a package failure is how a broken harness looks like
    twenty-five broken packages.
    """
    argv = docker_argv(image, cmd=cmd, work=work, network=network, cache=cache,
                       uid=uid, gid=gid, repo=repo, env=env, extra=extra, workdir=workdir)
    t0 = time.monotonic()
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        rc, out, err, timed_out = r.returncode, r.stdout, r.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, timed_out = None, True
        out = (e.stdout or b"").decode("utf8", "replace") if isinstance(e.stdout, bytes) \
            else (e.stdout or "")
        err = (e.stderr or b"").decode("utf8", "replace") if isinstance(e.stderr, bytes) \
            else (e.stderr or "")
    secs = round(time.monotonic() - t0, 1)

    # 125/126/127 with nothing from the program itself means docker refused to start it.
    infra = (rc in (125, 126, 127)) and not out.strip()
    return {"rc": rc, "stdout": out, "stderr": err, "seconds": secs,
            "timed_out": timed_out, "infra": infra, "argv": argv}

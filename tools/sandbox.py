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
it means the properties that actually contain the blast radius are assertable by a unit test
that runs OFFLINE, in CI, on a box with no docker installed at all. Asked for a run with no
network, the argv says `--network none` — no interface at all, not a blocked one — and no
argument can reach `--network host`, because the one caller-supplied passthrough (`extra=`) is
checked against an allowlist before it is spliced in. The RUN phase gets a THROWAWAY anonymous
cache volume,
so stranger code never sees the shared cache in either direction; that is stronger than
mounting it read-only, and read-only is not on offer anyway — see `CACHE_MODES` below for the
run that died of it. The docker socket is never mounted, for any arguments — no argument can
express a bind mount this function did not choose. The repository is mounted `:ro` or not at
all, and the per-package work directory is the only writable host path.

A containment guarantee that can only be checked by running docker is a guarantee that gets
checked when somebody remembers to check it. `tests/test_sandbox.py` reads the argv instead.

WHAT THAT DOES NOT COVER

Those tests read THIS function's output for a mode they pass in themselves. They do not read
the call sites that CHOOSE the mode: `network=not offline` and `cache=CACHE_COLD` in
`tools/flex-run.py`, and the same pair in `tools/exam.py`, are ordinary code no test asserts.
Change `not offline` to `True` and every test here stays green while `results.json` keeps
printing `carried`. What is proved is that `docker_argv` is faithful to the mode it is handed,
not that a harness ever hands it the offline one — which is why the Statements of
INV-SANDBOX-01 and INV-SANDBOX-02 were narrowed to the argv on 2026-09-15. The one
harness-level check that does exist is an AST one: that no harness executes a built artifact
outside `HostRunner`.

WHAT THIS IS NOT

A container is not a VM: a kernel exploit leaves the box. Rootless docker narrows that and
does not close it. And this contains *haru-pack's own test harnesses* — it says nothing about
`haru-pack build` run by an operator on an untrusted tree, which is INV-TRUST-02 and is still
`proposed`.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

#: CSI escape sequences, for stripping colour out of another tool's stdout before parsing it.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

REPO = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO / "docker" / "flex.Dockerfile"
PINS = REPO / "src" / "haru_pack" / "pins.toml"

IMAGE_NAME = "haru-pack-flex"

#: The warm cache, shared across packages in a run so a 25-package matrix does not download
#: a toolchain 25 times. Named, so it survives between runs. `docker volume rm` to reset.
CACHE_VOLUME = "haru-flex-cache"

#: Mount modes for /cache. Exactly two, and which phase gets which is the security decision:
#:
#:   `rw`    the shared named volume, writable. The BUILD phase only — it is what stops a
#:           25-package matrix downloading a toolchain 25 times.
#:   `cold`  an ANONYMOUS volume: docker creates it empty and `--rm` destroys it with the
#:           container. The RUN phase always. Stranger code therefore never sees the shared
#:           cache at all, in either direction, and every run starts pristine — which is
#:           also what makes the thick offline check mean something, since a warm cache
#:           would let the run succeed from cache and prove nothing about the payload.
#:
#: There is deliberately no read-only mode. The first draft of this gave the run phase the
#: shared volume mounted `:ro`, which is unimplementable: a thick binary STAGES into
#: $XDG_CACHE_HOME before it can execute, so it died with
#: `OSError: Read-only file system /cache/haru-pack/<hash>.tmp-1`. Not mounting the shared
#: cache is the stronger answer anyway — `:ro` still let a package read it.
CACHE_RW, CACHE_COLD = "rw", "cold"
CACHE_MODES = (CACHE_RW, CACHE_COLD)

WORKDIR = "/w"
SRCDIR = "/src"
CACHEDIR = "/cache"

#: HOME inside the container, and it must be the same path the IMAGE was built with.
#: `haru-pack bootstrap` installs the launcher's nimble dependencies (zippy, puppy, parsetoml,
#: nimcrypto) into `$HOME/.nimble`, each requested at an exact version — that is INV-SUPPLY-09,
#: which is about what gets INSTALLED. Not INV-SUPPLY-02: that one is about which version the
#: compiler ends up LINKING, it is still `proposed`, and `nim c` here resolves each import to
#: the highest version present regardless of what was installed. Nim's default config looks for
#: these under `$HOME`. Pointing HOME at the cache volume instead loses them, and the
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

#: What `extra=` may carry. An ALLOWLIST, and that choice is the fix for a real hole rather
#: than a matter of taste: `extra` is spliced in AFTER every containment flag below, and docker
#: resolves a repeated single-value flag LAST-WINS. So `extra=("--network", "host")` beat
#: `--network none`, `("-u", "0:0")` beat the uid drop, and `("--privileged",)` or
#: `("-v", "/var/run/docker.sock:/var/run/docker.sock")` were simply accepted — while the
#: module docstring promised the opposite "for any arguments". Nothing in-tree passes `extra`
#: yet, and `test_there_is_no_way_to_ask_for_the_host_network` reads only the string literals
#: inside `docker_argv`, so nothing was broken and nothing was red. The sentence was just false.
#:
#: Why an allowlist and not a denylist of the dangerous flags: a denylist is true only while it
#: is COMPLETE. It would have to name every flag docker has — or later adds — that can pierce
#: containment (`--privileged`, `--network`/`--net`, `-u`/`--user`, `--cap-add`,
#: `--security-opt`, `--pid`, `--ipc`, `--uts`, `--userns`, `--cgroupns`, `--device`,
#: `--sysctl`, `--volumes-from`, `--runtime`, `-v`/`--volume`/`--mount`), and it stops being
#: true on a docker release, silently. An allowlist is true by default: an unfamiliar flag is
#: refused, and widening it is a deliberate edit to this dict rather than something a caller
#: can do from outside the module.
#:
#: The value is whether the flag takes one. What is here is what the harnesses actually ask
#: for — busybody's resource lids — and none of it can override a decision made below:
#: `--read-only` only tightens, `--tmpfs` names a path INSIDE the container and cannot reach a
#: host path, and the rest are ceilings on cpu, memory and pids.
_EXTRA_FLAGS = {
    "--read-only": False,
    "--init": False,
    "--tmpfs": True,
    "-m": True, "--memory": True, "--memory-swap": True, "--memory-swappiness": True,
    "--cpus": True, "--cpu-shares": True, "--pids-limit": True, "--ulimit": True,
}


def _check_extra(extra) -> list:
    """`extra` validated token by token, as strings, or ValueError naming the token and why.

    Returns the strings it checked, so the caller splices THOSE rather than the original
    sequence: a `str()` at splice time on an object whose `__str__` is not stable would check
    one string and run another.
    """
    tokens = [str(t) for t in extra]
    i = 0
    while i < len(tokens):
        token = tokens[i]
        flag, inline, _ = token.partition("=")      # `-m=512m` is the same flag as `-m 512m`
        if flag not in _EXTRA_FLAGS:
            raise ValueError(
                f"extra={token!r} is not an allowed sandbox flag.\n"
                f"  `extra` is spliced in after the containment flags and docker takes the "
                f"LAST value of a repeated flag, so a token here can undo one of them: "
                f"`--network host` would beat `--network none` and `-u 0:0` the uid drop. "
                f"`--privileged`, `--cap-add`, `--security-opt`, `--pid`/`--ipc`/`--userns` "
                f"and any `-v`/`--volume`/`--mount` (the docker socket included) are not "
                f"expressible here at all.\n"
                f"  This is an allowlist, so a flag that is merely unfamiliar is refused too. "
                f"Allowed: {', '.join(sorted(_EXTRA_FLAGS))}.\n"
                f"  If a harness genuinely needs another one, add it to `_EXTRA_FLAGS` in "
                f"tools/sandbox.py and say there why it cannot loosen containment.")
        if inline and not _EXTRA_FLAGS[flag]:
            raise ValueError(f"extra={token!r}: {flag} takes no value")
        if _EXTRA_FLAGS[flag] and not inline:
            if i + 1 >= len(tokens):
                raise ValueError(f"extra={token!r}: {flag} needs a value and is the last token")
            i += 2      # the next token IS that value, and is never re-read as a flag
        else:
            i += 1
    return tokens


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

    `extra` is the caller's passthrough for resource lids — busybody passes `--read-only`,
    `-m 512m`, `--tmpfs` — and is checked against `_EXTRA_FLAGS` before anything is spliced.
    It lands LAST, after every containment flag, and docker takes the last value of a repeated
    flag; unchecked, it was a way for a caller to undo all of them. See `_EXTRA_FLAGS`.
    """
    if cache not in CACHE_MODES:
        raise ValueError(f"cache must be one of {CACHE_MODES}, got {cache!r}")
    # `image` is positional, so an image string beginning with `-` would be parsed by docker as
    # a FLAG, with the first word of `cmd` promoted to the image name. That is the only other
    # route from an argument of this function to a containment flag, and it costs one line.
    if str(image).startswith("-"):
        raise ValueError(f"image={image!r} starts with '-'; docker would read it as a flag")
    checked_extra = _check_extra(extra)

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
        argv += ["-v", f"{CACHE_VOLUME}:{CACHEDIR}"]

    for key, value in sorted((env or {}).items()):
        argv += ["-e", f"{key}={value}"]

    argv += ["-w", workdir, *checked_extra, image, *[str(c) for c in cmd]]
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


def image_tag(dockerfile_bytes: bytes, pins_bytes: bytes, *other_inputs: bytes) -> str:
    """Tag derived from the image's inputs, so a change to one of them rebuilds and a stale
    image is never silently reused. Pure, so the derivation itself is testable.

    WHICH INPUTS, AND THE ONE THAT IS DELIBERATELY LEFT OUT

    `current_tag` feeds this the Dockerfile, `pins.toml`, `pyproject.toml` and every script in
    `docker/` — the files that decide what gets BAKED: the toolchain, and the venv the harness
    imports from. Until 2026-09-15 it hashed only the first two, so editing `docker/
    install-nim-source.py` or adding a dependency changed what the image would contain and the
    tag did not move; the stale image was reused and the edit appeared to do nothing.

    It does NOT hash `src/` or `README.md`, which `flex.Dockerfile` also `COPY`s, and that is a
    decision rather than an oversight. The baked copy of the source is overwritten at run time
    by the read-only `/src` mount and `PYTHONPATH` — testing the WORKING TREE is the whole
    point — so a source edit changes nothing the run reads, while retagging on it would force a
    multi-minute toolchain rebuild on every edit. The residue is narrow and worth naming: add a
    runtime dependency and the tag DOES move (`pyproject.toml` is hashed, and the venv really is
    stale), but a `src/` edit alone reuses the image, correctly.

    Not hashed either: the `NIM_FROM` build arg. `ensure_image` never passes `--build-arg`, so
    in this tool it is always `auto` — but an image built by hand with `NIM_FROM=source` carries
    the same tag as one built with `binary`.
    """
    return hashlib.sha256(
        b"\0".join((dockerfile_bytes, pins_bytes, *other_inputs))).hexdigest()[:12]


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


def _image_input_files() -> list:
    """The rest of the files the image is built FROM, in a stable order.

    Everything in `docker/` (the Dockerfile's own `COPY docker/*.py docker/acquire-nim.sh` —
    taken as the whole directory so a script added later is covered without anyone remembering
    to add it here) plus `pyproject.toml`, which decides what lands in the baked venv. Measured
    on the dev box: six files, well under a millisecond to read, and `current_tag` is called
    once per harness run. Hashing `src/` too would be ~40 ms, which is also affordable — the
    reason it is excluded is not cost, it is that a `src/` edit must NOT force a rebuild. See
    `image_tag`.
    """
    files = [p for p in sorted((REPO / "docker").iterdir())
             if p.is_file() and p != DOCKERFILE]
    pyproject = REPO / "pyproject.toml"
    return ([pyproject] if pyproject.exists() else []) + files


def current_tag() -> str:
    parts = [DOCKERFILE.read_bytes(), PINS.read_bytes()]
    for path in _image_input_files():
        # The NAME is hashed with the bytes: renaming a script changes what the Dockerfile
        # copies, and two files swapping contents is still a different image.
        parts.append(path.name.encode() + b"\0" + path.read_bytes())
    return image_tag(*parts)


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


# ─────────────────────────────────────────────────────────────────────── cache accounting
#
# Measured on the dev box 2026-09-14, and the numbers moved the design:
#
#   ~/.cache/uv            21 GB    <- the thing actually filling the disk
#   haru-flex-cache        14 MB    <- the sandbox volume
#   ~/.cache/haru-pack    279 MB
#   anonymous run volumes    0      <- `--rm` reaps them; verified by count before/after
#
# The assumption going in was that the sandbox volume was the problem. It is not, because
# `bundle.warm_cache_and_lock` points UV_CACHE_DIR at the payload's own bundled cache inside
# the build tree rather than at ours. The host cache is where the bytes are.
#
# That split decides what may be automatic. The volume is harness-owned, rebuildable, and
# nobody else's: pruning it on a budget is fine. `~/.cache/uv` is shared with every other
# project on the machine, so this NEVER deletes it without being asked — it reports it, and
# `--flush-cache host` prunes it only when a human types that.

def _du_bytes(image: str, volume: str, timeout: int = 300) -> int:
    """Size of a docker volume, measured by a container that walks only that volume.

    Deliberately not `docker system df -v`: that walks every image and volume on the host,
    which on this box took minutes and timed out. This takes about a second.
    """
    r = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{volume}:/cache",
         "--cap-drop=ALL", "--security-opt", "no-new-privileges",
         image, "du", "-sb", CACHEDIR],
        capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        return -1
    try:
        return int(r.stdout.split()[0])
    except (IndexError, ValueError):
        return -1


def volume_exists(volume: str = CACHE_VOLUME) -> bool:
    """False when docker is absent, rather than raising.

    The cache accounting is reachable on boxes with no docker at all — `--cache-info` still
    has the host caches to report, and CI runs the tests around it. "There is no such volume"
    is the correct answer there, not a FileNotFoundError.
    """
    try:
        return subprocess.run(["docker", "volume", "inspect", volume],
                              capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def clean_path(text: str) -> Path:
    """A Path out of another tool's stdout, with colour escapes removed first.

    Not defensive programming for its own sake: `uv cache dir` writes a COLOURED path, the
    escape codes went into the Path, and `du` then reported **0 B for an 18.9 GB cache**.
    Nothing errored — the number was simply wrong, and it looked exactly like a right one.
    """
    return Path(_ANSI.sub("", text).strip())


def host_cache_paths() -> dict:
    """The caches on THIS machine that a flex/exam run grows. Reported, never auto-deleted."""
    out = {}
    try:
        # NO_COLOR, and an ANSI strip behind it. `uv cache dir` writes a COLOURED path when
        # it thinks anything is listening, and the escape codes end up inside the Path — so
        # `du` measures a directory that does not exist and reports 0 B for a 21 GB cache.
        # A wrong number that looks like a right one is worse than an error.
        r = subprocess.run(["uv", "cache", "dir"], capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, NO_COLOR="1", TERM="dumb"))
        if r.returncode == 0 and r.stdout.strip():
            out["uv"] = clean_path(r.stdout)
    except (OSError, subprocess.SubprocessError):
        pass
    out.setdefault("uv", Path.home() / ".cache" / "uv")
    try:
        from platformdirs import user_cache_dir
        out["haru-pack"] = Path(user_cache_dir("haru-pack", appauthor=False))
    except Exception:
        out["haru-pack"] = Path.home() / ".cache" / "haru-pack"
    return out


def _tree_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    r = subprocess.run(["du", "-sb", str(path)], capture_output=True, text=True, timeout=600)
    try:
        return int(r.stdout.split()[0]) if r.returncode == 0 else -1
    except (IndexError, ValueError):
        return -1


def human(n: int) -> str:
    if n < 0:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n:.1f} TB"


def cache_report(image: str | None = None) -> list:
    """[(label, path-or-volume, bytes, owner)] for everything a run grows.

    `owner` is "harness" for things this tool may delete on its own, and "shared" for the
    host caches that belong to the whole machine.
    """
    rows = []
    if image and volume_exists():
        rows.append(("sandbox volume", CACHE_VOLUME, _du_bytes(image, CACHE_VOLUME), "harness"))
    elif image:
        rows.append(("sandbox volume", f"{CACHE_VOLUME} (does not exist yet)", 0, "harness"))
    for label, path in sorted(host_cache_paths().items()):
        rows.append((f"host {label} cache", str(path), _tree_bytes(path), "shared"))
    return rows


def flush_volume(volume: str = CACHE_VOLUME, image: str | None = None) -> tuple:
    """(removed, bytes_freed). Removing the volume is safe: it is a cache, and it is ours."""
    if not volume_exists(volume):
        return False, 0
    freed = _du_bytes(image, volume) if image else -1
    r = subprocess.run(["docker", "volume", "rm", volume],
                       capture_output=True, text=True, timeout=120)
    return r.returncode == 0, freed


#: Refuse a budget below this. Not arbitrary — see `enforce_cache_budget`.
MIN_BUDGET_GB = 1.0

#: What emptying the sandbox volume actually costs, measured on the top25 run 2026-09-14.
#: Pre-wrapped: this is printed to a terminal, and a 400-character single line is how a
#: message that took real measurement to write gets skimmed past.
FLUSH_COST = (
    "the volume holds haru-pack's XZ-compressed uv (55.6 MB -> 14.2 MB at preset 9),\n"
    "  which is recomputed on the next build if it is gone. Measured across a top25\n"
    "  matrix: builds took 207-213s with a cold volume and 70-83s with a warm one —\n"
    "  about 140s per build, paid by every build that runs before the first one\n"
    "  repopulates it."
)


def enforce_cache_budget(max_gb: float, image: str, log=print) -> None:
    """Bring the sandbox volume under `max_gb` BEFORE a run starts.

    Before, never during: reclaiming space underneath a matrix that is halfway through would
    turn a disk problem into a pile of confusing package failures.

    `uv cache prune` first, then removal if that was not enough.

    Measured 2026-09-14: prune reclaimed **0 of 13.5 MB** here, and that is expected rather
    than a bug. Most of this volume is haru-pack's OWN cache at `/cache/haru-pack` (the
    XZ-compressed uv binaries), which uv neither owns nor knows about; uv's cache is the
    smaller `/cache/uv`. Prune is still tried first because it is cheap and, on a volume that
    has done a lot of dependency resolution, it is the non-destructive win.

    THE FLOOR EXISTS BECAUSE THIS VOLUME IS SMALL AND EXPENSIVE, NOT SMALL AND IDLE

    A budget under `MIN_BUDGET_GB` is refused rather than honoured. That looks paternalistic
    until you have paid for it: the first implementation of this was tested with a 1 MB
    budget, which removed the volume, and the next top25 run spent 207-213s on each of its
    first four builds instead of 70-83s. The saving would have been 13.5 MB. Nothing about
    the number "0.001" warns you that it trades ten minutes of CPU for a rounding error of
    disk, so the tool says it instead.
    """
    if max_gb < MIN_BUDGET_GB:
        raise ValueError(
            f"--max-cache-gb {max_gb:g} is below the {MIN_BUDGET_GB:g} GB floor.\n\n"
            f"  That budget would empty the sandbox cache to save almost nothing —\n"
            f"  {FLUSH_COST}\n\n"
            f"  If you actually want it gone, say so directly: --flush-cache sandbox.")
    if not volume_exists():
        return
    size = _du_bytes(image, CACHE_VOLUME)
    budget = int(max_gb * 1024 ** 3)
    if size < 0 or size <= budget:
        return

    log(f"cache: {human(size)} is over the {max_gb} GB budget — pruning")
    subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{CACHE_VOLUME}:{CACHEDIR}",
         "-e", f"UV_CACHE_DIR={CACHEDIR}/uv", "--cap-drop=ALL",
         "--security-opt", "no-new-privileges", image, "uv", "cache", "prune"],
        capture_output=True, text=True, timeout=900)

    after = _du_bytes(image, CACHE_VOLUME)
    if 0 <= after <= budget:
        log(f"cache: pruned to {human(after)} (freed {human(size - after)})")
        return
    removed, _ = flush_volume(image=image)
    if removed:
        log(f"cache: still {human(after)} after pruning — removed {CACHE_VOLUME} entirely "
            f"(it is a cache; the next run refills what it needs)")


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

"""INV-SANDBOX-01/02 — the flex and exam harnesses run stranger code in a box, not on the host.

These tests never start a container. They read the argv `tools/sandbox.docker_argv()`
produces and assert on it, which is deliberate and is the reason the module is shaped the
way it is: a containment guarantee that can only be checked by running docker is a guarantee
that gets checked when somebody remembers. This runs offline, in CI, on a box with no docker
installed.

`docs/adr/0005-sandboxed-flex-and-exam-harnesses.md` is the contract.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

import sandbox  # noqa: E402

WORK = Path("/tmp/flex-out/numpy")


def argv_for(**kw) -> list[str]:
    """A build-phase argv unless overridden. Keeps each test to the one thing it varies."""
    base = dict(cmd=["haru-pack", "build", "/w/proj"], work=WORK, network=True,
                cache=sandbox.CACHE_RW, uid=1000, gid=1000)
    base.update(kw)
    return sandbox.docker_argv("haru-pack-flex:abc123", **base)


def flag_value(argv: list[str], flag: str) -> str | None:
    """The value following `flag`, or None."""
    return argv[argv.index(flag) + 1] if flag in argv else None


def mounts(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]


# ───────────────────────────────────────────────── INV-SANDBOX-02: the network decision

@pytest.mark.invariant("INV-SANDBOX-02")
def test_a_thick_verification_run_has_no_network_interface():
    """Red-path: flip `network=False` to `True` for the thick run phase.

    This is the property that makes --offline-check mean something. flex used to force
    UV_OFFLINE and point the proxy variables at a dead port, and said so in its own
    docstring: it "does not stop a package from opening a raw socket of its own". With
    `--network none` there is no interface to open one on.
    """
    argv = argv_for(cmd=["/w/numpy"], network=False, cache=sandbox.CACHE_COLD)
    assert flag_value(argv, "--network") == "none", (
        "the thick verification run must have NO network interface. Without this the "
        "offline check is UV_OFFLINE plus a dead proxy, which a package can simply ignore "
        "by opening its own socket."
    )


@pytest.mark.invariant("INV-SANDBOX-02")
def test_the_offline_check_runs_against_a_cache_that_has_never_been_used():
    """Red-path: pass CACHE_RW (the warm named volume) instead of CACHE_COLD.

    A warm cache makes the run succeed from cache and prove nothing about the payload,
    which is the exact failure mode the original `_offline_env` docstring warned about.
    """
    argv = argv_for(cmd=["/w/numpy"], network=False, cache=sandbox.CACHE_COLD)
    assert "-v" in argv and sandbox.CACHEDIR in mounts(argv), (
        "a cold cache must be an anonymous volume mounted at /cache"
    )
    assert not any(m.startswith(f"{sandbox.CACHE_VOLUME}:") for m in mounts(argv)), (
        f"the offline check must not mount the warm {sandbox.CACHE_VOLUME} volume — "
        f"the dependency would be served from cache and the check would be vacuous"
    )


def test_the_default_tier_run_keeps_its_network():
    """Not every run should be offline, and pretending otherwise would fail everything.

    At the default tier the dependency is SUPPOSED to be fetched on first run. Denying the
    network there tests nothing; it just breaks the harness.
    """
    argv = argv_for(cmd=["/w/requests"], network=True, cache=sandbox.CACHE_COLD)
    assert flag_value(argv, "--network") == "bridge"


def test_there_is_no_way_to_ask_for_the_host_network():
    """`network` is a bool, not a docker network name. Adding `host` requires editing the
    function, which is the point — host networking would put stranger code on the
    developer's loopback, where their unauthenticated local services live."""
    src = (REPO / "tools" / "sandbox.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == "docker_argv")
    literals = {n.value for n in ast.walk(fn) if isinstance(n, ast.Constant)
                and isinstance(n.value, str)}
    assert "host" not in literals, "docker_argv must not be able to emit --network host"


# ───────────────────────────────────────── INV-SANDBOX-01: what the box does and does not hold

@pytest.mark.invariant("INV-SANDBOX-01")
def test_the_docker_socket_is_never_mounted():
    """Red-path: add the socket to the mount list.

    Mounting the daemon socket into a container that runs stranger code hands it the daemon,
    which on a rootful host is root. It is the single most common way a "sandbox" turns out
    not to be one.
    """
    for kw in ({}, dict(network=False, cache=sandbox.CACHE_COLD),
               dict(cache=sandbox.CACHE_COLD), dict(repo=REPO)):
        argv = argv_for(**kw)
        joined = " ".join(argv)
        assert "docker.sock" not in joined, f"docker socket mounted: {joined}"
        assert "--privileged" not in argv


@pytest.mark.invariant("INV-SANDBOX-01")
def test_the_repository_is_mounted_read_only_or_not_at_all():
    """Red-path: drop the `:ro` from the repo mount.

    The harness wants the working tree's haru-pack rather than whatever was baked into the
    image, so the repo is in the container's filesystem namespace while a hostile sdist
    build backend is running. Read-only is the entire reason that is acceptable.
    """
    argv = argv_for(repo=REPO)
    repo_mounts = [m for m in mounts(argv) if m.startswith(f"{REPO}:")]
    assert repo_mounts, "expected the repo to be mounted when `repo=` is given"
    for m in repo_mounts:
        assert m.endswith(":ro"), f"the repository must be mounted read-only, got {m!r}"


@pytest.mark.invariant("INV-SANDBOX-01")
def test_the_shared_cache_is_never_mounted_while_stranger_code_runs():
    """Red-path: pass CACHE_RW for the run phase, i.e. hand the package the shared volume.

    The build phase needs the shared cache writable, and that is a stated residual risk
    (ADR 0005 §9). The run phase — where the package's own code executes — must not see it
    at all, in either direction: writable lets a package poison what the next build reads,
    and read-only still lets it read every other package's fetched artifacts.

    It cannot simply be omitted either: a thick binary STAGES into $XDG_CACHE_HOME before it
    can execute. The first implementation mounted the shared volume `:ro` and died with
    `OSError: Read-only file system /cache/haru-pack/<hash>.tmp-1`. A throwaway anonymous
    volume is what satisfies both halves.
    """
    argv = argv_for(cmd=["/w/numpy"], network=True, cache=sandbox.CACHE_COLD)
    assert not any(m.startswith(f"{sandbox.CACHE_VOLUME}:") for m in mounts(argv)), (
        "the run phase must not mount the shared cache volume"
    )
    assert sandbox.CACHEDIR in mounts(argv), (
        "the run phase still needs a writable /cache — the launcher stages into it"
    )


def test_there_is_no_read_only_cache_mode_to_reach_for():
    """The mode that looked right and does not work is gone, not merely unused.

    Leaving `CACHE_RO` in the enum would invite exactly the bug that was just fixed back in,
    because mounting the shared cache read-only reads as the cautious choice.
    """
    assert set(sandbox.CACHE_MODES) == {sandbox.CACHE_RW, sandbox.CACHE_COLD}
    assert not hasattr(sandbox, "CACHE_RO")


@pytest.mark.invariant("INV-SANDBOX-01")
def test_every_container_drops_capabilities_and_cannot_regain_privilege():
    argv = argv_for()
    assert "--cap-drop=ALL" in argv
    assert flag_value(argv, "--security-opt") == "no-new-privileges"
    assert "--rm" in argv, "a container that outlives its step is a container nobody reaps"


@pytest.mark.invariant("INV-SANDBOX-01")
def test_the_container_runs_as_the_invoking_user():
    assert flag_value(argv_for(uid=1000, gid=1000), "-u") == "1000:1000"


@pytest.mark.invariant("INV-SANDBOX-01")
def test_the_only_writable_host_path_is_the_per_package_work_directory():
    """Red-path: mount $HOME, or the repo without `:ro`, or add any second writable path.

    Everything the harness needs to get back out comes through the work directory. Anything
    else mounted writable is blast radius with no purpose.
    """
    argv = argv_for(repo=REPO)
    writable = [m for m in mounts(argv)
                if ":" in m and not m.endswith(":ro") and not m.startswith(f"{sandbox.CACHE_VOLUME}:")]
    assert writable == [f"{WORK}:{sandbox.WORKDIR}"], (
        f"exactly one writable host mount expected (the work dir); got {writable}"
    )


def test_an_unknown_cache_mode_is_refused_rather_than_guessed():
    with pytest.raises(ValueError):
        argv_for(cache="warm-ish")


# ───────────────────────────────────────────────────────── INV-SANDBOX-01: the host path

@pytest.mark.invariant("INV-SANDBOX-01")
def test_the_host_path_warning_names_what_is_actually_at_risk():
    """Red-path: delete the banner, or soften it to "running without a sandbox".

    An operator's eye slides off "no sandbox". It does not slide off "your SSH keys".
    """
    banner = sandbox.host_warning(25, "packages")
    for phrase in ("SSH keys", "credentials", "$HOME", "EXECUTE", "25"):
        assert phrase in banner, f"the --no-docker banner must name {phrase!r}"
    assert "--no-docker" in banner, "the banner must name the flag that got you here"


@pytest.mark.invariant("INV-SANDBOX-01")
def test_missing_docker_is_an_error_and_never_a_silent_fallback_to_the_host():
    """Red-path: make `preflight` return None / fall through when docker is absent.

    A silent fallback is how a safe default quietly stops being the default: the harness
    keeps working, nobody sees a difference, and the containment is gone.
    """
    src = (REPO / "tools" / "sandbox.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == "preflight")
    raises = [n for n in ast.walk(fn) if isinstance(n, ast.Raise)]
    assert raises, "preflight must raise when docker is unavailable, not return a host fallback"
    assert "--no-docker" in ast.get_source_segment(src, fn), (
        "the error must name the flag that opts into the host path"
    )


# ───────────────────────────────────────────────────────────────── image identity

def test_the_image_tag_changes_when_a_pin_changes():
    """Red-path: tag the image `latest`, or hash only the Dockerfile.

    The image bakes the pinned toolchain. If bumping a pin does not change the tag, a stale
    image is silently reused and the harness tests a toolchain the repo no longer declares.
    """
    base = sandbox.image_tag(b"FROM debian", b"uv = 1")
    assert base != sandbox.image_tag(b"FROM debian", b"uv = 2"), "a pin bump must retag"
    assert base != sandbox.image_tag(b"FROM alpine", b"uv = 1"), "a Dockerfile edit must retag"
    assert base == sandbox.image_tag(b"FROM debian", b"uv = 1"), "the tag must be stable"


def test_the_tag_derivation_cannot_be_confused_by_a_field_boundary():
    """The two inputs are separated, so moving bytes from one to the other changes the tag."""
    assert sandbox.image_tag(b"AB", b"C") != sandbox.image_tag(b"A", b"BC")


def test_docker_argv_is_pure():
    """It reads no environment, no filesystem and no clock — which is what lets every test
    above run offline. Red-path: add an `os.environ` read to docker_argv."""
    src = (REPO / "tools" / "sandbox.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == "docker_argv")
    body = ast.get_source_segment(src, fn)
    for forbidden in ("os.environ", "getenv", "subprocess", "Path.cwd", "time.", "open("):
        assert forbidden not in body, f"docker_argv must stay pure; found {forbidden!r}"


# ─────────────────────────────────────── INV-SANDBOX-01: nobody bypasses the runner

HARNESS_FILES = ("flex-run.py", "exam.py", "exam_fetch.py")

#: The ONE class in each harness that is allowed to execute a built artifact directly. It is
#: reachable only via --no-docker, which prints the banner first.
SANCTIONED_HOST_CLASS = "HostRunner"


def _direct_artifact_executions(src: str) -> list[str]:
    """[enclosing class name or '<module>'] for each `subprocess.*([str(x)], ...)` call.

    An AST walk rather than a grep because the rule has an exception and a grep cannot see
    it: executing the artifact inside `HostRunner` IS the opt-in host path. Matching on text
    alone either flags the legitimate one or is loosened until it flags nothing.
    """
    tree = ast.parse(src)
    owner: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for child in ast.walk(node):
                owner[id(child)] = node.name

    found = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"run", "Popen", "call", "check_output"}
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"):
            continue
        if not (node.args and isinstance(node.args[0], ast.List)):
            continue
        # `[str(exe)]` — a one-element argv that is a stringified path object is how you
        # execute a produced artifact. `[self.haru, "build", ...]` is not.
        first = node.args[0].elts[0] if node.args[0].elts else None
        if (isinstance(first, ast.Call) and isinstance(first.func, ast.Name)
                and first.func.id == "str"):
            found.append(owner.get(id(node), "<module>"))
    return found


@pytest.mark.invariant("INV-SANDBOX-01")
@pytest.mark.parametrize("name", HARNESS_FILES)
def test_no_harness_executes_a_built_binary_except_through_the_sandbox(name: str):
    """Red-path: move `subprocess.run([str(exe)], ...)` out of HostRunner and back into
    `run_one`, where it runs regardless of which runner was chosen.

    One containerized path plus one forgotten direct call is not containment; it is
    containment with a hole that passes every test aimed at the good path.
    """
    path = REPO / "tools" / name
    if not path.exists():
        pytest.skip(f"{name} not present")
    offenders = [where for where in _direct_artifact_executions(path.read_text(encoding="utf-8"))
                 if where != SANCTIONED_HOST_CLASS]
    assert not offenders, (
        f"tools/{name} executes a built artifact directly in {offenders}. Route it through "
        f"tools/sandbox.run(), or through {SANCTIONED_HOST_CLASS}, which is reachable only "
        f"via --no-docker and prints the warning first."
    )


def test_the_bypass_check_would_actually_catch_a_bypass():
    """A guard-of-guards, in the style of tests/test_invariants_enforced.py.

    The test above passes trivially if the AST walk matches nothing, which is exactly what
    happened to its first (regex) version from the other direction. So: feed it a known
    bypass and a known-legitimate call, and require it to tell them apart.
    """
    bypass = "import subprocess\ndef run_one(exe):\n    subprocess.run([str(exe)])\n"
    assert _direct_artifact_executions(bypass) == ["<module>"]

    sanctioned = ("import subprocess\nclass HostRunner:\n"
                  "    def execute(self, exe):\n        subprocess.run([str(exe)])\n")
    assert _direct_artifact_executions(sanctioned) == ["HostRunner"]

    building = ('import subprocess\ndef b(haru, proj):\n'
                '    subprocess.run([haru, "build", str(proj)])\n')
    assert _direct_artifact_executions(building) == [], (
        "building is not executing the artifact; flagging it would make the rule useless"
    )


@pytest.mark.invariant("INV-SANDBOX-01")
@pytest.mark.parametrize("name", ("flex-run.py", "exam.py"))
def test_the_harness_imports_the_sandbox_at_all(name: str):
    """The cheap guard against this whole file being satisfied by a module nobody calls."""
    path = REPO / "tools" / name
    if not path.exists():
        pytest.skip(f"{name} not present")
    assert "sandbox" in path.read_text(encoding="utf-8"), (
        f"tools/{name} does not reference the sandbox runner"
    )


# ───────────────────────────────────────────────────────────────── cache accounting (#33)

def test_a_coloured_path_from_another_tool_is_cleaned_before_it_is_used():
    """Regression. `uv cache dir` emits a COLOURED path when it thinks anything is listening.

    The escape codes went into the Path, so `du` measured a directory that does not exist and
    reported **0 B for an 18.9 GB cache**. Nothing raised; the number was just wrong, and it
    looked exactly like a right one — the worst shape a bug can have in a tool whose entire
    output is numbers.

    Red-path: drop the strip and pass the raw stdout to Path().
    """
    coloured = "\x1b[36m/home/shyft/.cache/uv\x1b[39m\n"
    assert sandbox.clean_path(coloured) == Path("/home/shyft/.cache/uv")
    assert sandbox.clean_path("/plain/path\n") == Path("/plain/path")


def test_sizes_are_reported_in_units_a_person_can_act_on():
    assert sandbox.human(0) == "0 B"
    assert sandbox.human(2048) == "2.0 KB"
    assert sandbox.human(18_900_000_000).endswith("GB")


def test_an_unmeasurable_size_is_never_reported_as_zero():
    """`-1` means "could not measure". Rendering it as `0 B` would tell someone their cache
    is empty when the truth is that we failed to look at it."""
    assert sandbox.human(-1) == "?"


def test_the_host_caches_are_labelled_as_shared_and_the_volume_is_not():
    """The label decides what may be deleted automatically.

    `~/.cache/uv` is used by every project on the machine — 18.9 GB of it on the dev box,
    almost none of it flex's. Only the harness's own volume is ever removed without being
    asked. Red-path: mark a host cache "harness" and it becomes eligible for the budget.
    """
    owners = {label: owner for label, _where, _size, owner in sandbox.cache_report(None)}
    assert owners, "expected at least the host caches to be reported"
    for label, owner in owners.items():
        expected = "harness" if "sandbox" in label else "shared"
        assert owner == expected, f"{label} is labelled {owner}, expected {expected}"


@pytest.mark.invariant("INV-SANDBOX-01")
def test_the_cache_budget_is_enforced_before_the_matrix_not_during_it():
    """Red-path: call `enforce_cache_budget` from `run_one`.

    Reclaiming space underneath a run that is halfway through turns a disk problem into a
    pile of confusing package failures — builds start failing for a reason that has nothing
    to do with the packages being tested.
    """
    src = (REPO / "tools" / "flex-run.py").read_text(encoding="utf-8")
    callers = set()
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.FunctionDef):
            continue
        for child in ast.walk(node):
            if (isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                    and child.func.attr == "enforce_cache_budget"):
                callers.add(node.name)
    assert callers == {"choose_runner"}, (
        f"the cache budget must be enforced once, before the run starts; called from {callers}"
    )

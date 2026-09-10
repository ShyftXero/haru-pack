"""`--shake` — the tree-shaker's guards.

The feature deletes files out of a payload that is about to be signed and shipped, on the
strength of a test run. That makes two things worth more than the size saving: that it
never prunes without evidence, and that it never *ships* without re-proving the result
works. Both are invariants here; the rest of these tests pin the prune semantics that
those two guards depend on.
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from haru_pack import build as build_mod
from haru_pack import shake as sh


# --------------------------------------------------------------------------------- fixtures

def _write(p: Path, text: str = "x") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


@pytest.fixture
def fake_payload(tmp_path):
    """A thick payload's shape, small enough to assert about file by file.

    `mypkg` is a runtime dependency with one observed module and one big unobserved native
    blob. `pytest` stands in for the dev group — present in the payload today because the
    cache warm runs `uv sync`, which installs the default groups.
    """
    payload = tmp_path / "payload"
    arc = payload / "vendor" / "cache" / "archive-v0"
    _write(arc / "aaa" / "mypkg" / "__init__.py", "import os\n")
    _write(arc / "aaa" / "mypkg" / "heavy.so", "N" * 4096)
    _write(arc / "aaa" / "mypkg" / "unused.py", "pass\n")
    _write(arc / "aaa" / "mypkg-1.0.dist-info" / "METADATA", "Name: mypkg\nVersion: 1.0\n")
    _write(arc / "aaa" / "mypkg-1.0.dist-info" / "RECORD", "mypkg/__init__.py,,\n")
    _write(arc / "bbb" / "pytest" / "__init__.py", "pass\n")
    _write(arc / "bbb" / "pytest-8.0.dist-info" / "METADATA", "Name: pytest\nVersion: 8.0\n")
    _write(payload / "vendor" / "cache" / "simple-v20" / "pypi.json", "{}" * 500)
    _write(payload / "vendor" / "cache" / "wheels-v6" / "mypkg.msgpack", "wheel-pointer")
    _write(payload / "vendor" / "cache" / "interpreter-v4" / "probe.msgpack", "/home/op")
    _write(payload / "vendor" / "cache" / "whatsnew-v1" / "mystery.bin", "unknown bucket")
    py = payload / "vendor" / "python"
    _write(py / "lib" / "python3.12" / "os.py", "pass\n")
    _write(py / "lib" / "python3.12" / "test" / "test_os.py", "T" * 2048)
    _write(py / "lib" / "python3.12" / "idlelib" / "idle.py", "I" * 2048)
    _write(py / "lib" / "python3.12" / "tkinter" / "__init__.py", "K" * 2048)
    _write(py / "include" / "python3.12" / "Python.h", "H" * 2048)
    obs_env = tmp_path / "obs"
    (obs_env / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    return payload, obs_env


def _cache(payload: Path) -> Path:
    return payload / "vendor" / "cache"


def _rel(payload: Path):
    return {p.relative_to(payload).as_posix() for p in payload.rglob("*") if p.is_file()}


# ------------------------------------------------------- INV-SHAKE-03: no evidence, no prune

@pytest.mark.invariant("INV-SHAKE-03")
def test_shake_refuses_a_project_with_no_test_command(tmp_path):
    """Red-path: give `resolve_config` a fallback (`test = test or ["pytest"]`) and this
    goes green while `--shake` starts deleting files from projects that never proved
    anything about what they need."""
    app = tmp_path / "app"
    app.mkdir()
    _write(app / "pyproject.toml", "[project]\nname='a'\nversion='0'\n")
    with pytest.raises(sh.ShakeError) as e:
        sh.resolve_config(app, {})
    assert "test command" in str(e.value)
    assert "[shake]" in str(e.value), "the refusal must show how to declare one"


@pytest.mark.invariant("INV-SHAKE-03")
def test_a_declared_test_command_is_used_verbatim(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    cfg = sh.resolve_config(app, {"shake": {"test": ["pytest", "-q", "-m", "not slow"]}})
    assert cfg.test == ["pytest", "-q", "-m", "not slow"]


@pytest.mark.invariant("INV-SHAKE-03")
def test_a_tests_directory_is_evidence_enough_to_run_pytest(tmp_path):
    app = tmp_path / "app"
    (app / "tests").mkdir(parents=True)
    assert sh.resolve_config(app, {}).test == ["pytest"]


@pytest.mark.invariant("INV-SHAKE-03")
def test_a_failing_observation_run_prunes_nothing(tmp_path, monkeypatch):
    """A red suite is the worst possible input: everything after the first failure went
    unexecuted, so it all looks prunable. Refuse instead of shaking on a partial trace."""
    app = tmp_path / "app"
    app.mkdir()
    obs = tmp_path / "obs"
    (obs / "bin").mkdir(parents=True)
    cfg = sh.ShakeConfig(test=["false"])
    with pytest.raises(sh.ShakeError) as e:
        sh._observe(cfg, obs, app, Path("/usr/bin/python3"))
    assert "before anything was pruned" in str(e.value)


# ------------------------------------------------ INV-SHAKE-01: never ship an unverified cut

@pytest.mark.invariant("INV-SHAKE-01")
def test_a_failed_verification_raises_instead_of_returning_a_report(fake_payload,
                                                                   monkeypatch, tmp_path):
    """Red-path: wrap the `_verify(...)` call in `shake()` in `try/except ShakeError: pass`.
    This test goes red immediately — and a build would then emit a signed binary whose
    dependencies were pruned on an unproven guess."""
    payload, obs = fake_payload
    monkeypatch.setattr(sh, "_runtime_dists", lambda app_dir: {"mypkg"})
    monkeypatch.setattr(sh, "_observe", lambda *a, **k: (set(), [], "strace"))

    def boom(*a, **k):
        raise sh.ShakeError("suite failed against the shaken payload")
    monkeypatch.setattr(sh, "_verify", boom)

    with pytest.raises(sh.ShakeError):
        sh.shake(payload, tmp_path / "app", _cache(payload), Path("/usr/bin/python3"),
                 obs, sh.ShakeConfig(test=["pytest"]), tmp_path / "wd")


@pytest.mark.invariant("INV-SHAKE-01")
def test_shake_verifies_before_it_returns():
    """The verification is not an option a caller can decline; it is inside `shake()`."""
    src = inspect.getsource(sh.shake)
    assert "_verify(" in src, "shake() no longer verifies the pruned payload"
    assert "return {" in src.split("_verify(")[1], (
        "the report is built before verification, so a caller could use it without one"
    )


@pytest.mark.invariant("INV-SHAKE-01")
def test_the_verification_reinstalls_offline_exactly_as_the_target_will():
    """Verifying against the build host's own env would prove nothing: the point is that
    the PRUNED cache still resolves with no network, which is what thick promises."""
    src = inspect.getsource(sh._verify)
    assert 'UV_OFFLINE="1"' in src and '"--frozen"' in src, (
        "the shake verification no longer reinstalls from the pruned cache offline"
    )
    assert '"--no-dev"' in src, (
        "the verification env must be the RUNTIME set; syncing dev groups would install "
        "packages the payload no longer contains and hide the breakage"
    )


@pytest.mark.invariant("INV-SHAKE-01")
def test_a_shake_error_fails_the_build_rather_than_shipping_unshaken():
    """Red-path: change the `except ShakeError` in `build()` to log a warning and carry on.
    The operator then gets a binary many times the size they asked for, and finds out from
    `ls -l` or not at all."""
    src = inspect.getsource(build_mod.build)
    assert "ShakeError" in src and "raise BuildError" in src, (
        "build() no longer turns a failed shake into a failed build"
    )


# ------------------------------------ INV-SHAKE-02: verify against what actually got shipped

@pytest.mark.invariant("INV-SHAKE-02")
def test_a_resurrected_file_is_detected(tmp_path):
    """A dev dependency pinning a different version of a runtime dist makes uv reinstall it
    whole, un-pruned, into the verification env. The suite would then pass against files
    the customer will not have — a false green, which is worse than no check at all."""
    venv = tmp_path / "venv"
    sp = venv / "lib" / "python3.12" / "site-packages"
    _write(sp / "mypkg" / "heavy.so", "back again")
    assert sh._resurrected(venv, {"mypkg/heavy.so"}) == {"mypkg/heavy.so"}
    assert sh._resurrected(venv, {"mypkg/still-gone.so"}) == set()


@pytest.mark.invariant("INV-SHAKE-02")
def test_verification_checks_the_pruned_files_are_still_absent():
    src = inspect.getsource(sh._verify)
    assert "_resurrected(" in src, (
        "verification no longer confirms the pruned files are missing from the env it "
        "tests, so a reinstall can turn a broken payload into a passing build"
    )
    assert src.index("_resurrected(") < src.index("for cmd in"), (
        "the absence check must run BEFORE the suite, or the suite result is meaningless"
    )


# ------------------------------------------------------------------------- prune semantics

def test_the_prune_keeps_what_ran_and_drops_what_did_not(fake_payload, monkeypatch,
                                                         tmp_path):
    """One pass over a payload-shaped tree, asserting every category of decision."""
    payload, obs = fake_payload
    sp = obs / "lib" / "python3.12" / "site-packages"
    observed = {str(sp / "mypkg" / "__init__.py"),
                str(payload / "vendor" / "python" / "lib" / "python3.12" / "os.py")}
    monkeypatch.setattr(sh, "_runtime_dists", lambda app_dir: {"mypkg"})
    monkeypatch.setattr(sh, "_observe", lambda *a, **k: (observed, [], "strace"))
    monkeypatch.setattr(sh, "_verify", lambda *a, **k: {"env": "x", "runs": [{"exit": 0}]})

    report = sh.shake(payload, tmp_path / "app", _cache(payload), Path("/usr/bin/python3"),
                      obs, sh.ShakeConfig(test=["pytest"]), tmp_path / "wd")
    left = _rel(payload)

    # observed module stays; the unobserved native blob is the whole point of the feature
    assert "vendor/cache/archive-v0/aaa/mypkg/__init__.py" in left
    assert "vendor/cache/archive-v0/aaa/mypkg/heavy.so" not in left
    # installer metadata is never pruned — importlib.metadata and uv both read it
    assert "vendor/cache/archive-v0/aaa/mypkg-1.0.dist-info/METADATA" in left
    assert "vendor/cache/archive-v0/aaa/mypkg-1.0.dist-info/RECORD" in left
    # the dev group is the measuring device, not a runtime dependency
    assert not any(p.startswith("vendor/cache/archive-v0/bbb/pytest/") for p in left)
    # index metadata and the interpreter-probe cache are build-time only
    assert not any(p.startswith("vendor/cache/simple-v20/") for p in left)
    assert not any(p.startswith("vendor/cache/interpreter-v4/") for p in left)
    # ... but the buckets a runtime offline sync needs stay
    assert "vendor/cache/wheels-v6/mypkg.msgpack" in left
    # an unrecognised bucket is KEPT: no rule says it is safe to drop
    assert "vendor/cache/whatsnew-v1/mystery.bin" in left
    # interpreter rulepack
    assert "vendor/python/lib/python3.12/os.py" in left
    assert not any("/test/" in p for p in left if p.startswith("vendor/python"))
    assert not any("idlelib" in p for p in left)
    assert not any("include/python3.12" in p for p in left)
    # tkinter was never observed, so the whole Tk family goes
    assert not any("tkinter" in p for p in left)

    assert report["freed_bytes"] > 0
    assert report["per_dist"]["mypkg"]["dropped"] >= 1
    assert report["payload_bytes_after"] < report["payload_bytes_before"]


def test_interpreter_rules_match_whatever_prefix_upstream_extracts_to(tmp_path):
    """python-build-standalone extracts to a `python/` directory, and some layouts add an
    `install/` level under it, so the interpreter really lands at
    `vendor/python/python/lib/python3.12/...`. The first rulepack matched the full relative
    path and therefore matched NOTHING — the interpreter came through a shake untouched and
    the saving was silently zero.

    Red-path: make `_prune_interpreter` match `rel` alone instead of `_suffixes(rel)`.
    """
    payload = tmp_path / "payload"
    pydir = payload / "vendor" / "python"
    _write(pydir / "python" / "lib" / "python3.12" / "test" / "test_os.py", "T" * 512)
    _write(pydir / "python" / "install" / "lib" / "python3.12" / "idlelib" / "idle.py", "I")
    _write(pydir / "python" / "lib" / "python3.12" / "os.py", "keep me")
    dropped, freed = sh._prune_interpreter(pydir, payload, tmp_path / "q", set(), [])
    names = {p.name for p in dropped}
    assert names == {"test_os.py", "idle.py"}, f"rules matched {names}"
    assert freed > 0


def test_the_projects_own_wheel_is_not_mistaken_for_a_dev_dependency(tmp_path):
    """`uv export --no-emit-project` leaves the project's own distribution out, and a
    packaged project is installed at runtime from a wheel of itself that uv built into the
    cache. Without adding the name back, that wheel looks dev-only and is dropped whole.

    Red-path: delete the `own = _project_name(app_dir)` lines from `_runtime_dists`. A real
    thick shake then fails verification with uv's `failed to open file
    .../demo-0.1.0.dist-info/METADATA: No such file or directory`.
    """
    app = tmp_path / "app"
    app.mkdir()
    _write(app / "pyproject.toml", "[project]\nname = 'My_Demo.App'\nversion = '0'\n")
    assert sh._project_name(app) == "my-demo-app", "the name must be canonicalised"


def test_a_dev_only_tree_is_exempt_from_the_absence_check(fake_payload, monkeypatch,
                                                          tmp_path):
    """A dev-only dist is dropped BECAUSE it is the measuring device, and the verification
    step reinstalls the test tooling on purpose. Including those paths in the absence check
    made INV-SHAKE-02 fire on every real project (491 false positives, all `_pytest/**`,
    on the first end-to-end run).

    Red-path: return every dropped relpath from `_prune_dependencies` instead of only the
    ones from runtime dists.
    """
    payload, obs = fake_payload
    archives = sh._index_archives(_cache(payload))
    _, _, _, runtime_dropped = sh._prune_dependencies(
        archives, payload, tmp_path / "q", set(), {"mypkg"}, [])
    assert any(r.startswith("mypkg/") for r in runtime_dropped)
    assert not any(r.startswith("pytest/") for r in runtime_dropped), (
        "a dev-only tree's paths must not be required to stay absent from the verify env"
    )


def test_an_operator_keep_glob_overrides_the_evidence(fake_payload, monkeypatch, tmp_path):
    """`--shake-keep` is the escape hatch for the thing the suite cannot exercise. If it
    did not win over the trace, a wrong observation would be unfixable without abandoning
    the flag."""
    payload, obs = fake_payload
    monkeypatch.setattr(sh, "_runtime_dists", lambda app_dir: {"mypkg"})
    monkeypatch.setattr(sh, "_observe", lambda *a, **k: (set(), [], "strace"))
    monkeypatch.setattr(sh, "_verify", lambda *a, **k: {"env": "x", "runs": [{"exit": 0}]})
    sh.shake(payload, tmp_path / "app", _cache(payload), Path("/usr/bin/python3"), obs,
             sh.ShakeConfig(test=["pytest"], keep=["mypkg/heavy.so"]), tmp_path / "wd")
    assert "vendor/cache/archive-v0/aaa/mypkg/heavy.so" in _rel(payload)


def test_pruned_files_are_quarantined_not_unlinked(fake_payload, monkeypatch, tmp_path):
    """A build that deletes in place cannot tell an operator what it removed, and cannot
    put it back. The quarantine is what makes the receipt truthful."""
    payload, obs = fake_payload
    monkeypatch.setattr(sh, "_runtime_dists", lambda app_dir: {"mypkg"})
    monkeypatch.setattr(sh, "_observe", lambda *a, **k: (set(), [], "strace"))
    monkeypatch.setattr(sh, "_verify", lambda *a, **k: {"env": "x", "runs": [{"exit": 0}]})
    wd = tmp_path / "wd"
    report = sh.shake(payload, tmp_path / "app", _cache(payload), Path("/usr/bin/python3"),
                      obs, sh.ShakeConfig(test=["pytest"]), wd)
    q = Path(report["quarantine"])
    assert (q / "vendor/cache/archive-v0/aaa/mypkg/heavy.so").exists()
    assert "vendor/cache/archive-v0/aaa/mypkg/heavy.so" in report["dropped_paths"]


def test_a_lazy_import_target_survives_an_unexercised_code_path(tmp_path):
    """The break observation cannot see:

        def upload(p):
            import boto3        # the suite never calls upload()

    A module-level import runs when its module is imported and the tracer sees it. A
    function-level one does not. Deleting its target turns a working feature into an
    ImportError on a customer machine, so the closure keeps it without evidence.
    """
    root = tmp_path / "arc"
    _write(root / "app" / "__init__.py", "def upload(p):\n    import helper\n")
    _write(root / "helper.py", "VALUE = 1\n")
    _write(root / "orphan.py", "VALUE = 2\n")
    a = sh.Archive(root=root, dist="app", version="1")
    index = sh._module_index([a])
    keep = sh._lazy_import_closure({"app/__init__.py"}, index)
    assert "helper.py" in keep, "a function-level import target was not kept"
    assert "orphan.py" not in keep, "the closure kept a module nothing imports"


def test_the_closure_does_not_resurrect_native_blobs(tmp_path):
    """Why `--shake` can be conservative and still worth running: nothing reaches a `.so`,
    a model weight or a bundled browser through an `import` statement, so the closure
    protects importability while leaving the gigabyte-scale payload prunable."""
    root = tmp_path / "arc"
    _write(root / "pkg" / "__init__.py", "import ctypes\n")
    _write(root / "pkg" / "libcuda_kernels.so", "G" * 1024)
    a = sh.Archive(root=root, dist="pkg", version="1")
    keep = sh._lazy_import_closure({"pkg/__init__.py"}, sh._module_index([a]))
    assert "pkg/libcuda_kernels.so" not in keep


def test_a_package_on_a_kept_path_keeps_its_init(tmp_path):
    """`import a.b.c` executes `a/__init__.py` first. A file kept by the closure has no
    observation behind it, and a package directory without its `__init__.py` is not a
    package — the import fails naming the leaf, not the missing file."""
    root = tmp_path / "arc"
    _write(root / "a" / "__init__.py", "")
    _write(root / "a" / "b" / "__init__.py", "")
    _write(root / "a" / "b" / "c.py", "")
    index = sh._module_index([sh.Archive(root=root, dist="a", version="1")])
    keep = sh._retain_package_inits({"a/b/c.py"}, index)
    assert keep == {"a/b/c.py", "a/__init__.py", "a/b/__init__.py"}


# ------------------------------------------------------------------------------- the tracer

def test_strace_parsing_keeps_successes_and_drops_failed_probes(tmp_path):
    """An interpreter probes a dozen sys.path entries for every import. Keeping the ENOENT
    paths would keep files that do not exist and tell us nothing about the one it found."""
    t = _write(tmp_path / "t.txt",
               'openat(AT_FDCWD, "/opt/env/lib/python3.12/site-packages/mypkg/__init__.py",'
               ' O_RDONLY|O_CLOEXEC) = 3\n'
               'openat(AT_FDCWD, "/opt/env/lib/python3.12/site-packages/nope.py", O_RDONLY)'
               ' = -1 ENOENT (No such file or directory)\n'
               'openat(AT_FDCWD, "relative/thing.py", O_RDONLY) = 4\n')
    got = sh._parse_strace(t)
    assert "/opt/env/lib/python3.12/site-packages/mypkg/__init__.py" in got
    assert not any("nope.py" in p for p in got)
    assert not any(p.startswith("relative") for p in got), "only absolute paths are mappable"


def test_an_rpath_relative_library_open_is_normalized(tmp_path):
    """The bug that would have broken every scientific wheel.

    A manylinux wheel that vendors its shared libraries links them with an `$ORIGIN`
    RPATH, so the loader opens them by a path that walks back out through the package:

        .../site-packages/numpy/_core/../../numpy.libs/libscipy_openblas64_-f48b354e.so

    Un-normalized that yields the relpath `numpy/_core/../../numpy.libs/...`, which matches
    nothing in the archive tree — the library looks untouched, gets pruned, and the payload
    dies at `import numpy`. numpy, scipy, torch, pillow and lxml all do this.

    Red-path: drop the `os.path.normpath` in `shake._normalize`. This goes red, and a real
    `--shake` of anything numpy-shaped fails its own verification with numpy's "Original
    error was: libscipy_openblas64_...so: cannot open shared object file".
    """
    env = tmp_path / "env"
    sp = env / "lib" / "python3.12" / "site-packages"
    sp.mkdir(parents=True)
    t = _write(tmp_path / "t.txt",
               f'openat(AT_FDCWD, "{sp}/numpy/_core/../../numpy.libs/libopenblas.so",'
               ' O_RDONLY|O_CLOEXEC) = 3\n')
    assert sh._observed_relpaths(sh._parse_strace(t), env) == {"numpy.libs/libopenblas.so"}


def test_env_paths_map_onto_wheel_root_relative_paths(tmp_path):
    """The whole mapping: an archive tree is rooted where site-packages is rooted, so the
    relative path is shared. No inode games, and it holds whether uv hardlinked or copied."""
    env = tmp_path / "env"
    sp = env / "lib" / "python3.12" / "site-packages"
    sp.mkdir(parents=True)
    got = sh._observed_relpaths({str(sp / "jinja2" / "loaders.py"), "/usr/lib/libc.so.6"}, env)
    assert got == {"jinja2/loaders.py"}


def test_the_audit_hook_fallback_does_not_shadow_a_projects_sitecustomize(tmp_path):
    """A `.pth` whose line starts with `import` runs at interpreter start and cannot
    collide by name; a `sitecustomize.py` would silently replace the project's own."""
    env = tmp_path / "env"
    sp = env / "lib" / "python3.12" / "site-packages"
    sp.mkdir(parents=True)
    sh._install_audit_hook(env)
    assert not (sp / "sitecustomize.py").exists()
    pth = next(sp.glob("*.pth"))
    assert pth.read_text().startswith("import ")
    assert "addaudithook" in (sp / "haru_shake_trace.py").read_text()


def test_the_report_records_which_tracer_ran(fake_payload, monkeypatch, tmp_path):
    """strace sees a C extension's own dlopen; the audit hook cannot. A payload shaken
    without strace keeps native libraries it might not need, and the receipt must say so
    rather than letting an operator assume the stronger observation happened."""
    payload, obs = fake_payload
    monkeypatch.setattr(sh, "_runtime_dists", lambda app_dir: {"mypkg"})
    monkeypatch.setattr(sh, "_observe", lambda *a, **k: (set(), [], "audit"))
    monkeypatch.setattr(sh, "_verify", lambda *a, **k: {"env": "x", "runs": [{"exit": 0}]})
    rep = sh.shake(payload, tmp_path / "app", _cache(payload), Path("/usr/bin/python3"),
                   obs, sh.ShakeConfig(test=["pytest"]), tmp_path / "wd")
    assert rep["tracer"] == "audit"
    out = tmp_path / "app.exe"
    dest = sh.write_report(rep, out)
    assert dest.name == "app.exe.shake.json"
    assert sh.manifest_summary(rep)["shaken"] is True


# --------------------------------------------------------------------------- build-time guards

@pytest.mark.parametrize("tier", ["thin", "default"])
def test_shake_without_thick_is_refused(tmp_path, tier):
    """At thin/default the dependencies are not in the payload at all, so a shake would be
    a no-op reported as a saving."""
    with pytest.raises(build_mod.BuildError) as e:
        build_mod.assemble_payload(tmp_path / "src", {"app_subdir": "app", "kind": "project"},
                                   tier, "host", "3.12", tmp_path / "wd", shake=True)
    assert "--thick" in str(e.value)


def test_shake_is_refused_for_a_cross_target(tmp_path):
    """Observation means RUNNING the suite. A Linux host cannot run the Windows binary
    whose payload it is pruning."""
    with pytest.raises(build_mod.BuildError) as e:
        build_mod.assemble_payload(tmp_path / "src", {"app_subdir": "app", "kind": "project"},
                                   "thick", "windows-x86_64", "3.12", tmp_path / "wd",
                                   shake=True)
    assert "cannot build for" in str(e.value)


def test_shake_is_refused_for_a_bare_script(tmp_path):
    with pytest.raises(build_mod.BuildError) as e:
        build_mod.assemble_payload(tmp_path / "src", {"app_subdir": "app", "kind": "script"},
                                   "thick", "host", "3.12", tmp_path / "wd", shake=True)
    assert "not a single PEP 723 script" in str(e.value)


def test_the_guards_run_before_anything_is_downloaded():
    """Discovering a shake was impossible after staging a 90 MB interpreter wastes the
    operator's time — and the tempting fix at that point is to carry on and emit an
    unshaken binary."""
    src = inspect.getsource(build_mod.assemble_payload)
    head = src.split("payload = workdir")[0]
    assert "--shake needs --thick" in head, (
        "the --shake preconditions are checked after the payload staging begins"
    )


def test_the_shake_declaration_does_not_reach_the_launcher():
    """`[shake]` is build-time input. A manifest field nothing reads is a field someone
    later mistakes for load-bearing."""
    src = inspect.getsource(build_mod.assemble_payload)
    assert 'manifest.pop("shake_declared"' in src
    nim = (Path(__file__).resolve().parent.parent
           / "src/haru_pack/launcher/manifest.nim").read_text()
    assert "shake_declared" not in nim


def test_the_observation_env_is_the_one_built_from_the_bundled_cache():
    """Tracing a project's own `.venv` would observe a different resolution against a
    different interpreter, and produce a keep set for a payload that does not exist."""
    src = inspect.getsource(build_mod.assemble_payload)
    call = src.split("shake_mod.shake(")[1]
    assert "tmp_env" in call.split(")")[0], (
        "the shake no longer observes the env uv built from the bundled cache"
    )

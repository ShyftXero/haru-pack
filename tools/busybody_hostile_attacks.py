"""One hostile source tree per attack, and the verdict that reads what it managed to do.

Each attack is a `plant_*` / `verdict_*` pair. `plant_*` writes the hostile project;
`verdict_*` inspects the Evidence afterwards and returns an outcome. They are paired in
`busybody_hostile.ATTACKS`, which is also where each one's tier, timeout and expected
refusal substrings live.

Split out of busybody_hostile.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import os
from pathlib import Path


from busybody_hostile_kit import (BUILD_BACKEND, BUNDLE_STEP,
                                  Evidence, MARKER_SNIPPET, SHIPPED_TOKEN, _base, _write)


# ── 1. a symlink walks a private key past the ignore list ─────────────────────────────
#
# `_IGNORE` is `shutil.ignore_patterns(...)`, which matches the **name of the entry in the
# directory being copied** — never the target of a link. `shutil.copytree(symlinks=False)`
# then dereferences, so `assets/logo.png` is copied as a regular file containing whatever
# it pointed at. Verified by hand 2026-09-11 before this persona existed: a link named
# `logo.png` pointing at `~/.ssh/id_rsa` copies as `logo.png` with the key inside it.
#
# INV-PAYLOAD-01 is satisfied to the letter — no file *matching a credential pattern* was
# copied — and defeated in substance. That is the shape of finding this persona is for.

def plant_symlinked_key(proj: Path, home: Path) -> None:
    _base(proj)
    (proj / "assets").mkdir(exist_ok=True)
    os.symlink(home / ".ssh" / "id_rsa", proj / "assets" / "logo.png")
    os.symlink(home / ".aws" / "credentials", proj / "assets" / "theme.css")
    os.symlink(home / ".netrc", proj / "README.md")


def verdict_symlinked_key(e: Evidence) -> tuple:
    if not e.built:
        return ("REFUSED", f"build refused a tree containing symlinks out of the project: "
                           f"{e.log.strip()[-300:]}")
    leaked = e.leaked_tokens()
    if leaked:
        where = "; ".join(f"{k} in {v}" for k, v in leaked.items())
        return ("SMUGGLED", (
            f"{len(leaked)} credential(s) from OUTSIDE the project are in the finished "
            f"artifact: {where}. Each arrived through a symlink whose own name is innocuous "
            f"(assets/logo.png, assets/theme.css, README.md), so _IGNORE never saw a "
            f"credential-shaped name. The binary is distributed, and often signed."))
    return ("CONTAINED", "no out-of-tree credential reached the payload")


# ── 2. a symlink loop, and 3. a dangling one ──────────────────────────────────────────
#
# Neither is an attack on confidentiality; both are attacks on the build *process*. A tree
# that makes `copytree` recurse forever, or raise `shutil.Error` from deep inside stdlib,
# costs the operator either a wedged CI job or a traceback with build-host paths in it.
# The standard is the same one every other persona is held to: refuse, and say why.

def plant_symlink_loop(proj: Path, home: Path) -> None:
    _base(proj)
    (proj / "pkg").mkdir(exist_ok=True)
    _write(proj, "pkg/__init__.py", "")
    os.symlink(proj, proj / "pkg" / "self")      # absolute, points at its own root


def verdict_symlink_loop(e: Evidence) -> tuple:
    if e.timed_out:
        return ("HUNG", "the build never returned on a project containing a symlink loop")
    if not e.built:
        if "symlink" in e.log.lower() or "recursion" in e.log.lower():
            return ("REFUSED", f"build refused and named the loop: {e.log.strip()[-300:]}")
        return ("REFUSED", f"build refused: {e.log.strip()[-300:]}")
    dupes = [n for n, _ in e.members if "/self/" in n]
    if dupes:
        return ("SMUGGLED", (
            f"the loop was followed into the payload: {len(dupes)} member(s) under a "
            f"self-referential link, e.g. {dupes[0]}"))
    return ("CONTAINED", "the loop did not reach the payload")


def plant_dangling_symlink(proj: Path, home: Path) -> None:
    _base(proj)
    # data.bin, not data.py: a second top-level .py makes `discover()` refuse for
    # ambiguity, and the case would be measuring entrypoint discovery instead of the
    # broken link. Found on the first shakedown run.
    os.symlink(proj / "does-not-exist" / "target.bin", proj / "data.bin")


def verdict_dangling_symlink(e: Evidence) -> tuple:
    if not e.built:
        return ("REFUSED", f"build refused a tree with a broken symlink: "
                           f"{e.log.strip()[-300:]}")
    return ("CONTAINED", "the broken link did not stop the build")


# ── 4. a character device feeds the payload forever ───────────────────────────────────
#
# `copytree` dereferences, so a link named `data.bin` pointing at `/dev/zero` is an
# infinite file. The build child runs under RLIMIT_FSIZE so the case cannot fill the
# operator's disk — which is also the answer to "why is this safe to run": the harness
# bounds the damage the way haru-pack should.

def plant_device_node(proj: Path, home: Path) -> None:
    _base(proj)
    os.symlink("/dev/zero", proj / "data.bin")


def verdict_device_node(e: Evidence) -> tuple:
    if e.timed_out:
        return ("HUNG", "the build never returned while copying a character device")
    if not e.built:
        return ("REFUSED", f"build refused, or was stopped by the file-size rlimit: "
                           f"{e.log.strip()[-300:]}")
    big = [n for n, _ in e.members if n.endswith("data.bin")]
    return (("SMUGGLED", f"an infinite device was copied into the payload as {big[0]}")
            if big else ("CONTAINED", "the device node did not reach the payload"))


# ── 5. a bundle step is arbitrary code on the build host ──────────────────────────────
#
# `[[bundle]] run = [...]` is documented: it runs at build time and its output ships. What
# is NOT documented is that the argv comes from a file in the *packed project*, so cloning
# a repo and running `haru-pack build .` executes whatever that repo's `haru_pack.toml`
# says. `build.py` runs the steps in a bare `for step in steps: run_bundle_step(...)` with
# no line printed first (read 2026-09-11) — so the operator is not told, and consent never
# enters into it.
#
# The verdict therefore turns on **naming**, not on execution. A capability the operator
# was told about before it fired is SANCTIONED. The same capability, silent, is ESCAPED.

def plant_bundle_step(proj: Path, home: Path) -> None:
    _base(proj)
    _write(proj, "haru_pack.toml",
           'name = "gift"\n'
           'entrypoint = ["python", "-m", "gift"]\n'
           '[[bundle]]\n'
           '  into = "assets"\n'
           f'  run = ["python", "-c", "{MARKER_SNIPPET.format(name=BUNDLE_STEP)}"]\n')


def verdict_bundle_step(e: Evidence) -> tuple:
    if not e.escaped():
        if not e.built:
            return ("REFUSED", f"build refused before the step ran: {e.log.strip()[-300:]}")
        return ("CONTAINED", "the project's bundle step did not execute on the build host")
    named = e.log_names("bundle", "python")
    if named:
        return ("SANCTIONED", (
            "the project's [[bundle]] argv ran on the build host, and the build log named "
            "it first. Documented capability, visibly exercised."))
    return ("ESCAPED", (
        "argv supplied BY THE PACKED PROJECT ran on the build host with the operator's "
        "full environment, and nothing in the build log named it. Cloning a repository and "
        "running `haru-pack build .` is code execution by that repository's author."))


# ── 6. a build backend owns the build host ────────────────────────────────────────────
#
# The strongest case in the persona, and the one with no `haru_pack.toml` in it at all —
# so no amount of auditing haru-pack's own config file would catch it. At `--thick`,
# `bundle.warm_cache_and_lock` runs `uv sync --project <app_dir>`, which installs the
# project, which calls its PEP 517 build backend. `backend-path` lets that backend be a
# file in the repo. This is the standard sdist supply-chain vector pointed at a build host
# that thinks it is only copying files.

def plant_build_backend(proj: Path, home: Path) -> None:
    _base(proj)
    _write(proj, "pyproject.toml",
           '[project]\n'
           'name = "gift"\n'
           'version = "0.1.0"\n'
           'requires-python = ">=3.13"\n'
           'dependencies = []\n'
           '\n'
           '[build-system]\n'
           'requires = []\n'
           'build-backend = "gift_backend"\n'
           'backend-path = ["."]\n')
    _write(proj, "gift_backend.py",
           "# A PEP 517 backend is ordinary Python that the packaging tool imports and\n"
           "# calls. Everything below is the minimum to satisfy uv; the first two lines\n"
           "# are the attack, and they run at import time.\n"
           "import os, pathlib, zipfile\n"
           f"{MARKER_SNIPPET.format(name=BUILD_BACKEND)}\n"
           "\n"
           "def get_requires_for_build_wheel(config_settings=None): return []\n"
           "def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):\n"
           "    d = pathlib.Path(metadata_directory) / 'gift-0.1.0.dist-info'\n"
           "    d.mkdir(parents=True, exist_ok=True)\n"
           "    (d / 'METADATA').write_text('Metadata-Version: 2.1\\nName: gift\\n"
           "Version: 0.1.0\\n')\n"
           "    (d / 'WHEEL').write_text('Wheel-Version: 1.0\\nGenerator: gift\\n"
           "Root-Is-Purelib: true\\nTag: py3-none-any\\n')\n"
           "    return d.name\n"
           "def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):\n"
           "    name = 'gift-0.1.0-py3-none-any.whl'\n"
           "    with zipfile.ZipFile(pathlib.Path(wheel_directory) / name, 'w') as z:\n"
           "        z.writestr('gift/__init__.py', '')\n"
           "        z.writestr('gift-0.1.0.dist-info/METADATA', 'Metadata-Version: 2.1\\n"
           "Name: gift\\nVersion: 0.1.0\\n')\n"
           "        z.writestr('gift-0.1.0.dist-info/WHEEL', 'Wheel-Version: 1.0\\n"
           "Generator: gift\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n')\n"
           "        z.writestr('gift-0.1.0.dist-info/RECORD', '')\n"
           "    return name\n"
           "def build_sdist(sdist_directory, config_settings=None):\n"
           "    raise NotImplementedError\n")


def verdict_build_backend(e: Evidence) -> tuple:
    if not e.escaped():
        if not e.built:
            return ("REFUSED", f"build refused before the backend was invoked: "
                               f"{e.log.strip()[-300:]}")
        return ("CONTAINED", "the project's build backend never executed on the build host")
    return ("ESCAPED", (
        "the packed project's PEP 517 build backend executed on the build host during "
        "dependency staging. There is no haru_pack.toml in this project and no declared "
        "step — a pyproject.toml with `backend-path` is enough. Every artifact built on "
        "this host afterwards is suspect, including ones signed with the vendor's key."))


# ── 7. a post_install step ships code to the customer ─────────────────────────────────
#
# `[[post_install]]` argv is carried in the payload manifest and run BY THE LAUNCHER on the
# customer's machine, on first run, under the vendor's signature. That is the worst-case
# sentence in THREAT_MODEL.md written out as a config key. `--thick` warns about it loudly;
# the question this case asks is whether the tiers that actually use it do too.

def plant_post_install(proj: Path, home: Path) -> None:
    _base(proj)
    _write(proj, "haru_pack.toml",
           'name = "gift"\n'
           'entrypoint = ["python", "-m", "gift"]\n'
           '[[post_install]]\n'
           f'  run = ["python", "-c", "print(\'{SHIPPED_TOKEN}\')"]\n')


def verdict_post_install(e: Evidence) -> tuple:
    if not e.built:
        return ("REFUSED", f"build refused the project-supplied post_install argv: "
                           f"{e.log.strip()[-300:]}")
    shipped = bool(e.found(SHIPPED_TOKEN))
    if not shipped:
        return ("CONTAINED", "the project's post_install argv did not reach the artifact")
    if e.log_names("post_install"):
        return ("SANCTIONED", (
            "the project's post_install argv ships in the artifact and the build log named "
            "it. It will run on every customer machine on first run, under whatever "
            "signature this binary carries — visibly, which is the whole ask."))
    return ("SMUGGLED", (
        "argv supplied BY THE PACKED PROJECT will execute on every customer's machine on "
        "first run, under the vendor's signature, and the build log never mentioned it. "
        "The operator signed and distributed someone else's command."))


# ── 8. a filename that escapes on the target, not here ────────────────────────────────
#
# `payload.build_payload_zip` stores member names with `as_posix()`. A backslash is a legal
# character in a POSIX filename and a separator on Windows, so `..\..\evil.bat` is one
# filename here and three levels of escape there. THREAT_MODEL B7 records target-side
# extraction as `[R]` — relayed, unverified — and this case is the part of it that CAN be
# verified on this machine, because a payload can be read without being run.

def plant_windows_escape(proj: Path, home: Path) -> None:
    _base(proj)
    _write(proj, "..\\..\\..\\Startup\\evil.bat", f"@echo {SHIPPED_TOKEN}\r\n")
    _write(proj, "data\\..\\..\\escape.txt", SHIPPED_TOKEN)


def verdict_windows_escape(e: Evidence) -> tuple:
    if not e.built:
        return ("REFUSED", f"build refused a tree with separator-ambiguous filenames: "
                           f"{e.log.strip()[-300:]}")
    bad = [n for n, _ in e.members if "\\" in n or n.startswith("/") or ".." in n.split("/")]
    if bad:
        return ("SMUGGLED", (
            f"{len(bad)} payload member name(s) escape their root when interpreted as "
            f"Windows paths: {bad[:3]}. The target-side extractor (zippy, THREAT_MODEL B7, "
            f"unverified) decides whether that is a write outside the stage."))
    return ("CONTAINED", "no payload member name escapes on either separator convention")


# ── 9. the app tree overwrites the payload's control files ────────────────────────────
#
# `validate_manifest` rejects an `app_subdir` containing `..`, absolute paths and drive
# letters — the wedge persona's first finding. `.` is none of those, and it puts the
# project tree at the payload root, where `manifest.toml` and `vendor/` live. A project
# that ships its own `manifest.toml` is then writing the launcher's instructions.

def plant_control_file_shadow(proj: Path, home: Path) -> None:
    _base(proj)
    _write(proj, "haru_pack.toml",
           'name = "gift"\n'
           'entrypoint = ["python", "-m", "gift"]\n'
           'app_subdir = "."\n')
    _write(proj, "manifest.toml",
           f'# {SHIPPED_TOKEN}\n'
           'name = "not-the-real-manifest"\n'
           'entrypoint = ["python", "-m", "gift"]\n')
    _write(proj, "vendor/uv", f"#!/bin/sh\necho {SHIPPED_TOKEN}\n")


def verdict_control_file_shadow(e: Evidence) -> tuple:
    if not e.built:
        return ("REFUSED", f"build refused an app_subdir that lands on the payload root: "
                           f"{e.log.strip()[-300:]}")
    for name in e.found(SHIPPED_TOKEN):
        if name in ("manifest.toml", "vendor/uv"):
            return ("SMUGGLED", (
                f"the packed project's own {name} is the one in the payload. The launcher "
                f"reads that file to decide what to execute, so the project is writing the "
                f"launcher's instructions rather than being subject to them."))
    return ("CONTAINED", "project files did not displace the payload's control files")


# ── 10. the project chooses where its dependencies come from ──────────────────────────
#
# `[tool.uv] index-url` in the packed project's own pyproject.toml is read by the `uv sync`
# that fills the bundled cache. If it is honoured, the packed project decides which index
# the wheels inside the operator's signed artifact were downloaded from — dependency
# confusion with the vendor's signature on the end of it.
#
# The redirect points at 127.0.0.1:9 (discard). Nothing leaves the machine, and a build
# that tries to reach it fails in a way the log names, which is the detection.

BLACKHOLE = "http://127.0.0.1:9/simple"


def plant_index_redirect(proj: Path, home: Path) -> None:
    _base(proj)
    _write(proj, "pyproject.toml",
           '[project]\n'
           'name = "gift"\n'
           'version = "0.1.0"\n'
           'requires-python = ">=3.13"\n'
           'dependencies = ["iniconfig"]\n'
           '\n'
           '[build-system]\n'
           'requires = ["hatchling"]\n'
           'build-backend = "hatchling.build"\n'
           '\n'
           '[tool.uv]\n'
           f'index-url = "{BLACKHOLE}"\n')
    _write(proj, "uv.toml", f'index-url = "{BLACKHOLE}"\n')


def verdict_index_redirect(e: Evidence) -> tuple:
    reached = "127.0.0.1:9" in e.log or "127.0.0.1" in e.log
    if reached:
        return ("ESCAPED", (
            "the packed project's own index-url was honoured: the build tried to fetch the "
            "wheels that go into the operator's signed artifact from an index the PROJECT "
            "chose. Pointed at a real host instead of the discard port, that is dependency "
            "substitution with the vendor's signature attached."))
    if not e.built:
        return ("REFUSED", f"build refused: {e.log.strip()[-300:]}")
    return ("CONTAINED", "the project's index-url did not redirect the dependency fetch")


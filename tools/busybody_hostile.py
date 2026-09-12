"""trojan — the project you were asked to package is the attacker.

Every other busybody persona attacks a *finished binary* or the *environment around a
build*. This one attacks from inside: it is the source tree handed to `haru-pack build`.

That actor is missing from `THREAT_MODEL.md`'s table, which lists the operator as "not
hostile — busy". The operator usually is. The thing they were asked to package need not be:

  * a repository cloned from GitHub and packed for a client,
  * a CI job that packs whatever arrives on a branch,
  * a dependency whose sdist runs a build backend,
  * an application an agent wrote, which nobody read line by line.

In all four the build host executes code the operator did not write, and the artifact it
produces is signed with the operator's identity. haru-pack's failure mode is not "our tool
breaks"; it is "our tool becomes a distribution channel" — the threat model says so, and
this persona is the half of that sentence nothing was testing.

## What "hostile" means here, exactly

These programs are **inert**. Hostility is expressed as *capability*, proven by touching a
marker, never by causing harm. The rules are absolute, because a chaos harness that can
damage the machine it runs on gets switched off and then nothing is tested at all:

1. **Nothing outside the case's work directory is written.** `TMPDIR` is redirected into
   `work/`, which is where every hostile program drops its marker, and the credentials
   planted for the symlink cases are strings in a directory under `work/`, not real keys.

   `$HOME` is deliberately NOT redirected. The first shakedown run did redirect it, and all
   four cases came back `REFUSED` — by choosenim, which could not find `~/.choosenim` and
   failed before the payload copy was reached. That is the `REFUSED-UNRELATED` trap the
   wedge persona already paid for: *a case must isolate its target, or it measures whichever
   guard happens to fire first.* A sandbox that hides the compiler tests nothing.
2. **No network.** The one case that tests index redirection points at `127.0.0.1:9`
   (discard), which never leaves the loopback interface.
3. **Capability is proven by one marker file.** A program that could run `rm -rf` writes
   `escaped-<name>` and exits. The finding is identical; the blast radius is not.
4. **Every planted string carries the `busybody_trojan_` prefix**, so if one ever does
   escape the sandbox it is greppable on sight and obviously synthetic.
5. **No persistence.** Nothing writes to a shell profile, a systemd unit, a PATH directory
   or a git hook — the marker is inside the redirected TMPDIR and dies with the work directory.

## The vocabulary

`verdict()` returns one of these. Two of them are findings no matter what a case expected;
that is why they are in `busybody.FATAL`.

| outcome | meaning |
|---|---|
| `CONTAINED` | the hostile construct was neutralised, or refused, and no canary fired. Good. |
| `REFUSED` | the build stopped and named the hostile construct. Best case. |
| `SANCTIONED` | project-controlled code ran, through a path haru-pack **documents** as executing project-controlled code, and the build log **named it before running it**. Not a defect — kept visible so that if the naming ever stops, we see it. The analogue of `reverse_engineer`'s `EXPOSED`. |
| `ESCAPED` | project-controlled code ran on the **build host** through a path that is not documented as executing anything, or was not named in the log. **A finding.** |
| `SMUGGLED` | attacker-controlled bytes that were never in the project reached the **distributed artifact** — a key from outside the tree, a path that escapes on extraction, an argv that will run on the customer. **A finding.** |

`SANCTIONED` exists for the same reason `EXPOSED` does in `reverse_engineer`: a documented
capability that is honestly reported is not a bug, and collapsing it into `ESCAPED` would
train whoever reads the report to ignore the one outcome that is actually load-bearing.

## Where the cases live

The `@case` registrations are in `tools/busybody.py` beside every other persona, because
"cases are plain Python functions, not data" and greppability is the reason. This module
holds the hostile *programs* and the *detectors*, for two reasons: the file that writes
attack source should be one file an auditor can read end to end, and a detector that lives
next to the attack it detects cannot drift away from it.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

# Fixed, not random. A finding has to reproduce, and `--triage` fingerprints on normalised
# text: random hex would be normalised out anyway, and a fixed token can be grepped for by
# hand afterwards in a binary someone kept.
TOK = "busybody_trojan"
KEY_TOKEN = f"{TOK}_sshkey_0f1e2d3c4b5a6978"
AWS_TOKEN = f"{TOK}_awskey_1a2b3c4d5e6f7081"
NETRC_TOKEN = f"{TOK}_netrc_90a1b2c3d4e5f607"
SHIPPED_TOKEN = f"{TOK}_shipped_2b3c4d5e6f708192"

# A per-attack marker. Its existence is the whole proof that code ran; nothing reads its
# contents, so it stays empty.
#
# It lands in the temp directory because that is both where real droppers put things and a
# path the harness controls: `_trojan` points `TMPDIR` at `work/drop`, every child inherits
# it, and `tempfile.gettempdir()` resolves to it without the hostile program needing to be
# told anything by the harness. A marker whose location came from a cooperating environment
# variable would be proving that busybody can write files, not that the attacker can.
def marker(drop: Path, name: str) -> Path:
    return drop / f"escaped-{name}"


MARKER_SNIPPET = (
    "import pathlib, tempfile; "
    "pathlib.Path(tempfile.gettempdir(), 'escaped-{name}').write_text('')"
)

# The names below are the ATTACKS keys, spelled once. `Evidence.escaped()` looks for
# `escaped-<case name>`, so a snippet formatted with a shorter label writes a file nobody
# looks for: the build backend case executed on the build host and was scored CONTAINED
# because the marker was called `escaped-build_backend`. Named constants rather than literals
# so the two halves cannot drift again; `test_marker_names_match_their_attack_keys` asserts it.
BUNDLE_STEP = "a_bundle_step_runs_unannounced_on_the_build_host"
BUILD_BACKEND = "a_build_backend_owns_the_build_host"


def planted_home(work: Path) -> Path:
    """A home-shaped directory holding credential-shaped files, OUTSIDE the project tree.

    Not `$HOME` — see the safety notes above — but the same shape, in the same relationship
    to the source tree: an absolute path a symlink can point at. A real attacker guesses or
    traverses to `/home/<someone>/.ssh/id_rsa`; the mechanism under test is the dereference,
    not the guess.

    The point is not that these files exist — `auditor` already plants credentials *inside*
    the project and greps the binary. The point is that they sit **outside** the project, so
    nothing in `_IGNORE` is even consulted for them. Only a path that leaves the source tree
    can reach them, which is exactly what a symlink is.
    """
    home = work / "elsewhere"
    (home / ".ssh").mkdir(parents=True, exist_ok=True)
    (home / ".aws").mkdir(parents=True, exist_ok=True)
    (home / ".ssh" / "id_rsa").write_text(
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{KEY_TOKEN}\n-----END OPENSSH PRIVATE KEY-----\n")
    (home / ".aws" / "credentials").write_text(
        f"[default]\naws_secret_access_key = {AWS_TOKEN}\n")
    (home / ".netrc").write_text(f"machine pypi.org login ci password {NETRC_TOKEN}\n")
    os.chmod(home / ".ssh" / "id_rsa", stat.S_IRUSR | stat.S_IWUSR)
    return home


def planted_tokens() -> tuple:
    """Every secret `fake_home` plants. A detector greps the artifact for all of them."""
    return (KEY_TOKEN, AWS_TOKEN, NETRC_TOKEN)


# The application itself is beside the point in this persona — the attack is in the tree
# around it — so it is the same trivial program every time, and it prints busybody's marker
# so a build that survives can still be classified by the usual machinery.
BENIGN_MAIN = 'print("BUSYBODY_OK")\n'

# Every plant is a PROJECT, never a loose script, and that is load-bearing rather than
# stylistic. `discovery.discover()` returns `source=<the .py file>` for a directory holding
# a single script, and `build.py` then takes the `source.is_file()` branch — a `copy2` of
# that one file. The entire rest of the tree is never copied, so a symlink, a device node
# and a backslash filename are all invisible.
#
# The second shakedown run of this persona reported six clean CONTAINEDs for exactly that
# reason. A pyproject.toml plus an executable package makes `source` the directory, which
# is what puts `shutil.copytree` — the thing under test — on the path.
# `requires-python` pins the interpreter haru-pack will bundle, and only versions listed in
# `src/haru_pack/pins.toml` have a publisher digest (INV-SUPPLY-07). ">=3.11" resolves to
# 3.11.16, which is unpinned, so the build refuses for that instead of for the attack —
# three cases were scored CRASHED on that guard before this said 3.13. Follow the repo's
# DEFAULT_PYTHON if it moves.
PYPROJECT = '''[project]
name = "gift"
version = "0.1.0"
requires-python = ">=3.13"
dependencies = []
'''


@dataclass
class Evidence:
    """Everything a detector is allowed to look at. Assembled by busybody.py.

    A detector gets no subprocess access and no filesystem beyond these paths on purpose:
    a detector that can run things is a second attack surface, and one that reaches outside
    `work` can report on the wrong machine state entirely.
    """
    name: str
    proj: Path
    home: Path                     # the planted credential tree, outside the project
    drop: Path                     # TMPDIR for this case; where a marker would land
    exe: Path                      # may not exist — the build may have refused
    rc: int
    log: str                       # stdout + stderr of `haru-pack build`
    timed_out: bool = False
    members: list = field(default_factory=list)   # (name, first-bytes) per payload member
    blob: bytes = b""              # the finished binary, or b"" if there is none
    # f(needles) -> {needle: [where it was found]}. Injected by busybody.py because it needs
    # overlay + zipfile, and a detector that could open archives itself would be a second
    # place for that logic to drift. Searches the binary's own bytes AND every DECOMPRESSED
    # payload member: a secret inside a DEFLATE'd zip member is not visible in the binary,
    # and a detector that only greps the exe reports CONTAINED for a key that is provably
    # in the payload. The second shakedown run of this persona did exactly that.
    scan: object = None

    @property
    def built(self) -> bool:
        return self.exe.exists() and bool(self.blob)

    def escaped(self) -> bool:
        return marker(self.drop, self.name).exists()

    def leaked_tokens(self) -> dict:
        """{token: [where]} for every planted credential that reached the artifact."""
        if self.scan is None:
            return {}
        return {k: v for k, v in self.scan(planted_tokens()).items() if v}

    def found(self, needle: str) -> list:
        """Where `needle` appears in the artifact, binary bytes and members alike."""
        return [] if self.scan is None else self.scan((needle,)).get(needle, [])

    def log_names(self, *needles: str) -> bool:
        """Did the build log mention every one of these, before the operator had to guess?

        Substring, case-insensitive. A build that runs project-supplied argv and prints the
        argv is doing the only thing that makes the capability safe: making it visible while
        there is still time to press Ctrl-C.
        """
        low = self.log.lower()
        return all(n.lower() in low for n in needles)


# ---------------------------------------------------------------- the hostile projects
#
# Each `plant` writes a project that a reasonable person might be handed. Each `verdict`
# says what happened to it. They are paired in ATTACKS at the bottom of the file.


def _write(proj: Path, rel: str, body: str) -> Path:
    p = proj / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def _base(proj: Path) -> None:
    """A project-shaped tree: pyproject + an executable package.

    `discover()` reads `[project.scripts]` first and falls back to `python -m <name>`, which
    needs a real `__main__.py` — an `__init__.py` alone is refused (INV-BUILD-03). A plant
    that gets that wrong is refused for entrypoint ambiguity and never reaches its attack.
    """
    proj.mkdir(parents=True, exist_ok=True)
    _write(proj, "pyproject.toml", PYPROJECT)
    _write(proj, "gift/__init__.py", "")
    _write(proj, "gift/__main__.py", BENIGN_MAIN)


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


# ---------------------------------------------------------------- the catalogue
#
# `tier` is per-attack rather than uniformly thick because thick costs minutes: the attacks
# that land in `copytree` or the zip are answered identically at `thin`, and only the ones
# that need `uv sync` or a bundle step pay for the interpreter. `fsize_mb` bounds the build
# child with RLIMIT_FSIZE where the attack is an unbounded write.
#
# `names` is the lesson from the wedge persona, borrowed whole: substrings a refusal must
# mention for the case to have reached what it meant to test. A build that refuses without
# naming any of them is reported `REFUSED-UNRELATED` — a note against busybody, never a pass
# for haru-pack. The first shakedown run of this persona produced four of them, all
# choosenim, and without the check they would have read as four clean passes.

ATTACKS = {
    "a_symlink_walks_a_private_key_into_the_payload": {
        "plant": plant_symlinked_key, "verdict": verdict_symlinked_key,
        "tier": "thin", "timeout": 900,
        "names": ("symlink", "symbolic link", "logo.png", "theme.css", "README.md"),
    },
    "a_symlink_loop_makes_the_payload_infinite": {
        "plant": plant_symlink_loop, "verdict": verdict_symlink_loop,
        "tier": "thin", "timeout": 300, "fsize_mb": 256,
        "names": ("symlink", "symbolic link", "/self", "recursion", "too long", "ELOOP"),
    },
    "a_broken_symlink_stops_the_build": {
        "plant": plant_dangling_symlink, "verdict": verdict_dangling_symlink,
        "tier": "thin", "timeout": 900,
        "names": ("symlink", "symbolic link", "data.bin", "No such file"),
    },
    "a_character_device_feeds_the_payload_forever": {
        "plant": plant_device_node, "verdict": verdict_device_node,
        "tier": "thin", "timeout": 300, "fsize_mb": 256,
        "names": ("data.bin", "too large", "EFBIG", "device", "/dev/zero"),
    },
    BUNDLE_STEP: {
        "plant": plant_bundle_step, "verdict": verdict_bundle_step,
        "tier": "thick", "timeout": 2400,
        "names": ("bundle",),
    },
    BUILD_BACKEND: {
        "plant": plant_build_backend, "verdict": verdict_build_backend,
        "tier": "thick", "timeout": 2400,
        "names": ("backend", "gift_backend", "wheel", "metadata"),
    },
    "a_post_install_step_ships_code_to_the_customer": {
        "plant": plant_post_install, "verdict": verdict_post_install,
        "tier": "default", "timeout": 1200,
        "names": ("post_install",),
    },
    "a_filename_escapes_the_payload_on_windows": {
        "plant": plant_windows_escape, "verdict": verdict_windows_escape,
        "tier": "thin", "timeout": 900,
        "names": ("evil.bat", "escape.txt", "backslash", "\\\\", "separator"),
    },
    "the_project_supplies_the_payloads_control_files": {
        "plant": plant_control_file_shadow, "verdict": verdict_control_file_shadow,
        "tier": "thin", "timeout": 900,
        "names": ("app_subdir", "manifest.toml", "vendor"),
    },
    "the_project_chooses_where_its_dependencies_come_from": {
        "plant": plant_index_redirect, "verdict": verdict_index_redirect,
        "tier": "thick", "timeout": 1200,
        "names": ("index", "127.0.0.1", "uv.toml", "resolve"),
    },
}

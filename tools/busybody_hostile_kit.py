"""The trojan persona's sandbox: planted credentials, evidence, and a benign base project.

The rules these primitives enforce are the ones that make the persona safe to run at all
(see the charter in busybody_hostile.py): every planted string carries the
`busybody_trojan_` prefix so an escaped one is greppable on sight, and capability is proven
by touching a marker rather than by causing harm.

Split out of busybody_hostile.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
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


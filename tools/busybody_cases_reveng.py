"""reverse_engineer — rummage the extraction for what was supposed to be hidden.

The distinction these cases keep straight is the one INV-SECRET-02 turns on: obfuscation
raises the cost of READING the staged source; it is not a confidentiality boundary. A case
that conflated the two would report a pass for a binary whose secret is one `strings` away.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "src") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "src"))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from haru_pack import overlay  # noqa: E402,F401

from busybody_config import (FATAL, MARKER, case)  # noqa: E402,F401
from busybody_runner import (Ctx, InfraFailure, blame, classify, clean_env,  # noqa: E402,F401
                             dir_bytes, infra_failure_reason, run_exe, stage_root,
                             warm, work_root_report)
from busybody_wedge import _build, _run_artifact  # noqa: E402,F401

# ------------------------------------------------- reverse_engineer: rummage the extraction
# The dev who must embed an API key and ship it. Encryption protects the payload AT REST in
# the binary; but the launcher stages plaintext to disk so the interpreter can run it, and
# any user who can RUN the binary owns that plaintext. This persona plants a known secret and
# proves each edge of that boundary rather than asserting it (INV-SECRET-02).

RE_SECRET = "sk_live_REVENG_" + "a1b2c3d4e5f60718"


def _reveng_app(secret: str) -> str:
    return (f'API_KEY = "{secret}"\n'
            'def main():\n'
            f'    print("{MARKER} ran; key length", len(API_KEY))\n'
            'if __name__ == "__main__":\n    main()\n')


def _reveng_build(work: Path, name: str, *extra) -> tuple:
    proj = work / f"re-{name}"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "app.py").write_text(_reveng_app(RE_SECRET))
    out = work / f"re-bin-{name}"
    # thick so the staged interpreter matches an obfuscation target exactly, and so the run
    # needs no network (INV-OBF-01, INV-TIER-01).
    rc, so, se = _build(proj / "app.py", out, "--tier", "thick", *extra, timeout=2400)
    return (rc == 0 and out.exists()), out, (so + se).strip()[-400:]


def _reveng_run_and_stage(exe: Path, work: Path, tag: str) -> Path | None:
    """Run the binary so it stages, then return the staged tree root under an isolated
    cache. The stage is the whole point — that is where the plaintext lands."""
    cache = work / f"cache-{tag}"
    r = run_exe(exe, work, env=clean_env(cache), timeout=600)
    if r["outcome"] not in ("RAN", "APP-CRASHED"):
        return None
    return stage_root(cache)


def _grep_tree(root: Path, needle: bytes) -> list:
    hits = []
    for f in root.rglob("*"):
        if f.is_file():
            try:
                if needle in f.read_bytes():
                    hits.append(str(f.relative_to(root)))
            except OSError:
                pass
    return hits


@case("reverse_engineer", "RAN",
      "An ENCRYPTED build must not carry the secret in plaintext in the binary at rest. This "
      "is what encryption buys: someone who has the exe but does not run it cannot read the "
      "key out of it. The persona greps the whole binary for the planted literal.",
      inv="INV-SECRET-02",
      remedy="A LEAKED here means the payload was appended in plaintext despite --encrypt — "
             "check that the secret was threaded into build() and the payload is ciphertext "
             "(INV-BUILD-02). This is the one surface encryption is supposed to close.",
      per_fixture=False, serial=True)
def encrypted_binary_hides_the_secret_at_rest(exe: Path, work: Path) -> dict:
    ok, out, note = _reveng_build(work, "enc", "--encrypt", "--secret", "reveng-build-key")
    if not ok:
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"encrypted build failed: {note}"}
    present = RE_SECRET.encode() in out.read_bytes()
    if present:
        return {"outcome": "LEAKED", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": (
                    "the planted secret is in the ENCRYPTED binary's bytes at rest; "
                    "encryption did not close its one surface")}
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} secret absent from the encrypted binary at rest "
                      f"({out.stat().st_size / 1e6:.0f}MB scanned)", "stderr": ""}


@case("reverse_engineer", "EXPOSED",
      "A PLAIN build leaks its source to the stage. The launcher writes the decrypted (here, "
      "never-encrypted) payload to the running user's cache in plaintext and leaves it there "
      "— it is the regenerable cache, not a temp dir. This case keeps that reality VISIBLE: "
      "if it ever stops being exposed, the staging model changed and the docs must too.",
      inv="INV-SECRET-02",
      remedy="EXPOSED is the expected, documented outcome — not a bug to fix but a fact to "
             "keep true and keep documented. A secret that must never be recovered must "
             "never be shipped in an artifact the client holds.",
      per_fixture=False, serial=True)
def plaintext_source_is_recoverable_from_the_stage(exe: Path, work: Path) -> dict:
    ok, out, note = _reveng_build(work, "plain")
    if not ok:
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"plain build failed: {note}"}
    root = _reveng_run_and_stage(out, work, "plain")
    if root is None:
        return {"outcome": "REFUSED", "rc": None, "seconds": 0, "blame": "launcher",
                "stdout": "", "stderr": "binary did not stage; nothing to rummage"}
    hits = _grep_tree(root, RE_SECRET.encode())
    if hits:
        return {"outcome": "EXPOSED", "rc": 0, "seconds": 0, "blame": "unknown",
                "stdout": "", "stderr": (
                    f"planted secret recovered from the staged plaintext at {root.name}/: "
                    f"{hits[:4]} — the documented soft spot")}
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} secret NOT in the stage — unexpected; staging model may "
                      f"have changed, re-read INV-SECRET-02", "stderr": ""}


@case("reverse_engineer", "RAN",
      "Obfuscation must strip the plaintext literal from the staged source. Build the same "
      "app plain and with --obfuscate pyarmor, run both, rummage both stages: the literal is "
      "in the plain stage and GONE from the obfuscated one. This is the measured value of "
      "--obfuscate — cost raised, not a boundary — and the case proves it both ways so a "
      "no-op obfuscator cannot pass.",
      inv="INV-OBF-01",
      remedy="A LEAKED means obfuscation did not remove the literal (obfuscator no-op'd, or "
             "the swap failed). If the plain side is ALSO clean the case is vacuous — the "
             "control must show the literal, or the test proves nothing.",
      per_fixture=False, serial=True)
def obfuscation_strips_the_plaintext_literal_from_the_stage(exe: Path, work: Path) -> dict:
    okp, plain, notep = _reveng_build(work, "ctl")
    if not okp:
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"control (plain) build failed: {notep}"}
    oko, obf, noteo = _reveng_build(work, "obf", "--obfuscate", "pyarmor")
    if not oko:
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"obfuscated build failed (pyarmor/uv?): {noteo}"}

    plain_root = _reveng_run_and_stage(plain, work, "ctl")
    obf_root = _reveng_run_and_stage(obf, work, "obf")
    if plain_root is None or obf_root is None:
        return {"outcome": "REFUSED", "rc": None, "seconds": 0, "blame": "launcher",
                "stdout": "", "stderr": "a binary did not stage; cannot compare"}

    plain_hits = _grep_tree(plain_root, RE_SECRET.encode())
    obf_hits = _grep_tree(obf_root, RE_SECRET.encode())
    if not plain_hits:
        return {"outcome": "REFUSED-UNRELATED", "rc": 0, "seconds": 0, "blame": "harness",
                "stdout": "", "stderr": (
                    "the CONTROL (plain) stage did not contain the literal, so this case "
                    "cannot prove obfuscation did anything — the control is broken")}
    if obf_hits:
        return {"outcome": "LEAKED", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": (
                    f"the plaintext literal survived obfuscation, present in the obfuscated "
                    f"stage: {obf_hits[:4]}")}
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} literal present in plain stage ({plain_hits[:2]}) and GONE "
                      f"from the obfuscated stage — --obfuscate did its job", "stderr": ""}


@case("reverse_engineer", "RAN",
      "The staged plaintext must not be readable by OTHER users on the box. It is owner-only "
      "by design (hardenDir strips group/other), which is a real protection on a shared "
      "host even though it does nothing against the user who runs the binary. The persona "
      "checks the mode bits of the staged tree.",
      inv="INV-SECRET-02",
      remedy="A LEAKED here means a staged file is group- or world-readable; check hardenDir "
             "and the umask handling in stage.nim. On a shared host this exposes the secret "
             "to every other account.",
      per_fixture=False, serial=True)
def the_staged_tree_is_not_readable_by_other_users(exe: Path, work: Path) -> dict:
    ok, out, note = _reveng_build(work, "perm")
    if not ok:
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"build failed: {note}"}
    root = _reveng_run_and_stage(out, work, "perm")
    if root is None:
        return {"outcome": "REFUSED", "rc": None, "seconds": 0, "blame": "launcher",
                "stdout": "", "stderr": "binary did not stage"}
    import stat as _stat
    # REACHABILITY, not raw bits. A 0644 file inside a 0700 directory is NOT exposed: another
    # user is blocked at the sealed directory and never reaches the file. The first version
    # flagged inner bits directly and reported a false LEAKED — the staged root and the cache
    # base are both 0700, which gates the whole tree (verified 2026-09-10). A file leaks only
    # if it is other-readable AND every ancestor directory up to the cache base is
    # other-traversable.
    base = root.parent            # <cache>/haru-pack, the per-user gate
    stop = base.parent            # the cache dir itself; do not walk above it

    def other_reachable(f: Path) -> bool:
        try:
            if not (f.stat().st_mode & _stat.S_IROTH):
                return False       # not other-readable: not a leak whatever the ancestors
        except OSError:
            return False
        d = f.parent
        while True:
            try:
                if not (d.stat().st_mode & _stat.S_IXOTH):
                    return False   # a sealed ancestor blocks the path
            except OSError:
                return False
            if d == base or d == stop or d.parent == d:
                return True        # reached the gate and every step was traversable
            d = d.parent

    leaked = [str(f.relative_to(root)) for f in root.rglob("*")
              if f.is_file() and other_reachable(f)]
    if leaked:
        return {"outcome": "LEAKED", "rc": 0, "seconds": 0, "blame": "launcher",
                "stdout": "", "stderr": (
                    f"{len(leaked)} staged file(s) are genuinely reachable by other users "
                    f"(other-readable, with an other-traversable path from the cache base): "
                    f"{leaked[:4]}")}
    # Confirm the gate is actually a gate, not an accident of this run.
    base_mode = base.stat().st_mode & 0o777
    gated = not (base.stat().st_mode & (_stat.S_IXOTH | _stat.S_IROTH))
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} staged tree sealed: cache base {base.name} is "
                      f"{oct(base_mode)} ({'owner-only gate' if gated else 'NOT gated'}); "
                      f"{sum(1 for _ in root.rglob('*'))} inner paths unreachable by others",
            "stderr": ""}

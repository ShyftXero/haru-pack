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

# Re-exported so `import busybody_hostile as H` still reaches everything it used to: the
# tokens a test greps for, the Evidence type, and the sandbox helpers.
from busybody_hostile_attacks import *            # noqa: F401,F403
from busybody_hostile_kit import *                # noqa: F401,F403
from busybody_hostile_attacks import (plant_build_backend, plant_bundle_step,
                                      plant_control_file_shadow, plant_dangling_symlink,
                                      plant_device_node, plant_index_redirect,
                                      plant_post_install, plant_symlink_loop,
                                      plant_symlinked_key, plant_windows_escape,
                                      verdict_build_backend, verdict_bundle_step,
                                      verdict_control_file_shadow,
                                      verdict_dangling_symlink, verdict_device_node,
                                      verdict_index_redirect, verdict_post_install,
                                      verdict_symlink_loop, verdict_symlinked_key,
                                      verdict_windows_escape)
from busybody_hostile_kit import BUILD_BACKEND, BUNDLE_STEP, Evidence, planted_home  # noqa: F401



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

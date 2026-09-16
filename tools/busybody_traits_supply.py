"""Traits about what a build PICKS UP and what it PROMISES.

    auditor     credential-shaped files planted where the payload builder will see them
    tourist     the artifact on a platform that is not its own
    archivist   a build that must be byte-reproducible

Split out of busybody_traits.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import os
import stat

from busybody_compose import trait

APP_OK = "BUSYBODY_OK"


# ================================================================================= auditor
# Credential-shaped files planted where the payload builder will see them. The assertion —
# grep the finished binary — lives in busybody.py; the planting composes.

AUDITOR_SECRETS = {
    ".env": "API_KEY=busybody_secret_dotenv_9a8b7c\n",
    ".envrc": "export TOKEN=busybody_secret_envrc_1f2e3d\n",
    "id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nbusybody_secret_idrsa_4c5d6e\n",
    "credentials.json": '{"key": "busybody_secret_credsjson_7a8b9c"}\n',
    "secrets.yaml": "password: busybody_secret_yaml_2b3c4d\n",
    "app.pem": "-----BEGIN CERTIFICATE-----\nbusybody_secret_pem_5e6f7a\n",
    ".aws/credentials": "[default]\naws_secret_access_key = busybody_secret_aws_8b9c0d\n",
    ".npmrc": "//registry.npmjs.org/:_authToken=busybody_secret_npmrc_3d4e5f\n",
}


@trait("auditor_plants_credentials", "build", "project",
       "Every credential shape the ignore list claims to cover, dropped in the project root "
       "as a real build directory accumulates them. The planted values are unique strings, "
       "so the finished binary can be grepped for each one.",
       inv="INV-PAYLOAD-01",
       fires=0.8)
def _au_plant(ctx):
    ctx.files.update(AUDITOR_SECRETS)


@trait("auditor_plants_a_git_history", "build", "project",
       "A .git directory holding a credential in a loose object. Excluding .git is about "
       "size for most people and about secrets for anyone who has committed one.",
       inv="INV-PAYLOAD-01",
       fires=0.7)
def _au_git(ctx):
    ctx.files[".git/config"] = (
        "[remote \"origin\"]\n"
        "\turl = https://user:busybody_secret_giturl_6f7a8b@example.com/x.git\n")
    ctx.files[".git/HEAD"] = "ref: refs/heads/main\n"


@trait("auditor_plants_a_venv_with_a_token", "build", "project",
       "A .venv containing a token, which is what a real working tree looks like. Excluded "
       "for size; the consequence of forgetting is a published credential.",
       inv="INV-PAYLOAD-01",
       fires=0.7)
def _au_venv(ctx):
    ctx.files[".venv/pyvenv.cfg"] = "home = /usr\n"
    ctx.files[".venv/pip.conf"] = (
        "[global]\nindex-url = https://x:busybody_secret_pipconf_9c0d1e@pypi.example/simple\n")


@trait("auditor_plants_a_secret_in_pycache", "build", "project",
       "A credential inside __pycache__. Excluded as build noise rather than as a secret, so "
       "it is the exclusion most likely to be relaxed by someone optimising a payload.",
       inv="INV-PAYLOAD-01",
       fires=0.6)
def _au_pycache(ctx):
    ctx.files["__pycache__/leak.cpython-312.pyc"] = (
        "\x00\x00\x00\x00busybody_secret_pycache_2e3f4a")


# ================================================================================= tourist
# The artifact on a platform that is not its own. The honest scope here is "fails cleanly":
# a real foreign run needs a real foreign machine.

@trait("tourist_runs_a_foreign_binary", "run", "proc",
       "Exec a binary built for another architecture. The kernel refuses with an exec format "
       "error; the requirement is that the harness and the launcher both report that as what "
       "it is rather than as a corrupt payload.",
       needs=("cross-built-artifact",), inv="INV-TIER-03")
def _tr_foreign(ctx):
    ctx.env["HARU_BUSYBODY_FOREIGN"] = "1"


@trait("tourist_wine", "run", "proc",
       "Run the Windows artifact under wine. Not Windows, but it exercises the PE loader and "
       "the overlay's survival of a real foreign toolchain.",
       needs=("wine",), inv="INV-TIER-03")
def _tr_wine(ctx):
    ctx.env["HARU_BUSYBODY_WINE"] = "1"


# ============================================================================== archivist
# Reproducibility. The comparison is a case in busybody.py; what composes is the condition
# under which reproducibility is claimed.

@trait("archivist_shifted_mtimes", "build", "project",
       "Every source file given a different mtime than the previous build would see. A "
       "payload that embeds mtimes is not reproducible, and a signed artifact nobody can "
       "reproduce is one nobody can audit.",
       inv="INV-BUILD-03",
       fires=0.8)
def _ar_mtimes(ctx):
    def touch(proj):
        for i, p in enumerate(sorted(proj.rglob("*"))):
            if p.is_file():
                os.utime(p, (1600000000 + i * 7, 1600000000 + i * 7))
    ctx.post.append(touch)


@trait("archivist_odd_permissions", "build", "project",
       "Mixed permission bits across the project. The payload must normalise them or two "
       "checkouts of one commit produce different binaries.",
       inv="INV-BUILD-03",
       fires=0.7)
def _ar_perms(ctx):
    def chmods(proj):
        modes = (0o644, 0o600, 0o755, 0o444)
        for i, p in enumerate(sorted(proj.rglob("*"))):
            if p.is_file():
                try:
                    p.chmod(modes[i % len(modes)] | stat.S_IRUSR)
                except OSError:
                    pass
    ctx.post.append(chmods)

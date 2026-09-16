#!/usr/bin/env bash
# Cut a haru-pack release: verify a commit, derive its version, tag it, push the tag.
#
#   ./scripts/cut-release.sh                  # verify, tag the current commit, and offer to push
#   ./scripts/cut-release.sh --dry-run        # do everything except write anything
#   ./scripts/cut-release.sh --check          # just run the release gate, tag nothing
#   ./scripts/cut-release.sh --no-self-build  # skip building the release binaries
#
# The version is NOT passed in — it is DERIVED from the commit being tagged: the HEAD committer date
# in UTC as a single 14-digit segment, YYYYMMDDHHMMSS (src/haru_pack/_version.py, the one formatter).
# The tag is vYYYYMMDDHHMMSS. Nothing to stamp or mistype; a release is fully determined by its
# commit. PyPI rejects the +g<hash> local segment, so the published version is the bare timestamp
# (a git checkout still shows the hash at runtime via `haru-pack version`).
#
# The gate packs haru-pack WITH haru-pack for linux-x86_64 and windows-x86_64, verifies each
# payload, smoke-runs what this host can run, and — once the tag is pushed — attaches them to
# the GitHub release. That is the project's own claim tested on the project itself; see
# scripts/self-build.sh. `--no-self-build` skips it and says so loudly.
#
# WHY THIS EXISTS
#
# Publishing is the one irreversible step in this repo: a yanked PyPI release is still a
# released filename. The gate below runs the full test suite and the invariant contract
# against the exact commit being tagged. It does not accept an assurance that they passed —
# it runs them. That distinction is the entire point (see INVARIANTS.md, "What this file
# does and does not prove").
#
# Adopted from lotek's scripts/cut-release-tag.sh, which refuses to tag without
# --ack-tests and --ack-invariants bound to a specific sha. haru-pack executes the checks
# directly instead of recording an acknowledgement, because it can: the suite runs in about
# a minute on a laptop.
#
# NO AI REQUIRED. Every step is a shell command you can run by hand. If this script breaks,
# read it top to bottom and run the pieces yourself; nothing here is clever.
#
# WHAT IT WILL NOT DO
#   - push to main (it pushes a tag, nothing else)
#   - force-push anything
#   - tag a dirty tree, a non-main branch, or a commit that is not on the remote
#   - publish to PyPI (the publish workflow does that, on the tag, after CI passes again)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MAIN_BRANCH="main"

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m%s\033[0m\n' "$*"; }
die()   { red "cut-release: $*"; exit 1; }

usage() {
    sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---------------------------------------------------------------- arguments
DRY_RUN=0
CHECK_ONLY=0
SELF_BUILD=1
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --check)   CHECK_ONLY=1 ;;
        --no-self-build) SELF_BUILD=0 ;;
        -h|--help) usage 0 ;;
        -*)        die "unknown flag: $arg (try --help)" ;;
        *)         die "unexpected argument '$arg'. The version is derived from the commit
(HEAD committer date, YYYYMMDDHHMMSS); do not pass one. See --help." ;;
    esac
done

# ---------------------------------------------------------------- repo state
info "== repo state =="
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
SHA="$(git rev-parse HEAD)"
SHORT="$(git rev-parse --short HEAD)"
echo "branch : $BRANCH"
echo "commit : $SHORT"

# The version is DERIVED from the commit, not passed in: the HEAD committer date (UTC) as a single
# 14-digit segment. src/haru_pack/_version.py is the one formatter — the release tag, the wheel
# metadata (hatch_build.py) and the runtime `haru-pack version` all route through it. The bare form
# (no +g<hash>) goes to the tag and PyPI, which refuses local versions.
VERSION="$(python3 - "$REPO_ROOT" <<'PYEOF'
import importlib.util, sys
from pathlib import Path
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("_hv", root / "src" / "haru_pack" / "_version.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
print(mod.git_build_id(root, with_hash=False) or "")
PYEOF
)"
[ -n "$VERSION" ] || die "could not derive a version from HEAD (is this a git checkout?)"
TAG="v${VERSION}"
echo "version: $VERSION (derived)"
echo "tag    : $TAG"

# --check is a pure verification mode: it is meant to be runnable on a PR branch, before
# the merge that would make a release possible. Only the tagging path demands a clean main.
if [ "$CHECK_ONLY" -eq 0 ]; then
    [ "$BRANCH" = "$MAIN_BRANCH" ] || die "on '$BRANCH', not '$MAIN_BRANCH'.
Releases are stamped on a commit that is already merged to $MAIN_BRANCH.
(To run the gate here without tagging: ./scripts/cut-release.sh --check)"

    git diff --quiet && git diff --cached --quiet \
        || die "working tree is dirty. Commit or stash first — a release must be reproducible
from the tagged commit alone, and uncommitted changes are not in it."
fi

if [ -n "$(git ls-files --others --exclude-standard)" ]; then
    red "note: untracked files present (they will NOT be in the release):"
    git ls-files --others --exclude-standard | sed 's/^/  /' >&2
fi

if [ "$CHECK_ONLY" -eq 0 ]; then
    git fetch --quiet origin "$MAIN_BRANCH" 2>/dev/null || red "note: could not fetch origin"
    if git rev-parse --verify --quiet "origin/$MAIN_BRANCH" >/dev/null; then
        git merge-base --is-ancestor HEAD "origin/$MAIN_BRANCH" \
            || die "HEAD is not on origin/$MAIN_BRANCH. Push and merge it first —
a tag pointing at a commit nobody else has is not a release."
    fi
fi

if [ "$CHECK_ONLY" -eq 0 ] && git rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null; then
    die "tag $TAG already exists — this commit's timestamp is already released. Releases are
immutable and the version is derived from the commit, so to cut another you need a new commit
(the timestamp advances with it)."
fi

# ---------------------------------------------------------------- the gate
info ""
info "== release gate (this RUNS the checks; it does not take your word for it) =="

PY=".venv/bin/python"
[ -x "$PY" ] || PY="python3"
# Lint through the PINNED ruff from [dependency-groups] dev, not through whatever `ruff` is
# on PATH. This gate used to do the latter and passed, while CI — which downloaded a newer
# ruff — failed on the same commit for days. There were three different ruff versions on the
# maintainer's machine when that was diagnosed (INV-CI-01).
echo "-- lint (pinned ruff, same pin CI uses)"
command -v uv >/dev/null 2>&1 || die "uv is not on PATH, so the pinned linter cannot run.
The gate will not fall back to an unpinned \`ruff\` — that is exactly the drift that kept CI
red while this gate reported success. Install uv and re-run."
RUFF_PIN="$(sed -n 's/.*"ruff==\([0-9.]*\)".*/\1/p' pyproject.toml | head -1)"
[ -n "$RUFF_PIN" ] || die "no exact \`ruff==\` pin in pyproject.toml [dependency-groups] dev.
That pin is the single source of truth for both this gate and CI (INV-CI-01); without it the
two lint different things, which is how CI stayed red for a week while this said 'ok'."
# `uvx`, not `uv run --group dev`: the latter installs into the project environment, so the
# linter would mutate the env the tests are about to run in.
uvx --quiet "ruff@$RUFF_PIN" check . \
    || die "ruff $RUFF_PIN failed. Fix it; do not tag a release you would not merge."
echo "   ok (ruff $RUFF_PIN)"

# pytest's default basetemp lives at /tmp/pytest-of-$USER, which is shared and can end up
# owned by another uid (containers, CI runners, a parallel job). pytest then refuses to run
# at all — an infrastructure failure that looks exactly like a test failure. Give the gate
# its own scratch directory so a broken /tmp cannot be mistaken for a broken release.
GATE_TMP="$(mktemp -d)"
trap 'rm -rf "$GATE_TMP"' EXIT
PYTEST=("$PY" -m pytest -o addopts= --basetemp="$GATE_TMP/pt" -p no:cacheprovider -q)

echo "-- invariant contract (pytest -m invariant)"
"${PYTEST[@]}" -m invariant \
    || die "the invariant contract failed at $SHORT.

If the failures name INV- ids, that means an 'active' invariant in INVARIANTS.md has no
claiming test, a 'proposed' one has acquired one, or a test cites an invariant that does not
exist. Reconcile INVARIANTS.md with the suite before tagging, and do not relax the contract
to get a release out.

If instead the failures are collection or OSErrors, the suite could not RUN — that is an
environment problem, not a release blocker. Fix the environment and re-run."

echo "-- full suite"
"${PYTEST[@]}" \
    || die "tests failed at $SHORT. Not tagging."

echo "-- launcher compiles"
if command -v nim >/dev/null 2>&1; then
    nim c -d:release --nimcache:"$GATE_TMP/nimcache" --out:"$GATE_TMP/launcher" \
        src/haru_pack/launcher/main.nim >/dev/null \
        || die "the Nim launcher does not compile at $SHORT.
Every shipped binary embeds it; a release that cannot build it is not a release."
    echo "   ok"
else
    red "note: nim not on PATH — launcher NOT compile-checked.
This is a real gap in the gate, not a formality. Install Nim (haru-pack bootstrap) and
re-run before tagging anything you intend to publish."
fi

echo "-- self-build (haru-pack packs haru-pack, linux + windows)"
SELF_OUT="$REPO_ROOT/dist/self"
if [ "$SELF_BUILD" -eq 1 ]; then
    # Run BEFORE tagging on purpose. These artifacts are part of the release, so if the tool
    # cannot pack itself we want to know while there is still no tag — a pushed tag with no
    # binaries is a release that has to be explained.
    rm -rf "$SELF_OUT"
    ./scripts/self-build.sh --out "$SELF_OUT" \
        || die "haru-pack could not pack itself at $SHORT.

That is the demonstration failing, not a packaging detail: this project's claim is that you
point it at a Python project and get a binary, and it is a Python project. Fix it before
tagging. To tag anyway without artifacts (and know that you are doing it):
    ./scripts/cut-release.sh $VERSION --no-self-build"
    echo "   ok"
else
    red "note: --no-self-build given; release artifacts will NOT be built or attached.
The published release will be PyPI-only, and nobody without Python can install it."
fi

green ""
green "gate passed at $SHORT"

if [ "$CHECK_ONLY" -eq 1 ]; then
    info "--check given; stopping here. Nothing was written."
    exit 0
fi

# ---------------------------------------------------------------- tag
# Nothing is stamped: the version is derived from the commit (hatch_build.py bakes it into the wheel
# at build time; _version.py computes it at runtime). So there is no version-bump commit — the tag
# alone marks the release, and it points at a commit that is already on origin/main (checked above).

info ""
info "== release plan =="
echo "version : $VERSION (derived from the commit; nothing to stamp)"
echo "tag     : $TAG"
echo "commit  : $SHORT ($(git log -1 --format=%s))"
echo ""
echo "this will:"
echo "  1. tag $TAG at $SHORT (annotated)"
echo "  2. ask before pushing the tag (pushing the tag triggers PyPI publish)"

if [ "$DRY_RUN" -eq 1 ]; then
    info ""
    info "--dry-run given; stopping here. Nothing was written."
    exit 0
fi

printf '\nproceed? [y/N] '
read -r reply
case "$reply" in [yY]*) ;; *) die "aborted by user; nothing written." ;; esac

git tag -a "$TAG" -m "haru-pack $VERSION"
green "tagged $TAG at $(git rev-parse --short HEAD)"

printf '\npush %s to origin? [y/N] ' "$TAG"
read -r reply
case "$reply" in
    [yY]*)
        git push origin "$TAG"
        green "pushed. The publish workflow runs CI again on the tag, then uploads to PyPI."

        # The self-built binaries go to GitHub Releases, not PyPI — they exist for people
        # who have no Python, and PyPI cannot reach that audience (docs/PUBLISHING.md).
        if [ "$SELF_BUILD" -eq 1 ] && [ -d "$SELF_OUT" ]; then
            if command -v gh >/dev/null 2>&1; then
                info ""
                info "== attaching self-built binaries to the GitHub release =="
                if gh release view "$TAG" >/dev/null 2>&1; then
                    gh release upload "$TAG" "$SELF_OUT"/* --clobber \
                        && green "uploaded $(ls -1 "$SELF_OUT" | wc -l) asset(s) to $TAG"
                else
                    gh release create "$TAG" "$SELF_OUT"/* \
                        --title "haru-pack $VERSION" \
                        --notes "Built by haru-pack packing itself — see scripts/self-build.sh.

\`haru-pack-$VERSION-linux-x86_64\` and \`haru-pack-$VERSION-windows-x86_64.exe\` need no
Python and no uv on the machine that runs them: the launcher stages its own on first run.
Verify a download against \`SHA256SUMS\`.

Python users want \`pip install haru-pack\` or \`uv tool install haru-pack\` instead — same
tool, importable, one small wheel." \
                        && green "created release $TAG with $(ls -1 "$SELF_OUT" | wc -l) asset(s)"
                fi
            else
                info "gh not installed; attach the binaries by hand:"
                echo "    gh release create $TAG $SELF_OUT/* --title 'haru-pack $VERSION'"
            fi
        fi
        ;;
    *)
        info "not pushed. When ready:"
        echo "    git push origin $TAG"
        info "to undo locally:"
        echo "    git tag -d $TAG"
        ;;
esac

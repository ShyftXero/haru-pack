#!/usr/bin/env bash
# Cut a haru-pack release: verify a commit, stamp its version, tag it, push the tag.
#
#   ./scripts/cut-release.sh 0.2.0            # verify, stamp, tag, and offer to push
#   ./scripts/cut-release.sh 0.2.0 --dry-run  # do everything except write anything
#   ./scripts/cut-release.sh --check          # just run the release gate, tag nothing
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

VERSION_FILE="src/haru_pack/__init__.py"
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
VERSION=""
DRY_RUN=0
CHECK_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --check)   CHECK_ONLY=1 ;;
        -h|--help) usage 0 ;;
        -*)        die "unknown flag: $arg (try --help)" ;;
        *)         [ -n "$VERSION" ] && die "version given twice: $VERSION and $arg"
                   VERSION="$arg" ;;
    esac
done
[ "$CHECK_ONLY" -eq 0 ] && [ -z "$VERSION" ] && usage 1

if [ -n "$VERSION" ]; then
    # PEP 440 / semver-ish. Deliberately strict: a typo'd version becomes a permanent
    # filename on PyPI.
    printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([ab]|rc)?[0-9]*$' \
        || die "version '$VERSION' is not N.N.N (optionally with a/b/rc suffix)"
fi

TAG="v${VERSION}"

# ---------------------------------------------------------------- repo state
info "== repo state =="
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
SHA="$(git rev-parse HEAD)"
SHORT="$(git rev-parse --short HEAD)"
echo "branch : $BRANCH"
echo "commit : $SHORT"

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

if [ -n "$VERSION" ] && git rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null; then
    die "tag $TAG already exists. Releases are immutable; pick the next version."
fi

# ---------------------------------------------------------------- the gate
info ""
info "== release gate (this RUNS the checks; it does not take your word for it) =="

PY=".venv/bin/python"
[ -x "$PY" ] || PY="python3"
command -v ruff >/dev/null 2>&1 && RUFF="ruff" || RUFF=""

if [ -n "$RUFF" ]; then
    echo "-- lint"
    $RUFF check . || die "ruff failed. Fix it; do not tag a release you would not merge."
else
    red "note: ruff not on PATH, skipping lint"
fi

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

green ""
green "gate passed at $SHORT"

if [ "$CHECK_ONLY" -eq 1 ]; then
    info "--check given; stopping here. Nothing was written."
    exit 0
fi

# ---------------------------------------------------------------- stamp + tag
CURRENT="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$VERSION_FILE")"
[ -n "$CURRENT" ] || die "could not read __version__ from $VERSION_FILE"

info ""
info "== release plan =="
echo "version : $CURRENT -> $VERSION"
echo "tag     : $TAG"
echo "commit  : $SHORT ($(git log -1 --format=%s))"
echo ""
echo "this will:"
echo "  1. set __version__ = \"$VERSION\" in $VERSION_FILE"
echo "  2. commit that as 'release: $VERSION'"
echo "  3. tag $TAG"
echo "  4. ask before pushing the tag (pushing the tag triggers PyPI publish)"

if [ "$DRY_RUN" -eq 1 ]; then
    info ""
    info "--dry-run given; stopping here. Nothing was written."
    exit 0
fi

printf '\nproceed? [y/N] '
read -r reply
case "$reply" in [yY]*) ;; *) die "aborted by user; nothing written." ;; esac

if [ "$CURRENT" != "$VERSION" ]; then
    tmp="$(mktemp)"
    sed "s/^__version__ = \".*\"$/__version__ = \"$VERSION\"/" "$VERSION_FILE" > "$tmp"
    mv "$tmp" "$VERSION_FILE"
    grep -q "^__version__ = \"$VERSION\"$" "$VERSION_FILE" \
        || die "failed to write the version into $VERSION_FILE — check it by hand"
    git add "$VERSION_FILE"
    git commit -q -m "release: $VERSION"
    green "committed version bump"
else
    info "version already $VERSION; no bump commit needed"
fi

git tag -a "$TAG" -m "haru-pack $VERSION"
green "tagged $TAG at $(git rev-parse --short HEAD)"

printf '\npush %s and the release commit to origin? [y/N] ' "$TAG"
read -r reply
case "$reply" in
    [yY]*)
        git push origin "$MAIN_BRANCH"
        git push origin "$TAG"
        green "pushed. The publish workflow runs CI again on the tag, then uploads to PyPI."
        ;;
    *)
        info "not pushed. When ready:"
        echo "    git push origin $MAIN_BRANCH && git push origin $TAG"
        info "to undo locally:"
        echo "    git tag -d $TAG && git reset --hard HEAD~1"
        ;;
esac

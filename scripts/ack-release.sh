#!/usr/bin/env bash
# Run the release gate and record the result AGAINST THE EXACT SHA it ran on.
#
# This exists so `.claude/hooks/gate.py` has something to check that is not a promise.
# "The tests passed" is a claim about bytes; a claim about a branch is a different and much
# weaker claim, and the difference is the whole point of pinning the ack to a sha.
#
# `./scripts/cut-release.sh` runs the same gate and tags for you, and is the normal path.
# Use this one when you are doing something the script does not cover and still need the
# tag gate to be satisfiable.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

ACK=".claude/release-ack.json"
SHA="$(git rev-parse HEAD)"
NO_SELF_BUILD=0
[[ "${1:-}" == "--no-self-build" ]] && NO_SELF_BUILD=1

# A dirty tree means the bytes on disk are not the bytes at SHA, so an ack pinned to SHA
# would be false the moment it was written.
if [[ -n "$(git status --porcelain)" ]]; then
    echo "ack-release: the working tree is dirty." >&2
    echo "  An ack is pinned to a commit sha. With uncommitted changes, the gate would run" >&2
    echo "  on bytes that sha does not name, and the ack would be a lie from the start." >&2
    echo "  Commit or stash first." >&2
    exit 1
fi

run() {
    echo "== $*"
    if ! "$@"; then
        echo
        echo "ack-release: FAILED at: $*" >&2
        printf '{"ok": false, "sha": "%s", "failed": "%s", "at": %s}\n' \
            "$SHA" "$*" "$(date +%s)" > "$ACK"
        echo "  Recorded the failure in $ACK. The tag gate stays closed." >&2
        exit 1
    fi
}

mkdir -p "$(dirname "$ACK")"

run uv run --group dev ruff check .
if [[ "$NO_SELF_BUILD" == "0" ]]; then
    run ./scripts/self-build.sh
else
    echo "== skipping self-build (--no-self-build)"
fi
run uv run pytest -m invariant

printf '{"ok": true, "sha": "%s", "self_build": %s, "at": %s}\n' \
    "$SHA" "$([[ "$NO_SELF_BUILD" == "0" ]] && echo true || echo false)" "$(date +%s)" \
    > "$ACK"

echo
echo "ack-release: gate passed on ${SHA:0:12}; wrote $ACK"
[[ "$NO_SELF_BUILD" == "1" ]] && echo "  NOTE: recorded with self_build=false. A real release must not skip it (INV-CI-02)."
exit 0

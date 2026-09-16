#!/usr/bin/env bash
# Pack haru-pack with haru-pack, for every release target, and check the results.
#
#   ./scripts/self-build.sh                       # dist/self/ , linux + windows x86_64
#   ./scripts/self-build.sh --out /tmp/art        # somewhere else
#   ./scripts/self-build.sh --targets linux-x86_64
#
# Why this exists, beyond producing download artifacts:
#
#   1. It is the honest demonstration. haru-pack's pitch is "point it at a Python project
#      and get a binary". haru-pack IS a Python project — one with a native dependency
#      (`cryptography`), a console-script entrypoint, and package data that must survive
#      into the payload. If the tool cannot pack itself, the pitch is not true, and running
#      this every release means we find that out before a user does.
#   2. It serves the audience PyPI cannot reach. `uv tool install haru-pack` needs uv, which
#      needs Python. These binaries need neither. See docs/PUBLISHING.md, "Why not ship the
#      packed binary through PyPI".
#
# Deliberately the DEFAULT tier, not --thick: the artifact stays ~15 MB and the launcher
# fetches Python + deps on first run. A thick self-build would be ~90 MB per target and
# would need Windows wheels for `cryptography` resolved from Linux; that is a separate
# question from "does the tool work on itself".
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m%s\033[0m\n' "$*"; }
die()   { red "self-build: $*"; exit 1; }

OUT="$ROOT/dist/self"
TARGETS="linux-x86_64 windows-x86_64"
# Match the project's own default rather than hardcoding a number that drifts. haru-pack
# declares `requires-python = ">=3.9"`, so discovery would resolve 3.9 — which has no pinned
# interpreter and refuses (INV-SUPPLY-01). Naming the default explicitly is what keeps this
# working when the default moves; it moved 3.12 -> 3.13 on 2026-09-10.
#
# ASKED OF THE CODE, not scraped out of it. The first version sed'd build.py for a line
# ending in `or "N.N"`, which matches any such line and would have silently built a release
# against the wrong interpreter if that source moved (adversarial review 2026-09-11).
PYVER="$(uv run --quiet python -c 'from haru_pack.build import DEFAULT_PYTHON; print(DEFAULT_PYTHON)' 2>/dev/null || true)"
[ -n "$PYVER" ] || die "could not read haru_pack.build.DEFAULT_PYTHON.
The release artifacts must be built against the interpreter version this project actually
defaults to; guessing one is how a release ships against the wrong Python."

while [ $# -gt 0 ]; do
    case "$1" in
        --out)     OUT="$2"; shift 2 ;;
        --targets) TARGETS="$2"; shift 2 ;;
        --python)  PYVER="$2"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *)         die "unknown argument: $1" ;;
    esac
done

# ASKED OF THE CODE, not scraped: the version is git-derived (src/haru_pack/_version.py), so there
# is no static line to sed. The bare 14-digit form (no +g<hash>) names the artifact, matching the
# release tag and the PyPI version.
VERSION="$(uv run --quiet python -c 'import pathlib; from haru_pack._version import git_build_id; print(git_build_id(pathlib.Path("'"$ROOT"'"), with_hash=False) or "")' 2>/dev/null || true)"
[ -n "$VERSION" ] || die "could not derive the version from git (haru_pack._version.git_build_id).
Release artifacts are named for the commit being released; guessing a version is how a release
ships mislabelled."

# Use the haru-pack from THIS tree, not one on PATH — the point is to demonstrate the
# commit being released, and a stale global install would quietly demonstrate something else.
HARU=(uv run --quiet haru-pack)
command -v uv >/dev/null 2>&1 || die "uv is not on PATH; cannot run this tree's haru-pack"

command -v nim >/dev/null 2>&1 \
    || die "nim is not on PATH — the launcher cannot be compiled, so nothing can be packed.
Run \`haru-pack bootstrap\` first."

# A release gate that can succeed having built nothing is worse than no gate: it reports
# "ok", cut-release.sh believes the exit status, and `gh release create` publishes a
# SHA256SUMS describing an empty set. `--targets ""` did exactly that — `sha256sum` with no
# arguments read stdin and hashed nothing (adversarial review 2026-09-11). So the target
# list is validated before any work, and the artifact count is checked after it.
[ -n "${TARGETS// /}" ] || die "no targets to build.
\`--targets\` was empty, which would produce a release with no binaries and still exit 0."
for tgt in $TARGETS; do
    printf '%s' "$tgt" | grep -Eq '^[a-z0-9]+-[a-z0-9_]+$' \
        || die "target '$tgt' is not of the form <os>-<arch> (e.g. linux-x86_64).
Refusing rather than asking haru-pack to interpret it, because a typo here silently means a
release built for something other than what was intended."
done

mkdir -p "$OUT"
info "== packing haru-pack $VERSION with haru-pack =="
echo "targets : $TARGETS"
echo "out     : $OUT"
echo ""

BUILT=()
for tgt in $TARGETS; do
    case "$tgt" in
        windows*) name="haru-pack-${VERSION}-${tgt}.exe" ;;
        *)        name="haru-pack-${VERSION}-${tgt}" ;;
    esac
    dest="$OUT/$name"
    echo "-- $tgt"
    # `-e haru-pack` is REQUIRED and not a nicety: this project declares two console
    # scripts (haru-pack and haru, INV-PKG-01), so discovery correctly refuses to guess
    # between them. Naming one is how the ambiguity is resolved, not a workaround.
    "${HARU[@]}" build . -e haru-pack --target "$tgt" --python "$PYVER" -o "$dest" \
        >/dev/null || die "packing for $tgt failed"

    # Every artifact gets its payload integrity checked before it is offered to anyone.
    "${HARU[@]}" verify "$dest" >/dev/null \
        || die "$name failed payload verification — do not publish it"
    sz=$(( $(wc -c < "$dest") / 1000000 ))
    green "   built $name (${sz} MB), payload verified"
    BUILT+=("$name")
done

# ---------------------------------------------------------------- smoke checks
info ""
info "== smoke checks =="

host_os="$(uname -s)"; host_arch="$(uname -m)"
for name in "${BUILT[@]}"; do
    path="$OUT/$name"
    case "$name" in
        *windows*.exe)
            if command -v wine >/dev/null 2>&1; then
                # Known and accepted: wine cannot create the junctions uv wants for its
                # Python install ("Failed to create Python minor version link directory,
                # os error 50"). Reaching THAT error is still a real result — it proves the
                # launcher staged, expanded the XZ-compressed uv, and executed it as a
                # Windows binary. A full first run needs real Windows.
                out="$(WINEDEBUG=-all timeout 600 wine "$path" version 2>&1 || true)"
                if printf '%s' "$out" | grep -q "haru-pack $VERSION"; then
                    green "   $name: ran under wine and reported $VERSION"
                elif printf '%s' "$out" | grep -qi "minor version link\|os error 50"; then
                    info  "   $name: launcher + bundled uv executed under wine; uv could not"
                    info  "     install Python because wine lacks the required links. Expected;"
                    info  "     not a haru-pack failure. Full run needs real Windows."
                else
                    red   "   $name: unexpected output under wine:"
                    printf '%s\n' "$out" | tail -5 >&2
                    die "refusing to publish a Windows artifact that failed in an unknown way"
                fi
            else
                info "   $name: wine not installed, not smoke-tested (PE + payload verified)"
            fi
            ;;
        *linux-x86_64)
            if [ "$host_os" = "Linux" ] && [ "$host_arch" = "x86_64" ]; then
                got="$(timeout 900 "$path" version 2>&1 | tail -1)"
                printf '%s' "$got" | grep -q "haru-pack $VERSION" \
                    || die "$name ran but reported '$got', not haru-pack $VERSION"
                green "   $name: ran and reported $VERSION"
            else
                info "   $name: not this host ($host_os/$host_arch), not smoke-tested"
            fi
            ;;
        *)
            info "   $name: no smoke test for this target on this host"
            ;;
    esac
done

# ---------------------------------------------------------------- checksums
# The count is asserted, not assumed: this is the last chance to notice that the loop above
# produced nothing, and `sha256sum` with an empty argument list reads STDIN rather than
# failing, which is what made the empty case look successful.
[ "${#BUILT[@]}" -gt 0 ] || die "built 0 artifacts — nothing to publish.
The gate must not report success here; a release whose only asset is a checksum file for an
empty set is worse than a failed build."
( cd "$OUT" && sha256sum -- "${BUILT[@]}" > SHA256SUMS )
info ""
info "== artifacts =="
( cd "$OUT" && ls -la "${BUILT[@]}" SHA256SUMS && echo "" && cat SHA256SUMS )
green ""
green "self-build ok: ${#BUILT[@]} artifact(s) in $OUT"

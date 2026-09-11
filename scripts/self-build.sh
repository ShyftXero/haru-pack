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
VERSION_FILE="src/haru_pack/__init__.py"

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m%s\033[0m\n' "$*"; }
die()   { red "self-build: $*"; exit 1; }

OUT="$ROOT/dist/self"
TARGETS="linux-x86_64 windows-x86_64"
PYVER="3.12"

while [ $# -gt 0 ]; do
    case "$1" in
        --out)     OUT="$2"; shift 2 ;;
        --targets) TARGETS="$2"; shift 2 ;;
        --python)  PYVER="$2"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *)         die "unknown argument: $1" ;;
    esac
done

VERSION="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$VERSION_FILE")"
[ -n "$VERSION" ] || die "could not read __version__ from $VERSION_FILE"

# Use the haru-pack from THIS tree, not one on PATH — the point is to demonstrate the
# commit being released, and a stale global install would quietly demonstrate something else.
HARU=(uv run --quiet haru-pack)
command -v uv >/dev/null 2>&1 || die "uv is not on PATH; cannot run this tree's haru-pack"

command -v nim >/dev/null 2>&1 \
    || die "nim is not on PATH — the launcher cannot be compiled, so nothing can be packed.
Run \`haru-pack bootstrap\` first."

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
( cd "$OUT" && sha256sum "${BUILT[@]}" > SHA256SUMS )
info ""
info "== artifacts =="
( cd "$OUT" && ls -la "${BUILT[@]}" SHA256SUMS && echo "" && cat SHA256SUMS )
green ""
green "self-build ok: ${#BUILT[@]} artifact(s) in $OUT"

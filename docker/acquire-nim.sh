#!/bin/sh
# Get a Nim onto PATH, by whichever route the caller allows. Sourced by flex.Dockerfile.
#
#   acquire-nim.sh <pins.toml> <prefix-dir> <mode>
#
# MODES — the escape hatch. A user who wants to avoid one of these paths must be able to say
# so, rather than discovering after forty minutes which one the image chose for them.
#
#   auto     pinned binary, then compile from pinned source. The default.
#   binary   pinned binary only. FAILS rather than quietly compiling for an hour.
#   source   compile from the pinned source. Never fetches a binary this project published.
#   system   use the nim already on PATH. Fetches and compiles nothing.
#
# `binary` and `source` exist for opposite reasons and both are legitimate. Someone on a slow
# arm64 box wants `binary` and would rather fail than wait. Someone who declines to execute a
# compiler binary built by this project wants `source` and would rather wait than trust it.
# `auto` picks for whoever has no opinion, and says out loud which one it took.
set -eu

PINS="$1"
PREFIX="$2"
MODE="${3:-auto}"

want_binary=no
want_source=no
case "$MODE" in
    auto)   want_binary=yes; want_source=yes ;;
    binary) want_binary=yes ;;
    source) want_source=yes ;;
    system)
        # `command -v` rather than trusting a path: this mode's whole promise is that we
        # install nothing, so the only honest check is whether it is genuinely already there.
        if command -v nim >/dev/null 2>&1; then
            echo "acquire-nim: NIM_FROM=system — using $(command -v nim)"
            exit 0
        fi
        echo "acquire-nim: NIM_FROM=system, but no nim is on PATH. This mode installs" >&2
        echo "  nothing by design. Provide a nim, or use NIM_FROM=auto." >&2
        exit 1 ;;
    *)
        echo "acquire-nim: unknown NIM_FROM=$MODE (want auto|binary|source|system)" >&2
        exit 2 ;;
esac

if [ "$want_binary" = yes ]; then
    set +e
    out="$(python3 /tmp/install-nim-binary.py "$PINS" "$PREFIX")"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        echo "acquire-nim: installed the pinned prebuilt nim"
        ln -sf "$out/bin/nim" /usr/local/bin/nim
        ln -sf "$out/bin/nimble" /usr/local/bin/nimble 2>/dev/null || true
        exit 0
    fi
    # 3 means "nothing pinned for this platform, or it could not be fetched" — a gap, which
    # `auto` is allowed to route around. Any other code means a pinned artifact was WRONG,
    # and falling through to a source build would erase the finding.
    if [ "$rc" -ne 3 ]; then
        echo "acquire-nim: refusing to fall back — the pinned binary failed verification" >&2
        exit "$rc"
    fi
    if [ "$want_source" != yes ]; then
        echo "acquire-nim: NIM_FROM=binary, but no usable pinned binary for this platform." >&2
        echo "  Not compiling: you asked for a binary, and an hour-long bootstrap is not" >&2
        echo "  a smaller surprise than this error. Use NIM_FROM=auto to allow it." >&2
        exit 1
    fi
    echo "acquire-nim: no pinned binary for this platform — compiling from pinned source"
fi

# Source build. `build.sh`, never `build_all.sh`: the latter clones csources from git, which
# would put an unpinned fetch in the middle of a verified chain. The tarball already carries
# the prebuilt C the bootstrap needs.
src="$(python3 /tmp/install-nim-source.py "$PINS" "$PREFIX")"
cd "$src"
sh build.sh
./bin/nim c --skipUserCfg --skipParentCfg --hints:off koch
./koch boot -d:release --skipUserCfg --skipParentCfg --hints:off
./koch tools --skipUserCfg --skipParentCfg --hints:off
ln -sf "$src/bin/nim" /usr/local/bin/nim
ln -sf "$src/bin/nimble" /usr/local/bin/nimble
echo "acquire-nim: built nim from pinned source at $src"

# The box the flex and exam harnesses build and run stranger code in.
#
#   docker build -f docker/flex.Dockerfile -t haru-pack-flex:<tag> .
#
# `tools/sandbox.py` builds this for you and tags it with a hash of this file plus
# `src/haru_pack/pins.toml`, so bumping a pin rebuilds the image and a stale one is never
# silently reused. See docs/adr/0005-sandboxed-flex-and-exam-harnesses.md.
#
# WHAT GOES IN HERE AND WHAT DOES NOT
#
# In: the TOOLCHAIN — Nim, zig, uv, a Python. Those are slow to acquire and identical for
# every package in a run, so baking them is the difference between a 25-package matrix that
# downloads a toolchain once and one that downloads it 25 times.
#
# Not in: haru-pack's own source. The harness tests the WORKING TREE, so the repository is
# bind-mounted read-only at /src at run time and PYTHONPATH points at it. A copy baked into
# the image would mean flex quietly testing whatever the tree looked like when the image was
# last built, which is the kind of stale result that reads as a pass.
#
# ARCHITECTURE: linux/amd64.
# Not a preference — `haru_pack.toolchain` documents that choosenim publishes binaries for
# linux x86_64, macOS x86_64/arm64 and Windows, and NOTHING for linux aarch64. On an arm64
# host Nim has to be built from source, which is a different (and much slower) Dockerfile
# than this one. Running flex on the arm64 box needs that work done first.

FROM debian:12-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

# curl + ca-certificates: choosenim and zig are fetched over TLS.
# xz-utils: the launcher's payload compression and zig's tarballs.
# git: uv resolves VCS dependencies for some packages in the flex matrix.
# build-essential: Nim's own bootstrap compiles C. `--cc zig` covers haru-pack's LAUNCHER
#   builds, but choosenim still needs a working host cc to install Nim itself.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git xz-utils build-essential \
      python3 python3-venv python3-pip \
 && rm -rf /var/lib/apt/lists/*

# One place for everything baked, readable by whatever uid the harness runs us as.
# HOME and XDG_DATA_HOME must NOT be under /cache: /cache is a volume at run time and would
# shadow the toolchain this image exists to carry.
ENV HARU_ROOT=/opt/haru \
    HOME=/opt/haru \
    XDG_DATA_HOME=/opt/haru/data \
    XDG_CACHE_HOME=/opt/haru/buildcache \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN mkdir -p /opt/haru/data /opt/haru/buildcache /w /cache

# haru-pack, installed for its DEPENDENCIES and console scripts. The source is replaced at
# run time by the read-only /src mount (see PYTHONPATH below); this layer exists so typer,
# rich, cryptography et al. are present and so `haru-pack` is on PATH.
COPY pyproject.toml README.md /tmp/pkg/
COPY src /tmp/pkg/src
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir /tmp/pkg

# uv, at the digest pins.toml pins (INV-SUPPLY-01). A thick build shells out to `uv sync`,
# so it has to be on PATH. Deliberately NOT the upstream curl|sh installer — see
# docker/install-uv.py for why a second acquisition path is the thing being avoided.
COPY docker/install-uv.py /tmp/
RUN python3 /tmp/install-uv.py /tmp/pkg/src/haru_pack/pins.toml /usr/local/bin

# Nim (choosenim, digest-pinned) and zig (digest-pinned), through haru-pack's OWN acquisition
# path rather than a hand-written apt/curl layer here. Same reason as uv: one audited path.
RUN haru-pack bootstrap --minimal --yes
RUN python3 -c "import sys; sys.path.insert(0, '/tmp/pkg/src'); \
from haru_pack import toolchain; print(toolchain.install_zig())"

# The harness runs as the invoking user (`-u uid:gid`), who owns none of the above, so every
# baked path has to be readable and every baked directory traversable by that uid.
#
# /opt/haru is world-WRITABLE, not just readable: it is HOME at run time (nimble's package
# tree is under it), and Nim and nimble both write there during a build. Writes land in the
# container's own ephemeral layer and are destroyed by `--rm`, so this does not let one
# package's code reach the next one's toolchain — only the /cache volume persists, and the
# run phase mounts that read-only.
#
# /cache and /w are mount points, made world-writable so the run's uid can use them.
RUN chmod -R a+rwX /opt/haru \
 && chmod -R a+rX /opt/venv /usr/local/bin \
 && chmod 1777 /cache /w \
 && rm -rf /tmp/pkg /tmp/install-uv.py

# The working tree wins over the copy installed above. This is what makes flex test the code
# you are editing rather than the code the image was built from.
ENV PYTHONPATH=/src/src \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /w

# Rootless docker, for the flex and exam harnesses

The harnesses run code written by strangers (`INV-SANDBOX-01`). A container contains it. A
*rootless* container contains it better, and the difference is worth the twenty minutes.

## What the difference actually is

With a rootful daemon — the default on Debian/Ubuntu — `/var/run/docker.sock` is a
root-equivalent handle on the host, and a container escape lands you as real root. `--rm`,
`--cap-drop=ALL`, `--security-opt no-new-privileges` and `-u $(id -u)` all still apply and
all still help; none of them changes that the daemon underneath is root.

With a rootless daemon the whole thing runs as your user inside a user namespace. Container
root maps to an unprivileged host uid. An escape gets what your user has, which is the same
thing `--no-docker` would have given away anyway — so the sandbox is no longer betting on
the daemon.

Neither is a VM. A kernel exploit leaves either one. This narrows the gap; it does not close
it, and `tools/sandbox.py` says so rather than implying otherwise.

## What the harness does about it

`tools/sandbox.py` detects the mode and does not force your hand:

| daemon | default behaviour | with `--require-rootless` |
|---|---|---|
| rootless | runs, says nothing | runs |
| rootful | runs, prints a warning naming the gap | refuses |
| absent | refuses, names `--no-docker` | refuses |

It warns rather than refusing on purpose. Refusing on a rootful daemon would send people to
`--no-docker`, and running stranger code on the bare host is strictly worse than running it
in a rootful container. A warning you can act on beats a wall you route around.

## Setting it up

Debian/Ubuntu, once, as your normal user:

```sh
sudo apt-get install -y uidmap docker-ce-rootless-extras   # uidmap is the load-bearing one
dockerd-rootless-setuptool.sh install
systemctl --user enable --now docker
```

Then point your shell at the user daemon — the rootful socket is still there, so without
this you will keep using it without noticing:

```sh
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock     # add to your shell profile
```

Confirm:

```sh
docker info --format '{{.SecurityOptions}}'    # must contain name=rootless
docker info --format '{{.DockerRootDir}}'      # ~/.local/share/docker, not /var/lib/docker
```

The harness runs the same check. If the first command does not print `name=rootless`, the
warning will keep appearing, and it is right to.

## Two things that will bite

**Storage moves.** Rootless images and volumes live under `~/.local/share/docker`, not
`/var/lib/docker`. Your existing `haru-pack-flex` image and `haru-flex-cache` volume are not
there, so the first sandboxed run after switching rebuilds the image and refills the cache.
That is one slow run, not a problem.

**`$HOME` needs room.** A thick flex matrix pushes several GB through the cache volume, and
it now lands in your home directory. On a box with a small `/home` partition, move docker's
data root or expect the run to fail on ENOSPC partway through — which reads as a pile of
confusing package failures rather than as a disk problem.

## If you cannot switch

Run it anyway and read the warning. A rootful container is still the difference between a
compromised package reaching a namespace and it reaching your SSH keys. `--no-docker` is the
option that has no containment at all, and it tells you so before it starts.

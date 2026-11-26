#!/bin/bash
# spb-sandboxd.sh: SP-B's "sandboxd" step setup (plans/security-gaps-m1-m4.md
# §4.3): AerolVM's own sandboxd, built from the staged commit, running
# Firecracker VMs on the Nitro backend (SB_FIRECRACKER_BACKEND=nitro) on
# this Nitro machine. spb-run.sh runs it after spb-setup.sh, which already
# put Firecracker v1.18, its jailer, the EFI bzImage guest kernel, toolboxd,
# the jailer user and a NAT rule for 172.16.0.0/20 in place. spb.py
# sandboxd then drives the API.
#
#   spb-sandboxd.sh <source dir> <kit dir>
#
# Amazon Linux 2023, not Ubuntu, so not scripts/install.sh: AL2023 is the
# only parent kernel with the Nitro Sandboxes driver patches. Docker from
# dnf is the container engine sandboxd starts with; skopeo and umoci (the
# Firecracker image pipeline, pkg/oci) come from dnf when it has them, or
# are built from pinned tags. The admin token is made here, 0600, and never
# printed. The last line it prints sums it up.
set -euo pipefail
src="${1:?usage: spb-sandboxd.sh <source dir> <kit dir>}"
SKOPEO_TAG="${SKOPEO_TAG:-v1.17.0}"
UMOCI_TAG="${UMOCI_TAG:-v0.4.7}"
D=/opt/spb
export HOME=/root PATH=/usr/local/go/bin:$PATH GOFLAGS=-buildvcs=false

dnf install -y -q gcc git docker e2fsprogs nftables iproute >/dev/null
systemctl enable --now docker >/dev/null 2>&1

# sandboxd needs cgo (go-sqlite3).
(cd "$src" && CGO_ENABLED=1 go build -ldflags "-s -w" -o /usr/local/bin/sandboxd ./cmd/sandboxd)

tool() { # <name> <repo> <tag> <package> [build tags]: dnf first, then a pinned source build
  if dnf install -y -q "$1" >/dev/null 2>&1 && command -v "$1" >/dev/null; then
    command -v "$1"
    return
  fi
  rm -rf "/root/build-$1"
  git clone -q --depth 1 --branch "$3" "https://github.com/$2" "/root/build-$1"
  (cd "/root/build-$1" && CGO_ENABLED=0 go build -tags "${5:-}" -o "/usr/local/bin/$1" "$4")
  echo "/usr/local/bin/$1"
}
skopeo_bin="$(tool skopeo containers/skopeo "$SKOPEO_TAG" ./cmd/skopeo \
  "containers_image_openpgp exclude_graphdriver_btrfs exclude_graphdriver_devicemapper")"
umoci_bin="$(tool umoci opencontainers/umoci "$UMOCI_TAG" ./cmd/umoci)"
# skopeo's default signature policy; the builder passes --insecure-policy,
# but some versions still read the file.
[ -s /etc/containers/policy.json ] || { mkdir -p /etc/containers; echo '{"default":[{"type":"insecureAcceptAnything"}]}' >/etc/containers/policy.json; }

mkdir -p /var/lib/sandboxd/firecracker /etc/sandboxd /run/sandboxd
install -m 0644 "$D/bzImage" /var/lib/sandboxd/firecracker/bzImage
[ -s "$D/bzImage.config" ] && install -m 0644 "$D/bzImage.config" /var/lib/sandboxd/firecracker/bzImage.config
( umask 077 && openssl rand -hex 24 >/root/pat )
uid="$(id -u sandboxd-jailer)"
gid="$(id -g sandboxd-jailer)"
umask 077
cat >/etc/sandboxd/sandboxd.env <<EOF
SB_PAT_TOKEN=$(cat /root/pat)
SB_API_HOST=127.0.0.1
SB_API_PORT=21212
SB_PUBLIC_HOST=127.0.0.1
SB_DB_PATH=/var/lib/sandboxd/state.db
SB_TOOLBOX_BINARY_PATH=$D/toolboxd
SB_TOOLBOX_MOUNT_PATH=/usr/local/bin/toolboxd
SB_TOOLBOX_PORT=2280
SB_ENABLE_CADDY=false
SB_ENABLE_FIRECRACKER=true
SB_FIRECRACKER_BACKEND=nitro
SB_FIRECRACKER_NITRO_MODE=direct
SB_FIRECRACKER_KERNEL=/var/lib/sandboxd/firecracker/bzImage
SB_FIRECRACKER_BINARY=/usr/local/bin/firecracker
SB_JAILER_BINARY=/usr/local/bin/jailer
SB_FIRECRACKER_USE_JAILER=true
SB_JAILER_CHROOT_BASE=/srv/jailer
SB_JAILER_UID=$uid
SB_JAILER_GID=$gid
SB_FIRECRACKER_SKOPEO_BIN=$skopeo_bin
SB_FIRECRACKER_UMOCI_BIN=$umoci_bin
SB_FIRECRACKER_MKFS_BIN=$(command -v mkfs.ext4)
EOF
umask 022
# Its log stays on the machine and goes up with the results, masked.
(
  set -a
  . /etc/sandboxd/sandboxd.env
  set +a
  exec /usr/local/bin/sandboxd </dev/null >>/var/log/sandboxd.log 2>&1
) &
echo $! >/run/sandboxd/spb.pid
for _ in $(seq 1 120); do
  curl -fsS -o /dev/null http://127.0.0.1:21212/health && break
  sleep 1
done
curl -fsS -o /dev/null http://127.0.0.1:21212/health || { echo "sandboxd-setup: no /health after 120 s"; tail -20 /var/log/sandboxd.log | sed "s/$(cat /root/pat)/<pat>/g"; exit 1; }
echo "sandboxd-setup: sandboxd $(cd "$src" && git rev-parse --short=12 HEAD 2>/dev/null || echo staged) up; skopeo $skopeo_bin; umoci $umoci_bin; docker $(docker version --format '{{.Server.Version}}' 2>/dev/null)"

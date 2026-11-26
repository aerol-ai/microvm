#!/bin/bash
# spb-setup.sh: SP-B's tools on the Nitro machine (second boot, from
# spb-run.sh). The source and the kit are already in place and checked.
#
#   spb-setup.sh <source dir> <kit dir>
#
# Puts under /opt/spb: Firecracker v1.18 and its jailer (the upstream
# release, checked against the release's own SHA-256), Firecracker CI's EFI
# bzImage guest kernel (the pinned build, or the newest CI build when that
# one is gone), toolboxd built from the source, an Alpine root disk with
# toolboxd as PID 1 (the files AerolVM's cold boot injects:
# internal/runtime/firecracker/coldboot_agent.go), and nsm-attest, a static
# guest tool that asks /dev/nsm for an attestation document. Creates the
# jailer user, IPv4 forwarding and a NAT rule so guests reach the internet
# through their TAPs. The last line it prints sums it up.
set -euo pipefail
src="${1:?usage: spb-setup.sh <source dir> <kit dir>}"
kit="${2:?usage: spb-setup.sh <source dir> <kit dir>}"
FC_VERSION="${FC_VERSION:-v1.18.0}"
CI_PREFIX="${CI_PREFIX:-firecracker-ci/20261118-6d7cfa9c6b53-0}"
CI_KERNEL="${CI_KERNEL:-6.18.62}"
ALPINE="${ALPINE:-3.20}"
D=/opt/spb
arch=x86_64
cd "$D"
export HOME=/root

if [ ! -x /usr/local/go/bin/go ]; then
  gov="$(awk '/^go /{print $2; exit}' "$src/go.mod")"
  curl -fsSL --retry 5 "https://go.dev/dl/go${gov}.linux-amd64.tar.gz" | tar -C /usr/local -xz
fi
export PATH=/usr/local/go/bin:$PATH GOFLAGS=-buildvcs=false
(cd "$src" && CGO_ENABLED=0 go build -ldflags "-s -w" -o "$D/toolboxd" ./cmd/toolboxd)
# nsm-attest builds inside the module so it uses its golang.org/x/sys. Its
# "ignore" build tag keeps it out of the repo's own builds; dropped here.
mkdir -p "$src/cmd/spb-nsm-attest"
grep -v '^//go:build ignore$' "$kit/nsm-attest.go" >"$src/cmd/spb-nsm-attest/main.go"
(cd "$src" && CGO_ENABLED=0 go build -ldflags "-s -w" -o "$D/nsm-attest" ./cmd/spb-nsm-attest)

# Firecracker: the release tarball, checked against the release's own
# SHA-256 file (same origin; a spike, not an install).
rel=https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION
curl -fsSL --retry 5 -o fc.tgz "$rel/firecracker-$FC_VERSION-$arch.tgz"
curl -fsSL --retry 5 -o fc.tgz.sha256.txt "$rel/firecracker-$FC_VERSION-$arch.tgz.sha256.txt"
echo "$(awk '{print $1}' fc.tgz.sha256.txt)  fc.tgz" | sha256sum -c --quiet -
tar -xzf fc.tgz
install -m 0755 "release-$FC_VERSION-$arch/firecracker-$FC_VERSION-$arch" /usr/local/bin/firecracker
install -m 0755 "release-$FC_VERSION-$arch/jailer-$FC_VERSION-$arch" /usr/local/bin/jailer

# The guest kernel: Firecracker CI's EFI-stub bzImage (virtio-pci, vsock,
# VMGENID built in; the DMB patches applied; no CONFIG_NSM). The pinned
# build first; if it is gone, the newest CI build's newest bzImage-6.*,
# found the way Firecracker's getting-started.md finds its kernel.
s3=https://s3.amazonaws.com/spec.ccfc.min
if ! curl -fsSL --retry 3 -o bzImage "$s3/$CI_PREFIX/$arch/bzImage-$CI_KERNEL"; then
  CI_PREFIX="$(curl -fsSL "$s3?list-type=2&prefix=firecracker-ci/&delimiter=/" |
    grep -oE '<Prefix>firecracker-ci/[0-9]{8}-[^/]+/</Prefix>' | sed -e 's/<Prefix>//' -e 's/\/<\/Prefix>//' | sort | tail -1)"
  key="$(curl -fsSL "$s3?list-type=2&prefix=$CI_PREFIX/$arch/bzImage-6." |
    grep -oE "<Key>$CI_PREFIX/$arch/bzImage-6\.[0-9]+\.[0-9]+</Key>" | sed -e 's/<Key>//' -e 's/<\/Key>//' | sort -V | tail -1)"
  [ -n "$key" ] || { echo "setup: no CI bzImage found"; exit 1; }
  CI_KERNEL="${key##*bzImage-}"
  curl -fsSL --retry 5 -o bzImage "$s3/$key"
fi
curl -fsSL --retry 5 -o bzImage.config "$s3/$CI_PREFIX/$arch/vmlinux-$CI_KERNEL.config" || echo "setup: no config for $CI_KERNEL"

# The root disk: Alpine plus what AerolVM's cold boot injects. No token:
# like a template or warm-pool guest, the agent waits to be adopted over
# vsock (op "adopt"); the network comes from the kernel's ip= argument.
rm -rf rootfs && mkdir -p rootfs
alp=https://dl-cdn.alpinelinux.org/alpine/v$ALPINE/releases/$arch
mini="$(curl -fsSL --retry 5 "$alp/latest-releases.yaml" | awk '/file: alpine-minirootfs-.*\.tar\.gz/ {print $2; exit}')"
curl -fsSL --retry 5 "$alp/$mini" | tar -xz -C rootfs
install -D -m 0755 toolboxd rootfs/usr/local/bin/toolboxd
install -D -m 0755 "$src/internal/runtime/firecracker/assets/toolboxd-init.sh" rootfs/usr/local/bin/toolboxd-init
install -D -m 0755 nsm-attest rootfs/usr/local/bin/nsm-attest
printf "SB_TOOLBOX_PORT='2280'\n" >rootfs/etc/toolboxd.env
printf 'nameserver 169.254.169.253\n' >rootfs/etc/toolboxd.resolv.conf
rm -f rootfs.ext4 && mkfs.ext4 -q -d rootfs rootfs.ext4 256M

id sandboxd-jailer >/dev/null 2>&1 || useradd --system --no-create-home --shell /sbin/nologin sandboxd-jailer
mkdir -p /srv/jailer
sysctl -qw net.ipv4.ip_forward=1
uplink="$(ip -o route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}')"
nft list table ip spbnat >/dev/null 2>&1 || nft -f - <<NFT
table ip spbnat {
  chain post { type nat hook postrouting priority 100; ip saddr 172.16.0.0/20 oifname "$uplink" masquerade; }
}
NFT
echo "setup: firecracker $(/usr/local/bin/firecracker --version | head -1); jailer $(/usr/local/bin/jailer --version | head -1); guest kernel $CI_PREFIX bzImage-$CI_KERNEL; toolboxd $(stat -c %s toolboxd) bytes; rootfs $(du -h --apparent-size rootfs.ext4 | cut -f1)"

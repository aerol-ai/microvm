#!/usr/bin/env bash
# agent.sh: S2's agent container (plan §8.2). sandboxd only; upgraded by
# changing this container's image in place, which restarts this container
# and nothing else.
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

dnf -y -q install iproute iptables-nft nftables procps-ng >/dev/null
# OV-E2: rclone's FUSE mounts need fusermount3.
[[ -x /opt/aerolvm/bin/rclone ]] && dnf -y -q install fuse3 >/dev/null
export PATH="/opt/aerolvm/bin:$PATH"

# Wait for the runtime container: its containerd socket and the cgroup path
# it set up for sandboxes, both on shared folders.
for _ in $(seq 1 120); do
  [[ -S /run/containerd/containerd.sock && -s /run/aerolvm/cgroup-parent ]] && break
  sleep 1
done
[[ -S /run/containerd/containerd.sock ]] || { echo "agent: no containerd socket from the runtime container" >&2; exit 1; }
[[ -s /run/aerolvm/cgroup-parent ]] || { echo "agent: no cgroup parent from the runtime container" >&2; exit 1; }
SB_CONTAINERD_CGROUP_PARENT="$(cat /run/aerolvm/cgroup-parent)"
export SB_CONTAINERD_CGROUP_PARENT
echo "agent: sandboxes go under ${SB_CONTAINERD_CGROUP_PARENT}"

prepare_netfilter
sandboxd_env

echo "agent: starting sandboxd"
sandboxd 2>&1 | sed -u 's/^/[sandboxd] /'

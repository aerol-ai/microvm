#!/usr/bin/env bash
# run.sh: the H0 worker container. Starts our own containerd, then a
# single-node sandboxd on the containerd engine with gVisor.
#
# H0 keeps both in one container on purpose: it only proves the pieces run
# inside a pod. Spike S2 splits them into the runtime and agent containers of
# plan §8.2. Settings mirror what scripts/install.sh writes on a VM with
# --with-containerd-engine --with-gvisor, minus Caddy (no sandbox links in H0).
set -euo pipefail

: "${SB_PAT_TOKEN:?}"

dnf -y -q install iproute iptables-nft nftables procps-ng >/dev/null

export PATH="/opt/aerolvm/bin:$PATH"
mkdir -p /run/containerd /etc/containerd /var/lib/sandboxd/mounts \
  /var/lib/toolboxd/recordings /run/sandboxd
chmod 0700 /var/lib/sandboxd/mounts /run/sandboxd

# containerd's root is an emptyDir on the machine's disk (see the pod spec):
# its overlayfs snapshots cannot sit on the container's own overlay root.
containerd config default > /etc/containerd/config.toml
containerd --config /etc/containerd/config.toml 2>&1 | sed -u 's/^/[containerd] /' &
for _ in $(seq 1 60); do
  [[ -S /run/containerd/containerd.sock ]] && break
  sleep 1
done
[[ -S /run/containerd/containerd.sock ]] || { echo "run: containerd did not start" >&2; exit 1; }

export SB_NODE_NAME="${POD_NAME:-worker}"
export SB_API_HOST=0.0.0.0
export SB_API_PORT=21212
export SB_DB_PATH=/var/lib/sandboxd/state.db
export SB_TOOLBOX_BINARY_PATH=/opt/aerolvm/bin/toolboxd
export SB_TOOLBOX_MOUNT_PATH=/usr/local/bin/toolboxd
export SB_TOOLBOX_PORT=2280
export SB_ENABLE_CADDY=false
export SB_ENABLE_NETWORK_RULES=true
export SB_MOUNTS_ROOT=/var/lib/sandboxd/mounts
export SB_MOUNTS_CRED_DIR=/run/sandboxd
export SB_RECORDING_DIR=/var/lib/toolboxd/recordings
export SB_HOST_RUNTIMES=docker,gvisor
export SB_CONTAINER_ENGINE=containerd
export SB_CONTAINERD_SOCKET=/run/containerd/containerd.sock
export SB_CONTAINERD_NAMESPACE=aerolvm
export SB_CONTAINERD_CNI_PLUGIN_DIR=/opt/aerolvm/cni
export SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED=true

# A fresh pod network namespace has no `ip filter` table; on a VM, Docker
# made it long before sandboxd ran. sandboxd adds AEROLVM-USER to that table
# but does not create the table or its FORWARD chain
# (pkg/docker/netrules/netlink_backend.go, EnsureUserChain), so it exits with
# "nft add chain AEROLVM-USER: no such file or directory". The tables are made
# with nft directly: `iptables -L` in this image did not create them in
# nftables (run 4 of H0 on 2026-11-10). Phase 1 must make sandboxd create
# them itself; this is the spike's stand-in.
echo "run: iptables is $(iptables -V 2>&1); tables before: $(nft list tables 2>&1 | tr '\n' ' ')"
for fam in ip ip6; do
  nft add table "$fam" filter
  nft add chain "$fam" filter INPUT '{ type filter hook input priority 0; policy accept; }'
  nft add chain "$fam" filter FORWARD '{ type filter hook forward priority 0; policy accept; }'
  nft add chain "$fam" filter OUTPUT '{ type filter hook output priority 0; policy accept; }'
done
echo "run: tables after: $(nft list tables 2>&1 | tr '\n' ' ')"

echo "run: starting sandboxd"
# Not exec: the pipe adds a log prefix, and pipefail makes the container exit
# with sandboxd's status when it dies, so the pod shows the crash.
sandboxd 2>&1 | sed -u 's/^/[sandboxd] /'

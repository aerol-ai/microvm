#!/usr/bin/env bash
# g5-native.sh: G5's other half (g5.sh). The worker's binaries run on the
# machine itself as one plain systemd service, no pod: our containerd on its
# own socket next to the kubelet's, and sandboxd with the same settings the
# worker pod uses (common.sh), minus the cgroup parent. g5.sh copies this
# and the worker scripts to /opt/g5 on the machine and starts it with
# systemd-run, with the build's URLs and the API token in its environment.
set -euo pipefail
# shellcheck source=common.sh
source /opt/g5/common.sh

bash /opt/g5/fetch.sh
dnf -y -q install iproute iptables-nft nftables procps-ng >/dev/null
export PATH="/opt/aerolvm/bin:$PATH"

# Our containerd beside the kubelet's: its own root, state, sockets and NRI
# socket, so neither sees the other.
mkdir -p /etc/g5 /run/g5-containerd /var/lib/g5-containerd /var/lib/g5-sandboxd
containerd config default |
  sed -e 's#^root = .*#root = "/var/lib/g5-containerd"#' \
      -e 's#^state = .*#state = "/run/g5-containerd"#' \
      -e 's#/run/containerd/containerd.sock#/run/g5-containerd/containerd.sock#g' \
      -e 's#/var/run/nri/nri.sock#/run/g5-containerd/nri.sock#g' > /etc/g5/containerd.toml
protect_from_oom $$
containerd --config /etc/g5/containerd.toml 2>&1 | sed -u 's/^/[containerd] /' &
for _ in $(seq 1 60); do
  [[ -S /run/g5-containerd/containerd.sock ]] && break
  sleep 1
done
[[ -S /run/g5-containerd/containerd.sock ]] || { echo "g5-native: containerd did not start" >&2; exit 1; }

prepare_netfilter
sandboxd_env
export SB_NODE_NAME=g5-host
export SB_API_PORT=21299
export SB_DB_PATH=/var/lib/g5-sandboxd/state.db
export SB_CONTAINERD_SOCKET=/run/g5-containerd/containerd.sock
echo "g5-native: starting sandboxd on :21299"
sandboxd 2>&1 | sed -u 's/^/[sandboxd] /'

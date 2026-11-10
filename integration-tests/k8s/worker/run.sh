#!/usr/bin/env bash
# run.sh: the H0 worker container. Starts our own containerd, then a
# single-node sandboxd on the containerd engine with gVisor.
#
# H0 keeps both in one container on purpose: it only proves the pieces run
# inside a pod. S2 splits them (runtime.sh and agent.sh) into the runtime and
# agent containers of plan §8.2.
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

dnf -y -q install iproute iptables-nft nftables procps-ng util-linux >/dev/null
export PATH="/opt/aerolvm/bin:$PATH"

# C7 prototype (spike S1): every sandbox goes under this pod's own cgroup.
if [[ "${AEROL_C7_CGROUP_PARENT:-0}" == 1 ]]; then
  SB_CONTAINERD_CGROUP_PARENT="$(c7_setup)"
  export SB_CONTAINERD_CGROUP_PARENT
  echo "run: C7 on; sandboxes go under ${SB_CONTAINERD_CGROUP_PARENT}"
fi

# containerd's root is an emptyDir on the machine's disk (see the pod spec):
# its overlayfs snapshots cannot sit on the container's own overlay root.
mkdir -p /run/containerd /etc/containerd
containerd config default > /etc/containerd/config.toml
containerd --config /etc/containerd/config.toml 2>&1 | sed -u 's/^/[containerd] /' &
for _ in $(seq 1 60); do
  [[ -S /run/containerd/containerd.sock ]] && break
  sleep 1
done
[[ -S /run/containerd/containerd.sock ]] || { echo "run: containerd did not start" >&2; exit 1; }

# S7 stand-in: a pod that is not privileged gets /proc/sys read-only, and
# sandboxd sets per-network kernel settings there (ip_forward and the bridge
# ones; these live in the pod's own network namespace). Kubernetes' own way is
# the pod's securityContext.sysctls, but these count as "unsafe" and need the
# kubelet's --allowed-unsafe-sysctls, a node setting. With CAP_SYS_ADMIN the
# spike remounts it instead.
if awk '$5 == "/proc/sys" {print $6}' /proc/self/mountinfo | grep -q '^ro'; then
  mount -o remount,rw /proc/sys && echo "run: /proc/sys remounted read-write (S7 stand-in)"
fi

prepare_netfilter
sandboxd_env

echo "run: starting sandboxd"
# Not exec: the pipe adds a log prefix, and pipefail makes the container exit
# with sandboxd's status when it dies, so the pod shows the crash.
sandboxd 2>&1 | sed -u 's/^/[sandboxd] /'

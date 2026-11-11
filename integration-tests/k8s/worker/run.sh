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

dnf -y -q install iproute iptables-nft nftables procps-ng util-linux xfsprogs >/dev/null
export PATH="/opt/aerolvm/bin:$PATH"

# C7 prototype (spike S1): every sandbox goes under this pod's own cgroup.
if [[ "${AEROL_C7_CGROUP_PARENT:-0}" == 1 ]]; then
  SB_CONTAINERD_CGROUP_PARENT="$(c7_setup)"
  export SB_CONTAINERD_CGROUP_PARENT
  echo "run: C7 on; sandboxes go under ${SB_CONTAINERD_CGROUP_PARENT}"
  # AEROL_KEEPER=0 leaves the OOM settings to sandboxd (F10's fix in
  # sandboxd, markWholeOOMVictim), to prove it does them alone.
  if [[ "${AEROL_KEEPER:-1}" == 1 ]]; then
    keep_sandboxes_first "/sys/fs/cgroup${SB_CONTAINERD_CGROUP_PARENT}" &
  else
    echo "run: keeper loop off; sandboxd sets each sandbox's OOM settings"
  fi
fi

# S8: containerd's root on the local NVMe, XFS with project quotas.
if [[ "${AEROL_S8_NVME:-0}" == 1 ]]; then
  prepare_nvme
fi

# containerd's root is an emptyDir on the machine's disk (see the pod spec):
# its overlayfs snapshots cannot sit on the container's own overlay root.
mkdir -p /run/containerd /etc/containerd
protect_from_oom $$
containerd config default > /etc/containerd/config.toml
( in_runtime_group "${SB_CONTAINERD_CGROUP_PARENT:-}" containerd --config /etc/containerd/config.toml ) 2>&1 | sed -u 's/^/[containerd] /' &
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

# C6: the egress gateway with no systemd, as a pod would run it: its own
# process, a numeric user no passwd file names, only CAP_NET_ADMIN and
# CAP_NET_BIND_SERVICE, a socket it makes itself, and no sandboxd.service
# cgroup to check its peer against.
if [[ "${AEROL_EGRESS_GATEWAY:-0}" == 1 ]]; then
  mkdir -p /run/aerolvm /var/lib/aerolvm-egress
  chown 65532:65532 /var/lib/aerolvm-egress
  # The gateway makes its own socket here; sandboxd (root) makes the lookup one.
  chown 0:65532 /run/aerolvm && chmod 0775 /run/aerolvm
  ( SB_EGRESS_PEER_CGROUP=none SB_EGRESS_STATE_DIR=/var/lib/aerolvm-egress \
      setpriv --reuid=65532 --regid=65532 --clear-groups \
        --inh-caps=-all,+net_admin,+net_bind_service --ambient-caps=-all,+net_admin,+net_bind_service \
        --bounding-set=-all,+net_admin,+net_bind_service \
        /opt/aerolvm/bin/sandboxd egress-gateway ) 2>&1 | sed -u 's/^/[gateway] /' &
  export SB_EGRESS_GATEWAY_USER=65532
  echo "run: egress gateway started as uid 65532 without systemd (C6)"
fi

echo "run: starting sandboxd"
# Not exec: the pipe adds a log prefix, and pipefail makes the container exit
# with sandboxd's status when it dies, so the pod shows the crash.
sandboxd 2>&1 | sed -u 's/^/[sandboxd] /'

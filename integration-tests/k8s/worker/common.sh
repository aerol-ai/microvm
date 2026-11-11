#!/usr/bin/env bash
# common.sh: sourced by the worker scripts (run.sh for H0's one container,
# agent.sh for S2's agent container). Settings mirror what scripts/install.sh
# writes on a VM with --with-containerd-engine --with-gvisor, minus Caddy.

# prepare_netfilter is the spike's stand-in for finding F1 (plan §18, Phase 0
# results): a new pod network has no `ip filter` table, and sandboxd adds its
# AEROLVM-USER chain to that table without creating it. `nft add` is a no-op
# when the table or chain exists, so an agent restart can run it again.
prepare_netfilter() {
  echo "worker: iptables is $(iptables -V 2>&1); tables before: $(nft list tables 2>&1 | tr '\n' ' ')"
  local fam
  for fam in ip ip6; do
    nft add table "$fam" filter
    nft add chain "$fam" filter INPUT '{ type filter hook input priority 0; policy accept; }'
    nft add chain "$fam" filter FORWARD '{ type filter hook forward priority 0; policy accept; }'
    nft add chain "$fam" filter OUTPUT '{ type filter hook output priority 0; policy accept; }'
  done
  echo "worker: tables after: $(nft list tables 2>&1 | tr '\n' ' ')"
}

# sandboxd_env exports a single-node sandboxd on the containerd engine.
sandboxd_env() {
  : "${SB_PAT_TOKEN:?}"
  mkdir -p /var/lib/sandboxd/mounts /var/lib/toolboxd/recordings /run/sandboxd
  chmod 0700 /var/lib/sandboxd/mounts /run/sandboxd
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
}

# c7_setup puts this container's processes into supervisor/ and makes
# sandboxes/ hand cpu, memory and pids down (the C7 prototype). It prints the
# parent path for SB_CONTAINERD_CGROUP_PARENT. A privileged container sees the
# machine's whole cgroup tree, so /proc/self/cgroup names this container's
# group; cgroup v2 lets a group hand controllers down only while it holds no
# processes itself.
c7_setup() {
  local self cg pid
  self="$(cut -d: -f3 /proc/self/cgroup)"
  # A container that is not privileged gets its own cgroup namespace and sees
  # its own group as "/" (S7, S9); avoid "//sandboxes".
  [[ "$self" == / ]] && self=""
  # It also gets /sys/fs/cgroup read-only. With a real CAP_SYS_ADMIN (not in
  # a user namespace) it can remount it read-write; in a user namespace (S9)
  # the remount is refused and the mkdir below fails, as recorded.
  if awk '$5 == "/sys/fs/cgroup" {print $6}' /proc/self/mountinfo | grep -q '^ro'; then
    # To stderr: this function's stdout is the path the caller captures.
    mount -o remount,rw /sys/fs/cgroup >&2 2>&1 || true
  fi
  cg="/sys/fs/cgroup${self}"
  mkdir -p "$cg/supervisor" "$cg/sandboxes"
  for pid in $(cat "$cg/cgroup.procs"); do
    echo "$pid" > "$cg/supervisor/cgroup.procs" 2>/dev/null || true
  done
  echo "+cpu +memory +pids" > "$cg/cgroup.subtree_control"
  echo "+cpu +memory +pids" > "$cg/sandboxes/cgroup.subtree_control"
  # Finding F10 (S3): with the kubelet's default, one pod-level OOM kills
  # every process in this container, as a group: all sandboxes and the
  # machinery. Turn group-killing off here, on sandboxes/, and on the pod's
  # own group when it is visible, so the kernel kills only the process it
  # picks; sandboxd gives each sandbox a high OOM score, so it picks one.
  echo 0 > "$cg/memory.oom.group" 2>/dev/null || true
  echo 0 > "$cg/sandboxes/memory.oom.group" 2>/dev/null || true
  [[ -n "$self" ]] && echo 0 > "/sys/fs/cgroup$(dirname "$self")/memory.oom.group" 2>/dev/null || true
  echo "${self}/sandboxes"
}

# protect_from_oom lowers the caller's OOM score; what it starts inherits it.
# The machinery (containerd, sandboxd) must never be the kernel's choice when
# the pod hits its limit (finding F10).
protect_from_oom() {
  echo -999 > "/proc/$1/oom_score_adj" 2>/dev/null || echo "worker: could not lower the OOM score" >&2
}

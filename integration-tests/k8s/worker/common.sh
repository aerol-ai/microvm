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
  # F10's full fix (fifth S3 run showed it is needed): with sandboxes and the
  # machinery sharing the container's one limit, a pod at that limit starved
  # sandboxd even after whole sandboxes were killed. So sandboxes/ gets its
  # own cap, the container's limit minus a reserve (10%, between 1 and
  # 4 GiB), and supervisor/ keeps memory.min of that reserve. An out-of-memory
  # event then happens inside sandboxes/, where it can only kill a sandbox.
  local max reserve
  read -r max < "$cg/memory.max"
  if [[ "$max" =~ ^[0-9]+$ ]]; then
    reserve=$(( max / 10 ))
    (( reserve < 1073741824 )) && reserve=1073741824
    (( reserve > 4294967296 )) && reserve=4294967296
    echo $(( max - reserve )) > "$cg/sandboxes/memory.max"
    echo "$reserve" > "$cg/supervisor/memory.min" 2>/dev/null || true
    echo "worker: sandboxes/ capped at $(( (max - reserve) / 1048576 )) MiB; ${reserve} bytes kept for the machinery" >&2
  else
    echo "worker: the container has no memory limit ($max); sandboxes/ is not capped" >&2
  fi
  echo "${self}/sandboxes"
}

# keep_sandboxes_first makes each sandbox the kernel's first and whole
# choice when the pod runs out of memory, every 2 s, in the background:
#
#   - every process under the sandboxes group gets OOM score 500. The spec's
#     oomScoreAdj is not enough: runsc applies it only to its own boot
#     process, containerd sets each shim's score from its own (-999), and
#     gVisor's helper processes, which hold a sandbox's memory, inherit the
#     shim's (third S3 run);
#   - each sandbox's own group gets memory.oom.group 1, so the kernel kills
#     all of that sandbox's processes together. A gVisor sandbox's tmpfs is
#     one shared memory file held by several of its processes; killing one
#     of them frees nothing, and the pod stays wedged at its limit (fourth
#     S3 run). The groups above it stay at 0 (c7_setup), so one OOM never
#     takes the machinery or other sandboxes.
#
# Phase 1 does both in sandboxd right after a sandbox starts; this loop is
# the spike's stand-in. Builtins only: a fork per process would cost
# thousands of forks per pass at 1,000 sandboxes.
keep_sandboxes_first() {
  local dir="$1" d pid v
  while true; do
    for d in "$dir"/*/; do
      [[ -e "$d/memory.oom.group" ]] || continue
      { read -r v < "$d/memory.oom.group"; } 2>/dev/null && [[ "$v" == 1 ]] || echo 1 > "$d/memory.oom.group" 2>/dev/null
      while read -r pid; do
        { read -r v < "/proc/$pid/oom_score_adj"; } 2>/dev/null || continue
        [[ "$v" == 500 ]] || echo 500 > "/proc/$pid/oom_score_adj" 2>/dev/null
      done < "$d/cgroup.procs"
    done
    sleep 2
  done
}

# prepare_nvme (spike S8) formats the machine's local NVMe instance store as
# XFS with project quotas and mounts it as containerd's root, so each
# sandbox's writable layer can get its own disk limit (plan C27, eng review
# D8). A privileged container sees the machine's devices; the instance store
# is the NVMe disk whose model says so. The spike formats it every start:
# whatever was there belonged to a previous worker pod.
prepare_nvme() {
  local dev="" b
  for b in /sys/block/nvme*n1; do
    if grep -q 'Instance Storage' "$b/device/model" 2>/dev/null; then dev="/dev/${b##*/}"; break; fi
  done
  [[ -n "$dev" ]] || { echo "worker: no NVMe instance store on this machine" >&2; return 1; }
  mkfs.xfs -f -q "$dev"
  mount -o prjquota "$dev" /var/lib/containerd
  echo "worker: $dev ($(lsblk -no SIZE "$dev" | head -1)) is XFS with project quotas at /var/lib/containerd"
}

# protect_from_oom lowers the caller's OOM score; what it starts inherits it.
# The machinery (containerd, sandboxd) must never be the kernel's choice when
# the pod hits its limit (finding F10).
protect_from_oom() {
  echo -999 > "/proc/$1/oom_score_adj" 2>/dev/null || echo "worker: could not lower the OOM score" >&2
}

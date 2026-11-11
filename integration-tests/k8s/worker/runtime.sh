#!/usr/bin/env bash
# runtime.sh: S2's runtime container (plan §8.2). It holds containerd and
# every sandbox, changes rarely, and has no liveness probe: a restart of this
# container would end every sandbox in it.
#
# Its first process never exits: it restarts containerd in place if it dies.
# Sandboxes keep running meanwhile, because each belongs to its own shim, not
# to containerd.
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"
export PATH="/opt/aerolvm/bin:$PATH"

# C7: sandboxes live in THIS container's group. The agent, in another
# container, learns the path from a file on the shared /run/aerolvm.
parent="$(c7_setup)"
mkdir -p /run/aerolvm /run/containerd /etc/containerd
echo "$parent" > /run/aerolvm/cgroup-parent.tmp
mv /run/aerolvm/cgroup-parent.tmp /run/aerolvm/cgroup-parent
echo "runtime: sandboxes go under $parent"
keep_sandboxes_first "/sys/fs/cgroup${parent}" &

protect_from_oom $$
containerd config default > /etc/containerd/config.toml
while true; do
  ( in_runtime_group "$parent" containerd --config /etc/containerd/config.toml ) 2>&1 | sed -u 's/^/[containerd] /' || true
  echo "runtime: containerd exited; starting it again in 2s"
  sleep 2
done

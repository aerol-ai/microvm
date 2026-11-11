#!/usr/bin/env bash
# s9-probe.sh: spike S9's first look inside a pod with its own user namespace
# (hostUsers: false), before the worker even tries to start. Each line answers
# one of plan §8.7's three S9 questions, or explains why the worker will fail.
# Nothing here stops on an error: every check reports and moves on.
set +e
export PATH="/opt/aerolvm/bin:$PATH"
dnf -y -q install iproute nftables procps-ng util-linux >/dev/null 2>&1
ok() { echo "s9: $1: ok"; }
no() { echo "s9: $1: FAIL ($2)"; }

echo "s9: uid_map: $(tr -s ' ' < /proc/self/uid_map | tr '\n' ';')"
echo "s9: capabilities: $(grep CapEff /proc/self/status | tr -s '\t' ' ')"
echo "s9: /sys/fs/cgroup mount: $(awk '$5 == "/sys/fs/cgroup" {print $6, $9, $10}' /proc/self/mountinfo)"
echo "s9: own cgroup (as seen here): $(cut -d: -f3 /proc/self/cgroup)"

# Question 1: per-sandbox CPU and memory limits need a cgroup we can create
# and hand controllers to.
cg=/sys/fs/cgroup
if mkdir "$cg/s9-probe" 2>/tmp/e; then
  ok "make a cgroup"
  if echo "+memory +cpu +pids" > "$cg/cgroup.subtree_control" 2>/tmp/e; then ok "hand controllers down"; else no "hand controllers down" "$(cat /tmp/e)"; fi
  rmdir "$cg/s9-probe" 2>/dev/null
else
  no "make a cgroup" "$(cat /tmp/e)"
fi

# Question 2: the sandbox network, all inside the pod's network namespace.
if ip link add s9br type bridge 2>/tmp/e; then ok "bridge in the pod's network"; ip link del s9br; else no "bridge in the pod's network" "$(cat /tmp/e)"; fi
if ip netns add s9ns 2>/tmp/e; then
  ok "new network namespace"
  if ip link add s9v0 type veth peer name s9v1 netns s9ns 2>/tmp/e; then ok "link from the pod into it"; ip link del s9v0; else no "link from the pod into it" "$(cat /tmp/e)"; fi
  ip netns del s9ns
else
  no "new network namespace" "$(cat /tmp/e)"
fi
if nft add table ip s9t 2>/tmp/e; then ok "nftables rules in the pod's network"; nft delete table ip s9t; else no "nftables rules in the pod's network" "$(cat /tmp/e)"; fi
if [[ -e /proc/sys/net/bridge/bridge-nf-call-iptables ]]; then ok "bridge-nf-call-iptables visible ($(cat /proc/sys/net/bridge/bridge-nf-call-iptables))"; else no "bridge-nf-call-iptables visible" "absent"; fi

# Question 3: gVisor itself.
if out="$(timeout 60 runsc --rootless --network=none --ignore-cgroups do echo hello-from-gvisor 2>&1)"; then
  ok "runsc do (rootless, no network): $(echo "$out" | tail -1)"
else
  no "runsc do (rootless, no network)" "$(echo "$out" | tail -2 | tr '\n' ' ' | cut -c1-200)"
fi
echo "s9: probe done; starting the H0 worker (run.sh) to see where it stops"

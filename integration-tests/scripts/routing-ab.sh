#!/usr/bin/env bash
# routing-ab.sh — flip SB_INGRESS_PROXY_ROUTING on every node of a kept
# routing scenario, for the routing A/B (plans/cluster-phase-2.md §4.2).
#
# Usage:
#   integration-tests/scripts/routing-ab.sh <scenario> off|on|status
#
#   off     set SB_INGRESS_PROXY_ROUTING=false on every node (a drop-in, see
#           lib/node-run.sh) and restart sandboxd, one node at a time, seed
#           first. Each routing node then rolls back to per-sandbox Caddy
#           routes in one Caddy load, through its
#           ingress_proxy_routing_last_enabled marker.
#   on      remove that drop-in and restart the same way: each node goes
#           back to its installed value, which on a routing scenario is on,
#           and engages in one Caddy load.
#   status  print each node's override, configured value, marker, static
#           route and unit state. Changes nothing.
#
# A node already where it should be is skipped, so a run that stopped half
# way is finished by running the same command again. After each restart the
# script waits for the unit, the node's /health and, in a cluster, for the
# node's own member list to be whole again, so the next restart never takes
# a second Raft voter down while the first is still away. Then it checks
# the flip took: an "on" node whose engage was refused (missing resolver
# routing, iptables) fails here, not later as a confusing A/B number.
#
# The A/B, from integration-tests/README.md:
#   run-on-node.sh <s> --label on-1  -run '^TestIngressRoutingChurnGate$'
#   routing-ab.sh  <s> off
#   run-on-node.sh <s> --label off-1 -run '^TestIngressRoutingChurnGate$'
#   routing-ab.sh  <s> on
#   ... and the same four steps once more (on-2, off-2).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${HERE}/.." && pwd)"
# shellcheck source=../lib/common.sh
source "${HERE}/lib/common.sh"
# shellcheck source=../lib/node-run.sh
source "${HERE}/lib/node-run.sh"

SCENARIO="${1:-}"
ACTION="${2:-}"
if [[ -z "$SCENARIO" || $# -ne 2 ]] || [[ "$ACTION" != off && "$ACTION" != on && "$ACTION" != status ]]; then
  sed -n '5,6p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
fi
if [[ "$SCENARIO" == *[^A-Za-z0-9._-]* ]]; then
  echo "scenario name contains unsafe characters (refusing: ${SCENARIO})" >&2
  exit 2
fi
CAPS_FILE="${HERE}/scenarios/${SCENARIO}.caps.yml"
[[ -f "$CAPS_FILE" ]] || { echo "unknown scenario ${SCENARIO}: no ${CAPS_FILE}" >&2; exit 2; }
if [[ "$ACTION" != status ]] && ! yq -r '.capabilities | contains(["ingress-proxy-routing"])' "$CAPS_FILE" | grep -q true; then
  # The A/B compares the flag on with the flag off. A scenario not installed
  # with routing has no "on" to return to (no resolver routing domain).
  echo "scenario ${SCENARIO} does not run ingress proxy routing (no ingress-proxy-routing capability); the A/B needs a -routing scenario" >&2
  exit 2
fi

TARGETS=$(kept_targets "$REPO_ROOT" "$SCENARIO")
EXPECTED_MEMBERS=$(yq -r '.expected_members // ""' "$CAPS_FILE")
resolve_ssh_identity "${HERE}/scenarios/${SCENARIO}.tfvars" "${REPO_ROOT}/config/terraform.tfvars" >/dev/null
PAT=$(yq -r '.cluster.pat_token' "${REPO_ROOT}/config/secrets.yml")
SSH_USER="${AEROL_SSH_USER:-ubuntu}"

probe() {
  ab_probe_script | ssh "${SSH_OPTS[@]}" "$1" 'bash -s' 2>/dev/null
}

# wait_node_back <ssh_target> <name>
# The unit active, /health answering, and in a cluster the node's own view of
# the member list whole again. The PAT reaches curl on stdin: it works on the
# node's loopback even under SB_PAT_SCOPE=host.
wait_node_back() {
  local target="$1" name="$2" deadline out n
  deadline=$(( $(date +%s) + ${AEROL_AB_NODE_TIMEOUT:-300} ))
  while (( $(date +%s) < deadline )); do
    out=$(ssh "${SSH_OPTS[@]}" "$target" \
      'systemctl is-active --quiet sandboxd && curl -fsS -m 5 -o /dev/null http://127.0.0.1:21212/health && echo up' 2>/dev/null) || out=""
    if [[ "$out" == *up* ]]; then
      if [[ -z "$EXPECTED_MEMBERS" ]]; then
        return 0
      fi
      n=$(printf 'Authorization: Bearer %s\n' "$PAT" | ssh "${SSH_OPTS[@]}" "$target" \
        'curl -fsS -m 10 -H @- http://127.0.0.1:21212/v1/cluster/members' 2>/dev/null \
        | jq -r '(.members // []) | length' 2>/dev/null) || n=0
      if [[ "$n" == "$EXPECTED_MEMBERS" ]]; then
        return 0
      fi
    fi
    sleep 5
  done
  echo "${name}: sandboxd not back (active, /health and ${EXPECTED_MEMBERS:-?} members) within ${AEROL_AB_NODE_TIMEOUT:-300}s" >&2
  return 1
}

# wait_settled <ssh_target> <name> <role>
# The engage or rollback finishes after /health answers (the commit waits for
# the router to serve), so the final state is polled for, not read once.
wait_settled() {
  local target="$1" name="$2" role="$3" deadline p=""
  deadline=$(( $(date +%s) + 180 ))
  while (( $(date +%s) < deadline )); do
    p=$(probe "$target") || p=""
    if ab_node_settled "$role" "$ACTION" "$p"; then
      return 0
    fi
    sleep 5
  done
  echo "${name} (${role}): not settled ${ACTION} after its restart:" >&2
  sed 's/^/    /' <<<"$p" >&2
  if [[ "$ACTION" == on ]]; then
    echo "    an 'on' node with marker false/none refused to engage; its journal says why:" >&2
    echo "    ssh ${target} sudo journalctl -u sandboxd | grep 'ingress proxy routing'" >&2
  fi
  return 1
}

failed=0
# The node list is read on fd 3: every ssh below would otherwise read the
# loop's stdin and swallow the remaining nodes.
while IFS=$'\t' read -r name role seed ip <&3; do
  [[ -n "$ip" ]] || { echo "${name}: no public IP, skipped" >&2; failed=1; continue; }
  target="${SSH_USER}@${ip}"
  p=$(probe "$target") || p=""
  if [[ "$ACTION" == status ]]; then
    printf '%-12s %-16s %-4s override=%s configured=%s marker=%s static_route=%s active=%s\n' \
      "$name" "$role" "$seed" "$(probe_value "$p" override)" "$(probe_value "$p" configured)" \
      "$(probe_value "$p" marker)" "$(probe_value "$p" static_route)" "$(probe_value "$p" active)"
    continue
  fi
  if ab_node_settled "$role" "$ACTION" "$p"; then
    echo "${name}: already ${ACTION}, skipped" >&2
    continue
  fi
  echo "${name} (${role}): routing ${ACTION}, restarting sandboxd" >&2
  ab_apply_script "$ACTION" | ssh "${SSH_OPTS[@]}" "$target" 'bash -s'
  # reset-failed first: a unit that crash-looped into systemd's start limit
  # ignores restart until the counter is cleared (harness.WithNodeEnv).
  ssh "${SSH_OPTS[@]}" "$target" 'sudo systemctl reset-failed sandboxd 2>/dev/null; sudo systemctl restart sandboxd'
  # Stop at the first node that does not come back: restarting the next
  # server too could cost the cluster its Raft quorum.
  wait_node_back "$target" "$name" || exit 1
  wait_settled "$target" "$name" "$role" || failed=1
done 3< <(nodes_seed_first "$TARGETS")

if [[ "$ACTION" != status ]]; then
  if [[ "$failed" != 0 ]]; then
    echo "routing ${ACTION}: at least one node did not settle; see above" >&2
    exit 1
  fi
  echo "routing ${ACTION}: every node of ${SCENARIO} settled" >&2
fi

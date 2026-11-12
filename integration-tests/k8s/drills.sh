#!/usr/bin/env bash
# drills.sh: the live drills of plans/kubernetes-v2-architecture.md §19
# (Phase 3), against a cluster-mode install that is already up.
#
#   drills.sh <state-dir> <drill> [drill...]
#
# cell.sh <name> drills [drill...] runs it on the EKS cell. On kind:
#   KUBECTL_CONTEXT=kind-aerolvm-cluster drills.sh /tmp/d probe gateway-stream
#
# Drills (each prints PASS or FAIL with what it measured, into
# <state-dir>/drills.txt):
#   probe            C24: no profile reaches nothing internal; a profile that
#                    opens one internal range reaches that range only
#   bank-egress      a bank's own deny-all egress policy for the worker pods
#                    holds even under an "allow all" AerolVM rule
#   gateway-stream   a gateway killed mid-stream; the client reads on through
#                    another gateway and gets the recent output
#   api-down         the operator cut off from the Kubernetes API for
#                    DRILL_API_DOWN_SECONDS (600): creates and exec go on.
#                    It proves the cut from the operator's leader Lease; on
#                    kind (kindnet) pods reach the API server through any
#                    egress policy, so there it fails with "cut off=no".
#                    A second result, api-recover: once the policy goes,
#                    the operator renews its Lease again by itself
#   delete-guard     C26: a worker pod delete is refused, goes through with
#                    aerolvm.io/force-delete=true, and is counted
#   zone-loss        G1, EKS only: one zone's subnet cut off by a deny-all
#                    network ACL for DRILL_ZONE_SECONDS (240). The API stays
#                    up, creates recover within 30 s, and every recreate
#                    sandbox of that zone comes back in another
#   disk-full        C27, EKS only (on kind every node shares one disk), two
#                    results; in both a sandbox beside the writer keeps
#                    working and the worker pod is not evicted:
#                      disk-own   a writer with a 2 GB disk is stopped by
#                                 the disk watchdog
#                      disk-floor a writer takes the sandbox volume under
#                                 the floor (DRILL_DISK_FLOOR, 0.30 on the
#                                 cell): the worker refuses new sandboxes
#                                 until the writer is gone
#   rollout          one upgrade to DRILL_VERSION_B (images in the registry,
#                    cell.sh build2 makes them), four results:
#                      rollout-mixed    G9: paused after the first worker,
#                                       N and N-1 serve for DRILL_MIXED_MINUTES
#                                       (60) with no failed round
#                      rollout-guard    C26: a plain worker pod delete is
#                                       refused mid-rollout
#                      rollout-leaders  C13: the operator and Raft leaders
#                                       killed together; the agents took
#                                       their turns in the leader's order,
#                                       no pod stepped twice
#                      rollout-restarts G8: no sandbox restarted (each keeps
#                                       its session running throughout)
#   rotation         G8, EKS only: a new launch template version rolled over
#                    the whole worker node group. Each worker is decommissioned
#                    before its machine goes: every recreate sandbox is moved
#                    and started, the others stopped, none lost by surprise
#
# A FAIL leaves what to read in <state-dir>/evidence/<drill>/ (AerolNodes,
# pods, events, the operator's and each worker container's log, the member
# list). zone-loss logs every failed create with its error and how long it
# took; zone-loss and rotation write a timeline of AerolNode states, worker
# pods and machines (zone-loss.txt, rotation.txt, one picture a minute).
#
# The EKS drills need DRILL_EKS_CLUSTER and DRILL_AWS_REGION (cell.sh sets
# them) and AWS credentials that may change the VPC's network ACLs.
#
# It changes the install (a NetworkPolicy, Helm values, a pod) and puts each
# change back, also when the drill fails.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sd="${1:?usage: drills.sh <state-dir> <drill> [drill...]}"; shift
mkdir -p "$sd"
ns="${AEROL_NS:-aerolvm-system}"
workers="${AEROL_WORKER_NS:-aerolvm-workers}"
release="${AEROL_HELM_RELEASE:-aerolvm}"
chart="${AEROL_CHART:-$HERE/../../charts/aerolvm}"
HELM="${HELM:-helm}"
port="${DRILL_PORT:-21310}"
internet="${DRILL_INTERNET_URL:-http://example.com/}"
results="$sd/drills.txt"
: > "$results"
kc() { kubectl ${KUBECTL_CONTEXT:+--context "$KUBECTL_CONTEXT"} "$@"; }
hm() { "$HELM" ${KUBECTL_CONTEXT:+--kube-context "$KUBECTL_CONTEXT"} "$@"; }
say() { echo "$*" | tee -a "$sd/drills.log"; }
result() { echo "$1 $2 $3" | tee -a "$results" "$sd/drills.log"; }

kc -n "$ns" get secret aerolvm-admin -o jsonpath='{.data.token}' | base64 -d > "$sd/token"
chmod 600 "$sd/token"

# kpf runs kubectl port-forward as a plain command, not through kc: a
# shell function sent to the background is a subshell, and killing it
# leaves its kubectl running (it kept the port, and the next run's forward
# could not bind).
kpf() { exec kubectl ${KUBECTL_CONTEXT:+--context "$KUBECTL_CONTEXT"} -n "$ns" port-forward "$@" >/dev/null 2>&1; }

# forward keeps one port-forward to the gateway Service (or to one named
# gateway pod) on $port and waits for /health. A port-forward holds one pod
# and stops working when that pod's container restarts, which an upgrade
# does to every gateway: so a keeper starts it again, through the Service to
# a gateway that answers, whenever /health stops answering.
pf=""
stop_forward() {
  [[ -n "$pf" ]] || return 0
  local kids
  kids="$(pgrep -P "$pf" 2>/dev/null || true)"
  kill "$pf" 2>/dev/null || true
  [[ -z "$kids" ]] || kill $kids 2>/dev/null || true
  pf=""
}
forward() {
  local target="${1:-svc/aerolvm-gateway}" p="${2:-$port}"
  stop_forward
  (
    k=""
    trap '[[ -z "$k" ]] || kill "$k" 2>/dev/null; exit 0' TERM
    while :; do
      kpf "$target" "$p:21212" &
      k=$!
      sleep 5
      while kill -0 "$k" 2>/dev/null && curl -fsS --max-time 5 -o /dev/null "http://127.0.0.1:$p/health" 2>/dev/null; do sleep 5; done
      kill "$k" 2>/dev/null || true
      wait "$k" 2>/dev/null || true
      sleep 1
    done
  ) 2>/dev/null &
  pf=$!
  local _
  for _ in $(seq 1 30); do
    curl -fsS --max-time 3 -o /dev/null "http://127.0.0.1:$p/health" 2>/dev/null && return 0
    sleep 1
  done
  return 1
}
# zone_restore puts back the network ACLs zone-loss swapped, and deletes
# its deny-all ACL. The exit trap runs it too, so a run that dies mid-drill
# does not leave a zone cut off (and the VPC undeletable).
zl_restore=() zl_acl=""
zone_restore() {
  local r sn old assoc
  for r in ${zl_restore[@]+"${zl_restore[@]}"}; do
    sn="${r%%:*}" old="${r#*:}"
    assoc="$(awsr ec2 describe-network-acls --filters "Name=association.subnet-id,Values=$sn" \
      --query "NetworkAcls[0].Associations[?SubnetId=='$sn'].NetworkAclAssociationId | [0]" --output text)" &&
      awsr ec2 replace-network-acl-association --association-id "$assoc" --network-acl-id "$old" >/dev/null ||
      echo "drills.sh: could not give $sn its network ACL $old back" >&2
  done
  zl_restore=()
  if [[ -n "$zl_acl" ]]; then
    awsr ec2 delete-network-acl --network-acl-id "$zl_acl" >/dev/null || echo "drills.sh: could not delete $zl_acl" >&2
    zl_acl=""
  fi
}
trap 'zone_restore; stop_forward' EXIT
api() { python3 "$HERE/cell/api.py" --url "http://127.0.0.1:${API_PORT:-$port}" --token-file "$sd/token" "$@"; }
jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
# fetch <sandbox> <url>: exit 0 when the sandbox gets an answer from url.
fetch() { api exec "$1" --timeout 20 -- sh -c "wget -q -T 5 -O /dev/null '$2'" | jget 'd.get("exit_code", 1)'; }

# --- probe (C24) -------------------------------------------------------------
drill_probe() {
  local run="probe-$RANDOM" ip other open closed wrong
  kc create namespace drill-target --dry-run=client -o yaml | kc apply -f - >/dev/null
  kc -n drill-target run target --image=nginx:1.27-alpine --restart=Never --port=80 >/dev/null 2>&1 || true
  kc -n drill-target wait --for=condition=Ready pod/target --timeout=180s >/dev/null
  ip="$(kc -n drill-target get pod target -o jsonpath='{.status.podIP}')"
  other="$(kc -n "$ns" get pods -l app.kubernetes.io/component=gateway -o jsonpath='{.items[0].status.podIP}')"
  # The second wall: the worker pods' egress NetworkPolicy must let this
  # one range out too (networkPolicy.extraEgressCIDRs).
  hm upgrade "$release" "$chart" -n "$ns" --reuse-values --set-json "networkPolicy.extraEgressCIDRs=[\"$ip/32\"]" >/dev/null
  api put-profile drill-internal --allow-out "$ip/32" >/dev/null
  local opened plain
  opened="$(api create --run "$run" --n 1 --profile drill-internal | jget 'd[0]')"
  plain="$(api create --run "$run-p" --n 1 | jget 'd[0]')"
  api wait --run "$run" --n 1 >/dev/null; api wait --run "$run-p" --n 1 >/dev/null
  open="$(fetch "$opened" "http://$ip/")"
  closed="$(fetch "$plain" "http://$ip/")"
  wrong="$(fetch "$opened" "http://$other:21212/health")"
  api delete-run --run "$run" >/dev/null || true; api delete-run --run "$run-p" >/dev/null || true
  hm upgrade "$release" "$chart" -n "$ns" --reuse-values --set-json 'networkPolicy.extraEgressCIDRs=[]' >/dev/null
  kc delete namespace drill-target --wait=false >/dev/null
  if [[ "$open" == 0 && "$closed" != 0 && "$wrong" != 0 ]]; then
    result PASS probe "with the profile $ip answered; without it, refused; with it, a gateway ($other) refused"
  else
    result FAIL probe "opened range exit=$open (want 0), no profile exit=$closed (want non-0), other address exit=$wrong (want non-0)"
  fi
}

# --- bank-egress ---------------------------------------------------------------
drill_bank_egress() {
  local run="bank-$RANDOM" sb before after
  sb="$(api create --run "$run" --n 1 --allow-out 0.0.0.0/0 | jget 'd[0]')"
  api wait --run "$run" --n 1 >/dev/null
  before="$(fetch "$sb" "$internet")"
  # The bank replaces the chart's egress policy with its own: AerolVM's pods
  # and the cluster DNS only, never the internet.
  hm upgrade "$release" "$chart" -n "$ns" --reuse-values --set networkPolicy.enabled=false >/dev/null
  kc -n "$workers" apply -f - >/dev/null <<YAML
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: bank-deny-egress }
spec:
  podSelector: { matchLabels: { app.kubernetes.io/component: worker } }
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: $ns } }
        - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: $workers } }
    - to: [{ namespaceSelector: {}, podSelector: { matchLabels: { k8s-app: kube-dns } } }]
      ports: [{ protocol: UDP, port: 53 }, { protocol: TCP, port: 53 }]
YAML
  sleep 10
  after="$(fetch "$sb" "$internet")"
  local alive
  alive="$(api exec "$sb" -- true | jget 'd.get("exit_code", 1)')"
  kc -n "$workers" delete networkpolicy bank-deny-egress >/dev/null
  hm upgrade "$release" "$chart" -n "$ns" --reuse-values --set networkPolicy.enabled=true >/dev/null
  api delete-run --run "$run" >/dev/null || true
  if [[ "$after" != 0 && "$alive" == 0 ]]; then
    result PASS bank-egress "allow-all sandbox: internet before=$before, under the bank policy refused (exit $after); exec still works"
  else
    result FAIL bank-egress "under the bank policy internet exit=$after (want non-0), exec exit=$alive (want 0)"
  fi
}

# --- gateway-stream --------------------------------------------------------------
drill_gateway_stream() {
  local run="gw-$RANDOM" sb sid a b n1 n2 log2
  forward >/dev/null
  sb="$(api create --run "$run" --n 1 | jget 'd[0]')"
  api wait --run "$run" --n 1 >/dev/null
  sid="$(api session-start "$sb" -- sh -c 'i=0; while [ $i -lt 600 ]; do echo tick $i; i=$((i+1)); sleep 1; done' | jget 'd.get("id")')"
  read -r a b < <(kc -n "$ns" get pods -l app.kubernetes.io/component=gateway -o jsonpath='{.items[0].metadata.name} {.items[1].metadata.name}')
  forward "pod/$a" $((port + 1)) || { result FAIL gateway-stream "no forward to $a"; return; }
  sleep 5
  n1="$(API_PORT=$((port + 1)) api session-log "$sb" "$sid" | jget 'd["log"].count("tick")')"
  kc -n "$ns" delete pod "$a" --wait=false >/dev/null
  forward "pod/$b" $((port + 2)) || { result FAIL gateway-stream "no forward to $b"; return; }
  sleep 5
  log2="$(API_PORT=$((port + 2)) api session-log "$sb" "$sid" | jget 'd["log"]')"
  n2="$(grep -c '^tick' <<<"$log2" || true)"
  local gaps
  gaps="$(awk '/^tick/ {if ($2 != n) bad++; n=$2+1} END {print bad+0}' <<<"$log2")"
  forward >/dev/null
  api delete-run --run "$run" >/dev/null || true
  if [[ "$n2" -gt "$n1" && "$gaps" == 0 ]]; then
    result PASS gateway-stream "read $n1 lines through $a, killed it, read $n2 through $b with none missing"
  else
    result FAIL gateway-stream "through $a: $n1 lines; through $b: $n2 lines, $gaps gaps"
  fi
}

# --- api-down ----------------------------------------------------------------------
drill_api_down() {
  local secs="${DRILL_API_DOWN_SECONDS:-600}" run="api-$RANDOM" ok=0 bad=0 t0
  forward >/dev/null
  # The operator is AerolVM's only pod that talks to the API server. Its
  # egress becomes AerolVM's own pods and DNS only. An "everything but the
  # API server" ipBlock was not enforced for the API server's address on
  # kind (kindnet), so the API server is left out rather than excepted.
  kc -n "$ns" apply -f - >/dev/null <<YAML
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: drill-no-kube-api }
spec:
  podSelector: { matchLabels: { app.kubernetes.io/component: operator } }
  policyTypes: [Egress]
  egress:
    - to: [{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: $ns } } }]
    - to: [{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: $workers } } }]
    - to: [{ namespaceSelector: {}, podSelector: { matchLabels: { k8s-app: kube-dns } } }]
      ports: [{ protocol: UDP, port: 53 }, { protocol: TCP, port: 53 }]
YAML
  # A policy judges new connections only, and the operator holds one open
  # to the API server (a run on kind kept renewing its Lease through the
  # policy). New operator pods start under it, with no way to the API.
  kc -n "$ns" delete pod -l app.kubernetes.io/component=operator --wait=false >/dev/null
  t0=$(date +%s)
  local renewed_mid=""
  while (( $(date +%s) - t0 < secs )); do
    # Halfway in, the leader must have stopped renewing its Lease: proof the
    # operator really lost the API server.
    [[ -z "$renewed_mid" ]] && (( $(date +%s) - t0 > secs / 2 )) && renewed_mid="$(lease_renewed)"
    local sb e
    if sb="$(api create --run "$run" --n 1 | jget 'd[0]')" && api wait --run "$run" --n 1 --timeout 120 >/dev/null; then
      e="$(api exec "$sb" -- echo ok | jget 'd.get("exit_code", 1)')"
      [[ "$e" == 0 ]] && ok=$((ok + 1)) || bad=$((bad + 1))
    else
      bad=$((bad + 1))
    fi
    api delete-run --run "$run" >/dev/null || true
    run="api-$RANDOM"
    sleep 10
  done
  kc -n "$ns" delete networkpolicy drill-no-kube-api >/dev/null
  # Cut off means the Lease was last renewed before the halfway point, with
  # 20 s for the renewals in flight when the policy landed.
  local cut=no
  [[ -n "$renewed_mid" ]] && (( renewed_mid < t0 + 20 )) && cut=yes
  if [[ "$bad" == 0 && "$ok" -gt 0 && "$cut" == yes ]]; then
    result PASS api-down "${secs}s with the operator cut off (its Lease last renewed $((renewed_mid - t0))s in): $ok create+exec rounds, 0 failed"
  else
    result FAIL api-down "${secs}s: operator cut off=$cut (Lease renewed $(( ${renewed_mid:-0} - t0 ))s in), $ok rounds worked, $bad failed"
  fi
  # api-recover: once the policy is gone, the operator must come back by
  # itself (its Lease renewed again). On EKS (aws-network-policy-agent
  # v1.4.0-eksbuild.4) the pods started under the policy kept a deny-all
  # after it was deleted ("PE belongs to same NP. Ignore and move on since
  # it's a delete flow"), crash-looped on their liveness probe, and only
  # new pods recovered. Either way the drill leaves a working operator for
  # the drills after it.
  local t1 back="" back_new=""
  t1=$(date +%s)
  for _ in $(seq 1 36); do
    (( $(lease_renewed) > t1 )) && { back=$(( $(date +%s) - t1 )); break; }
    sleep 5
  done
  if [[ -n "$back" ]]; then
    result PASS api-recover "the operator renewed its Lease ${back}s after the policy went"
    return
  fi
  kc -n "$ns" delete pod -l app.kubernetes.io/component=operator --wait=false >/dev/null
  t1=$(date +%s)
  for _ in $(seq 1 36); do
    (( $(lease_renewed) > t1 )) && { back_new=$(( $(date +%s) - t1 )); break; }
    sleep 5
  done
  result FAIL api-recover "the operator did not renew its Lease within 180 s of the policy going; new operator pods did after ${back_new:-never}s (pods started under a deleted egress policy can keep its deny on EKS's network policy agent)"
}

# --- delete-guard (C26) ---------------------------------------------------------------
drill_delete_guard() {
  local w out lost0 lost1
  w="$(kc -n "$workers" get pods -l app.kubernetes.io/component=worker -o jsonpath='{.items[0].metadata.name}')"
  lost0="$(worker_pods_lost)"
  out="$(kc -n "$workers" delete pod "$w" --wait=false 2>&1 || true)"
  if ! kc -n "$workers" get pod "$w" >/dev/null 2>&1 || ! grep -q "denied" <<<"$out"; then
    result FAIL delete-guard "a plain delete of $w was not refused: $out"
    return
  fi
  kc -n "$workers" annotate pod "$w" aerolvm.io/force-delete=true --overwrite >/dev/null
  out="$(kc -n "$workers" delete pod "$w" --wait=false 2>&1 || true)"
  sleep 20
  lost1="$(worker_pods_lost)"
  if grep -q "recorded" <<<"$out" && [[ "$lost1" -gt "$lost0" ]]; then
    result PASS delete-guard "plain delete refused; forced delete went through with a warning; worker_pods_lost $lost0 -> $lost1"
  else
    result FAIL delete-guard "forced delete output: $out; worker_pods_lost $lost0 -> $lost1"
  fi
}

# operator_leader is the operator pod holding the leader Lease.
operator_leader() {
  local h
  h="$(kc -n "$ns" get lease aerolvm-operator.aerolvm.io -o jsonpath='{.spec.holderIdentity}')"
  echo "${h%%_*}"
}

# worker_pods_lost reads the leader's aerolvm_operator_worker_pods_lost_total.
# Through a port-forward: the operator's NetworkPolicy lets the API server
# reach its webhook port only, so the API server's pod proxy cannot.
worker_pods_lost() {
  local op v fpid
  op="$(operator_leader)"
  kpf "pod/$op" $((port + 9)):8080 &
  fpid=$!
  sleep 3
  v="$(curl -s --max-time 5 "http://127.0.0.1:$((port + 9))/metrics" | awk '/^aerolvm_operator_worker_pods_lost_total/ {s += $2} END {print s+0}')"
  kill "$fpid" 2>/dev/null || true
  echo "${v%.*}"
}

# lease_renewed is the operator leader Lease's renewTime, in Unix seconds.
lease_renewed() {
  local t
  t="$(kc -n "$ns" get lease aerolvm-operator.aerolvm.io -o jsonpath='{.spec.renewTime}')"
  python3 -c "import datetime,sys; print(int(datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')).timestamp()))" "$t"
}

forward || { echo "drills.sh: no gateway answers on $port" >&2; exit 2; }
# --- zone-loss (G1) ---------------------------------------------------------------
# snap <file> <label>: one timestamped picture of the cluster, appended to
# <state-dir>/<file>: every AerolNode's state and reason, the worker pods
# and where they run, and the machines. A drill that takes minutes writes
# one a minute, so a failure has a timeline to read.
snap() {
  {
    echo "=== $2 $(date -u +%T)"
    kc -n "$ns" get aerolnodes -o json 2>/dev/null |
      jq -r '.items[] | "node \(.metadata.name) \(.spec.role) \(.spec.zone // "-") \(.status.state // "-") pod=\(.status.podName // "-") on=\(.status.nodeName // "-") \(.status.reason // "")"'
    kc -n "$workers" get pods -o json 2>/dev/null |
      jq -r '.items[] | "pod \(.metadata.name) \(.status.phase) on=\(.spec.nodeName // "-") ready=\([.status.containerStatuses[]? | select(.ready) | .name] | join(",")) restarts=\([.status.containerStatuses[]?.restartCount] | add // 0) \([.status.conditions[]? | select(.status == "False") | .message // empty] | join("; "))"'
    kc get nodes -o json 2>/dev/null |
      jq -r '.items[] | "machine \(.metadata.name) \(.metadata.labels["topology.kubernetes.io/zone"] // "-") ready=\([.status.conditions[] | select(.type == "Ready") | .status][0]) cordoned=\(.spec.unschedulable // false) pool=\(.metadata.labels["aerolvm.io/pool"] // "-") image=\(.status.nodeInfo.osImage) kernel=\(.status.nodeInfo.kernelVersion) made=\(.metadata.creationTimestamp)"'
  } >> "$sd/$1" 2>&1
}

# evidence <drill>: what a failed drill leaves for whoever reads it, in
# <state-dir>/evidence/<drill>/: the AerolNodes, both namespaces' pods and
# warning events, the operator's log, each worker pod's description and
# its containers' logs, and AerolVM's member list.
evidence() {
  local dir="$sd/evidence/$1" p c
  mkdir -p "$dir"
  snap "evidence/$1/snap.txt" "$1"
  kc -n "$ns" get aerolnodes -o yaml > "$dir/aerolnodes.yaml" 2>&1 || true
  kc -n "$ns" get pods -o wide > "$dir/pods-$ns.txt" 2>&1 || true
  kc -n "$workers" get pods -o wide > "$dir/pods-$workers.txt" 2>&1 || true
  kc -n "$ns" get events --sort-by=.lastTimestamp > "$dir/events-$ns.txt" 2>&1 || true
  kc -n "$workers" get events --sort-by=.lastTimestamp > "$dir/events-$workers.txt" 2>&1 || true
  for p in $(kc -n "$ns" get pods -l app.kubernetes.io/component=operator -o name 2>/dev/null); do
    kc -n "$ns" logs "$p" --tail=400 > "$dir/operator-${p#pod/}.log" 2>&1 || true
  done
  for p in $(kc -n "$workers" get pods -o name 2>/dev/null); do
    kc -n "$workers" describe "$p" > "$dir/${p#pod/}.describe.txt" 2>&1 || true
    for c in $(kc -n "$workers" get "$p" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}' 2>/dev/null); do
      kc -n "$workers" logs "$p" -c "$c" --tail=300 > "$dir/${p#pod/}.$c.log" 2>&1 || true
    done
  done
  api members > "$dir/members.json" 2>&1 || true
  say "$1: evidence in $dir"
}

eks_only() {
  if [[ -z "${DRILL_EKS_CLUSTER:-}" || -z "${DRILL_AWS_REGION:-}" ]]; then
    result FAIL "$1" "EKS only: set DRILL_EKS_CLUSTER and DRILL_AWS_REGION (cell.sh does)"
    return 1
  fi
}
awsr() { aws --region "$DRILL_AWS_REGION" "$@"; }

drill_zone_loss() {
  eks_only zone-loss || return 0
  local secs="${DRILL_ZONE_SECONDS:-240}" run="zone-$RANDOM" zone gw vpc subnets acl assoc old
  zone="${DRILL_ZONE:-$(kc -n "$ns" get aerolnode aerolvm-server-2 -o jsonpath='{.spec.zone}')}"
  gw="$(kc -n "$ns" get pods -l app.kubernetes.io/component=gateway -o json |
    jq -r --arg z "$zone" '[.items[] | select(.metadata.labels["topology.kubernetes.io/zone"] != $z)][0].metadata.name')"
  forward "pod/$gw" || { result FAIL zone-loss "no gateway outside $zone answers"; return; }
  api create --run "$run" --n 15 --recreate >/dev/null
  api wait --run "$run" --n 15 --timeout 300 >/dev/null || { result FAIL zone-loss "the 15 sandboxes did not start"; return; }
  # Which of them live in the zone about to go.
  local members inzone=() id o keeper=""
  members="$(api members)"
  for id in $(api list --run "$run" | jq -r '.[].id'); do
    o="$(api owner "$id" | jq -r .owner)"
    if [[ "$(jq -r --arg n "$o" '.[] | select(.node_id == $n) | .zone' <<<"$members")" == "$zone" ]]; then
      inzone+=("$id")
    elif [[ -z "$keeper" ]]; then
      keeper="$id"
    fi
  done
  vpc="$(awsr eks describe-cluster --name "$DRILL_EKS_CLUSTER" --query cluster.resourcesVpcConfig.vpcId --output text)"
  subnets="$(awsr ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc" "Name=availability-zone,Values=$zone" --query 'Subnets[].SubnetId' --output text)"
  acl="$(awsr ec2 create-network-acl --vpc-id "$vpc" --query NetworkAcl.NetworkAclId --output text)"
  zl_acl="$acl"
  awsr ec2 create-tags --resources "$acl" --tags Key=Name,Value="drill-zone-loss-$DRILL_EKS_CLUSTER" >/dev/null
  for sn in $subnets; do
    read -r assoc old < <(awsr ec2 describe-network-acls --filters "Name=association.subnet-id,Values=$sn" \
      --query "NetworkAcls[0].[Associations[?SubnetId=='$sn'].NetworkAclAssociationId | [0], NetworkAclId]" --output text)
    zl_restore+=("$sn:$old")
    awsr ec2 replace-network-acl-association --association-id "$assoc" --network-acl-id "$acl" >/dev/null
  done
  local t0 now fails=0 worst=0 down_since="" back=0 back60="" tries=0 out
  t0=$(date +%s)
  say "zone-loss: $zone cut off at $(date -u +%T): ${#inzone[@]} of 15 sandboxes there, subnets $subnets"
  snap zone-loss.txt "start of the cut"
  while (( $(date +%s) - t0 < secs )); do
    now=$(date +%s)
    # A new key each time: the same key would answer with the first create.
    tries=$((tries + 1))
    if out="$(api create --run "$run-c" --n 1 --nonce "$tries" 2>&1)"; then
      [[ -n "$down_since" ]] && (( now - down_since > worst )) && worst=$((now - down_since))
      down_since=""
    else
      fails=$((fails + 1)); [[ -z "$down_since" ]] && down_since=$now
      # What failed and how long it took: which hop (placement, the
      # reservation, the forward) and whether it waited out a timeout.
      say "zone-loss: +$(( now - t0 ))s create $tries failed after $(( $(date +%s) - now ))s: $(head -c 400 <<<"$out")"
    fi
    back=0
    for id in "${inzone[@]}"; do
      o="$(api owner "$id" 2>/dev/null | jq -r .owner 2>/dev/null || true)"
      st="$(api get "$id" 2>/dev/null | jq -r .status 2>/dev/null || true)"
      [[ -n "$o" && "$st" == started ]] && [[ "$(jq -r --arg n "$o" '.[] | select(.node_id == $n) | .zone' <<<"$members")" != "$zone" ]] && back=$((back + 1))
    done
    [[ -z "$back60" ]] && (( now - t0 >= 60 )) && back60=$back
    (( back == ${#inzone[@]} )) && [[ -z "${all_back:-}" ]] && all_back=$((now - t0))
    sleep 5
  done
  [[ -n "$down_since" ]] && worst=$(( $(date +%s) - down_since ))
  local alive
  alive="$( [[ -n "$keeper" ]] && api exec "$keeper" -- true | jq -r .exit_code || echo 1)"
  snap zone-loss.txt "end of the cut"
  zone_restore
  say "zone-loss: $zone back at $(date -u +%T)"
  # The next drills go through the Service again, not the one gateway pod.
  forward || true
  api delete-run --run "$run" >/dev/null || true; api delete-run --run "$run-c" >/dev/null || true
  local detail="$zone cut ${secs}s; creates failed $fails of $tries, longest gap ${worst}s; ${#inzone[@]} recreate sandboxes in it: ${back60:-?} back in 60 s, all back after ${all_back:-never}s; a sandbox elsewhere exec=$alive"
  unset all_back
  if (( worst <= 30 )) && [[ "$alive" == 0 && -n "${detail}" ]] && (( back == ${#inzone[@]} )); then
    result PASS zone-loss "$detail"
  else
    result FAIL zone-loss "$detail"
    evidence zone-loss
  fi
}

# --- disk-full (C27) -----------------------------------------------------------------
# Two parts, on one worker, with a neighbour sandbox there that must keep
# working and a worker pod that must not be evicted.
#   disk-own    a writer with a 2 GB disk: the disk watchdog stops it
#               (status_reason disk_limit) before it hurts anyone.
#   disk-floor  a writer allowed more than the room above the floor pushes
#               the sandbox volume below it: the worker refuses new sandboxes
#               (can_admit false, a disk reason), the writer still stops at
#               its own limit, and once it is gone the worker admits again.
# The cell's sandbox volume is the machine's root disk (an emptyDir), where
# kubelet's default eviction lines (imagefs 15% free, nodefs 10%) sit at or
# above the chart's default floor of 10%: so the cell sets the floor to 0.30
# (cell/values.yaml), disk-floor stops 3 points under it, and it logs the
# machine's real evictionHard. It runs only when disk-own showed the
# watchdog stops a writer, so a broken watchdog cannot fill the disk.

# on_worker <run> <disk_gb> <worker>: one sandbox placed on that worker,
# found by creating until one lands there.
on_worker() {
  local i id
  for i in $(seq 1 12); do
    id="$(api create --run "$1-$i" --n 1 --disk-gb "$2" | jget 'd[0]')" || continue
    api wait --run "$1-$i" --n 1 >/dev/null || continue
    if [[ "$(api owner "$id" | jq -r .owner)" == "$3" ]]; then echo "$id"; return 0; fi
    api delete-run --run "$1-$i" >/dev/null || true
  done
  return 1
}
# writer_stop <id> <secs>: waits for a writer to leave "started"; prints
# "<status> <reason> <seconds>".
writer_stop() {
  local t0 st="" reason=""
  t0=$(date +%s)
  while (( $(date +%s) - t0 < $2 )); do
    read -r st reason < <(api get "$1" | jq -r '"\(.status) \(.status_reason // "-")"')
    [[ "$st" != started ]] && break
    sleep 10
  done
  echo "$st $reason $(( $(date +%s) - t0 ))"
}
# writer_why <id> <worker>: why a writer stopped, as the sandbox record and
# the worker's own log tell it: exit code, last error, and the agent's lines
# about it (the stop's mode and reason, the disk watchdog, an OOM).
writer_why() {
  api get "$1" | jq -c '{exit_code, status_reason, last_error}' 2>/dev/null || true
  kc -n "$workers" logs "$2" -c agent --since=15m 2>/dev/null | grep -v "request complete" |
    grep -e "$1" -e "disk watchdog" -e "oom" -e "OOM" | tail -20 || true
}
worker_health() {  # <worker> <pod uid>: "ok" or what went wrong
  local bad=""
  [[ "$(api exec "$keeper" -- true | jq -r .exit_code 2>/dev/null)" == 0 ]] || bad+="neighbour failed; "
  [[ "$(kc -n "$workers" get pod "$1" -o jsonpath='{.metadata.uid}' 2>/dev/null)" == "$2" ]] || bad+="worker pod evicted or replaced; "
  [[ "$(kc -n "$workers" get pod "$1" -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].ready}' 2>/dev/null)" == true ]] || bad+="agent not ready; "
  echo "${bad:-ok}"
}
member_of() { api members | jq -c --arg n "$1" '.[] | select(.node_id == $n)'; }

drill_disk_full() {
  eks_only disk-full || return 0
  local run="disk-$RANDOM" w pod keeper writer m free total health
  local floor="${DRILL_DISK_FLOOR:-0.30}" mins="${DRILL_DISK_MINUTES:-20}"
  keeper="$(api create --run "$run-k" --n 1 | jget 'd[0]')"; api wait --run "$run-k" --n 1 >/dev/null
  w="$(api owner "$keeper" | jq -r .owner)"
  pod="$(kc -n "$workers" get pod "$w" -o jsonpath='{.metadata.uid}')"
  disk_cleanup() {
    local r i
    for r in "$run-a" "$run-b" "$run-after"; do
      for i in $(seq 1 12); do api delete-run --run "$r-$i" >/dev/null 2>&1 || true; done
    done
    api delete-run --run "$run-k" >/dev/null 2>&1 || true
  }
  # disk-own
  writer="$(on_worker "$run-a" 2 "$w")" || { result FAIL disk-own "no sandbox landed on $w in 12 tries"; disk_cleanup; return; }
  api session-start "$writer" -- sh -c 'dd if=/dev/zero of=/fill bs=1M; sleep 86400' >/dev/null
  local st reason secs
  read -r st reason secs < <(writer_stop "$writer" 360)
  health="$(worker_health "$w" "$pod")"
  say "disk-own: writer $st ($reason) after ${secs}s; $w: $health"
  if [[ "$st" == stopped && "$reason" == disk_limit && "$health" == ok ]]; then
    result PASS disk-own "a writer with a 2 GB disk was stopped by the watchdog after ${secs}s (disk_limit); its neighbour and $w's agent kept working"
  else
    say "disk-own: why the writer stopped:"
    writer_why "$writer" "$w" | sed 's/^/  /' | tee -a "$sd/drills.log"
    m="$(member_of "$w")"
    say "disk-own: $w has $(jq -r '.disk_free_mb // "?"' <<<"$m") of $(jq -r '.disk_total_mb // "?"' <<<"$m") MB free"
    result FAIL disk-own "writer $st ($reason) after ${secs}s; $w: $health"
    evidence disk-own
    disk_cleanup
    result FAIL disk-floor "not run: disk-own did not show the watchdog stopping a writer"
    return
  fi
  # disk-floor: write to 3 points under the floor; the writer may go 1 GB on.
  m="$(member_of "$w")"
  free="$(jq -r '.disk_free_mb // 0' <<<"$m")"; total="$(jq -r '.disk_total_mb // 0' <<<"$m")"
  local need gb
  need="$(python3 -c "print(max(0, int($free - ($floor - 0.03) * $total)))")"
  gb=$(( need / 1024 + 1 ))
  local node evict
  node="$(kc -n "$workers" get pod "$w" -o jsonpath='{.spec.nodeName}')"
  evict="$(kc get --raw "/api/v1/nodes/$node/proxy/configz" 2>/dev/null | jq -c '.kubeletconfig.evictionHard' || echo unknown)"
  say "disk-floor: $w has $free of $total MB free, floor $floor: a writer with $gb GB; kubelet evictionHard on $node: $evict"
  writer="$(on_worker "$run-b" "$gb" "$w")" || { result FAIL disk-floor "no sandbox landed on $w in 12 tries"; disk_cleanup; return; }
  api session-start "$writer" -- sh -c 'dd if=/dev/zero of=/fill bs=1M; sleep 86400' >/dev/null
  local t0 refused=no low="" reasons=""
  t0=$(date +%s)
  while (( $(date +%s) - t0 < mins * 60 )); do
    m="$(member_of "$w")"
    free="$(jq -r '.disk_free_mb // 0' <<<"$m")"
    if [[ "$(jq -r .can_admit <<<"$m")" == false ]] && jq -r '.reasons | join(" ")' <<<"$m" | grep -qi disk; then
      refused=yes; low="$free"; reasons="$(jq -r '.reasons | join("; ")' <<<"$m")"
    fi
    [[ "$(api get "$writer" | jq -r .status)" != started && "$refused" == yes ]] && break
    health="$(worker_health "$w" "$pod")"
    [[ "$health" == ok ]] || break
    sleep 15
  done
  read -r st reason secs < <(writer_stop "$writer" 60)
  health="$(worker_health "$w" "$pod")"
  local elsewhere
  elsewhere="$(api create --run "$run-after-1" --n 1 >/dev/null 2>&1 && api owner "$(api list --run "$run-after-1" | jq -r '.[0].id')" | jq -r .owner || echo refused)"
  # Gone again: the worker admits once the writers' layers are deleted.
  disk_cleanup
  local again=no
  for _ in $(seq 1 18); do
    [[ "$(member_of "$w" | jq -r .can_admit)" == true ]] && { again=yes; break; }
    sleep 10
  done
  local detail="$w refused new sandboxes: $refused (at $low of $total MB free: $reasons); writer $st ($reason); a create then went to ${elsewhere}; $w: $health; admitting again after cleanup: $again"
  if [[ "$refused" == yes && "$st" == stopped && "$health" == ok && "$elsewhere" != "$w" && "$elsewhere" != refused && "$again" == yes ]]; then
    result PASS disk-floor "$detail"
  else
    result FAIL disk-floor "$detail"
    evidence disk-floor
  fi
}

# --- rollout (G8, G9, C13, C26) ---------------------------------------------------------
# rollout_state is the rollout's state, "none" when there is no rollout
# (404), and "unreachable" when the API did not answer.
rollout_state() { api raw GET /v1/cluster/upgrade | jq -r 'if .code == 0 then "unreachable" elif .code == 404 then "none" else (.body.state // "unknown") end'; }
wait_rollout() {
  local want="$1" secs="$2" t0 st=""
  t0=$(date +%s)
  while (( $(date +%s) - t0 < secs )); do
    st="$(rollout_state 2>/dev/null || true)"
    [[ " $want " == *" $st "* ]] && { echo "$st"; return 0; }
    sleep 10
  done
  echo "$st"; return 1
}
# agent_started prints "pod time" for every AerolVM pod: when its agent
# container last started, which in an upgrade is when the node took its turn.
agent_started() {
  local n
  for n in "$ns" "$workers"; do
    kc -n "$n" get pods -l app.kubernetes.io/name=aerolvm -o json |
      jq -r '.items[] | .metadata.name as $p | (.status.containerStatuses // [])[] | select(.name == "agent") | "\($p) \(.state.running.startedAt // "")"'
  done
}
# restarts prints "pod container count" for every AerolVM pod.
restarts() {
  local n
  for n in "$ns" "$workers"; do
    kc -n "$n" get pods -l app.kubernetes.io/name=aerolvm -o json |
      jq -r '.items[] | .metadata.name as $p | (.status.containerStatuses // [])[] | "\($p) \(.name) \(.restartCount)"'
  done
}

drill_rollout() {
  local b="${DRILL_VERSION_B:-}" mins="${DRILL_MIXED_MINUTES:-60}" run="ro-$RANDOM" st
  [[ -n "$b" ]] || { result FAIL rollout "set DRILL_VERSION_B (cell.sh build2 makes its images)"; return; }
  api create --run "$run" --n 6 --recreate >/dev/null && api create --run "$run-p" --n 3 >/dev/null
  api wait --run "$run" --n 6 >/dev/null && api wait --run "$run-p" --n 3 >/dev/null || { result FAIL rollout "sandboxes did not start"; return; }
  local pairs=() id sid
  for id in $(api list --run "$run" | jq -r '.[].id') $(api list --run "$run-p" | jq -r '.[].id'); do
    sid="$(api session-start "$id" -- sleep 86400 | jq -r .id)"
    pairs+=("$id:$sid")
  done
  restarts > "$sd/restarts-before.txt"
  # The rollout the operator would start, paused after the first worker:
  # then spec.version names the same target and the operator carries it on.
  st="$(api raw POST '/v1/cluster/upgrade?driver=operator' "{\"version\":\"$b\",\"source\":\"images\",\"batch\":\"1\",\"pause_after\":1,\"node_timeout\":\"15m\"}" | jq -c .)"
  say "rollout: apply -> $st"
  kc -n "$ns" patch aerolcluster aerolvm --type merge -p "{\"spec\":{\"version\":\"$b\"}}" >/dev/null
  if ! st="$(wait_rollout "paused" 2400)"; then
    result FAIL rollout-mixed "never paused after the first worker (state $st)"
  else
    # G9: N and N-1 together.
    local t0 ok=0 bad=0 sb
    t0=$(date +%s)
    while (( $(date +%s) - t0 < mins * 60 )); do
      # A fresh run (and so fresh idempotency keys) each round.
      local rm="$run-m$((ok + bad))"
      if sb="$(api create --run "$rm" --n 1 | jget 'd[0]')" && api wait --run "$rm" --n 1 --timeout 120 >/dev/null &&
         [[ "$(api exec "$sb" -- echo ok | jq -r .exit_code)" == 0 ]]; then ok=$((ok + 1)); else bad=$((bad + 1)); fi
      api delete-run --run "$rm" >/dev/null || true
      sleep 30
    done
    [[ "$bad" == 0 && "$ok" -gt 0 ]] && result PASS rollout-mixed "${mins} min on mixed versions: $ok rounds, 0 failed" ||
      result FAIL rollout-mixed "${mins} min on mixed versions: $ok rounds, $bad failed"
    # C26 mid-rollout: a plain delete is refused.
    local w out
    w="$(kc -n "$workers" get pods -l app.kubernetes.io/component=worker -o jsonpath='{.items[0].metadata.name}')"
    out="$(kc -n "$workers" delete pod "$w" --wait=false 2>&1 || true)"
    if grep -q denied <<<"$out" && kc -n "$workers" get pod "$w" >/dev/null 2>&1; then
      result PASS rollout-guard "a plain delete of $w mid-rollout was refused"
    else
      result FAIL rollout-guard "a plain delete of $w mid-rollout: $out"
    fi
  fi
  # C13: resume, then kill the operator and Raft leaders together.
  if ! api raw POST '/v1/cluster/upgrade/resume?driver=operator' >/dev/null; then
    result FAIL rollout-leaders "resume refused: $(api raw POST '/v1/cluster/upgrade/resume?driver=operator' | jq -c .)"
    return
  fi
  sleep 45
  local opl raftl
  opl="$(operator_leader)"; raftl="$(api raw GET /v1/cluster/leader | jq -r '.body.leader // empty')"
  [[ -n "$opl" && -n "$raftl" ]] || { result FAIL rollout-leaders "no leader to kill (operator '$opl', Raft '$raftl')"; return; }
  kc -n "$ns" delete pod "$opl" "$raftl" --wait=false >/dev/null
  say "rollout: killed operator leader $opl and Raft leader $raftl at $(date -u +%T)"
  forward >/dev/null || true
  st="$(wait_rollout "done finalized" 3600)" || true
  restarts > "$sd/restarts-after.txt"
  # No pod stepped twice: each container restarted at most once more, the
  # runtime containers (they hold the sandboxes) not at all. The two killed
  # pods are new pods and are left out.
  local twice runtime_restarts
  twice="$(awk -v a="$opl" -v r="$raftl" 'NR==FNR {b[$1" "$2]=$3; next} ($1 != a && $1 != r) && (($1" "$2) in b) && $3 - b[$1" "$2] > 1 {print $1"/"$2}' "$sd/restarts-before.txt" "$sd/restarts-after.txt" | tr '\n' ' ')"
  runtime_restarts="$(awk 'NR==FNR {b[$1" "$2]=$3; next} $2 == "runtime" && (($1" "$2) in b) && $3 > b[$1" "$2] {print $1}' "$sd/restarts-before.txt" "$sd/restarts-after.txt" | tr '\n' ' ')"
  # The leader's order held when the agents started in it. Not the
  # rollout's updated_at: that is each node's last write, and finalize
  # writes every node. The killed Raft leader's pod is new and left out.
  local order
  order="$(api raw GET /v1/cluster/upgrade | jq -r '.body.nodes // [] | sort_by(.order) | .[].node_id' |
    awk -v skip="$raftl" 'NR == FNR {t[$1] = $2; next} $1 != skip && ($1 in t) {print t[$1]}' <(agent_started) - |
    { if sort -c 2>/dev/null; then echo "in order"; else echo "out of order"; fi; })"
  if [[ "$st" == done || "$st" == finalized ]] && [[ -z "$twice" && "$order" == "in order" ]]; then
    result PASS rollout-leaders "the rollout reached $st after both leaders were killed; nodes done $order; no pod stepped twice"
  else
    result FAIL rollout-leaders "rollout state $st; nodes $order; stepped twice: ${twice:-none}"
  fi
  # G8: every sandbox still runs its session.
  local dead=0
  for p in "${pairs[@]}"; do
    [[ "$(api session-get "${p%%:*}" "${p#*:}" | jq -r .status 2>/dev/null)" == running ]] || dead=$((dead + 1))
  done
  if [[ "$dead" == 0 && -z "$runtime_restarts" ]]; then
    result PASS rollout-restarts "${#pairs[@]} sandboxes kept their session through the whole upgrade; no runtime container restarted"
  else
    result FAIL rollout-restarts "$dead of ${#pairs[@]} sessions ended; runtime containers restarted: ${runtime_restarts:-none}"
  fi
  api delete-run --run "$run" >/dev/null || true; api delete-run --run "$run-p" >/dev/null || true
}

# --- rotation (G8) ----------------------------------------------------------------------
drill_rotation() {
  eks_only rotation || return 0
  local run="rot-$RANDOM" ng lt latest new upd st t0
  api create --run "$run" --n 6 --recreate >/dev/null && api create --run "$run-p" --n 3 >/dev/null
  api wait --run "$run" --n 6 >/dev/null && api wait --run "$run-p" --n 3 >/dev/null || { result FAIL rotation "sandboxes did not start"; return; }
  # The IDs before the rotation: one that is gone afterwards must count as
  # gone, not drop out of a list made afterwards.
  local recreate_ids plain_ids
  recreate_ids="$(api list --run "$run" | jq -r '.[].id')"
  plain_ids="$(api list --run "$run-p" | jq -r '.[].id')"
  ng="$(awsr eks list-nodegroups --cluster-name "$DRILL_EKS_CLUSTER" --query 'nodegroups[?starts_with(@, `worker-`)] | [0]' --output text)"
  local rel0
  rel0="$(awsr eks describe-nodegroup --cluster-name "$DRILL_EKS_CLUSTER" --nodegroup-name "$ng" --query nodegroup.releaseVersion --output text)"
  lt="$(awsr eks describe-nodegroup --cluster-name "$DRILL_EKS_CLUSTER" --nodegroup-name "$ng" --query nodegroup.launchTemplate.id --output text)"
  latest="$(awsr ec2 describe-launch-templates --launch-template-ids "$lt" --query 'LaunchTemplates[0].LatestVersionNumber' --output text)"
  # A new version that changes nothing but a tag: every machine is replaced
  # all the same, which is what a new machine image does.
  new="$(awsr ec2 create-launch-template-version --launch-template-id "$lt" --source-version "$latest" \
    --launch-template-data "{\"TagSpecifications\":[{\"ResourceType\":\"instance\",\"Tags\":[{\"Key\":\"drill-rotation\",\"Value\":\"$run\"}]}]}" \
    --query LaunchTemplateVersion.VersionNumber --output text)"
  upd="$(awsr eks update-nodegroup-version --cluster-name "$DRILL_EKS_CLUSTER" --nodegroup-name "$ng" \
    --launch-template "id=$lt,version=$new" --query update.id --output text)"
  say "rotation: node group $ng to launch template $lt version $new (update $upd) at $(date -u +%T); AMI release $rel0"
  snap rotation.txt "update started"
  t0=$(date +%s)
  while (( $(date +%s) - t0 < 5400 )); do
    st="$(awsr eks describe-update --name "$DRILL_EKS_CLUSTER" --nodegroup-name "$ng" --update-id "$upd" --query update.status --output text)"
    [[ "$st" == Successful || "$st" == Failed || "$st" == Cancelled ]] && break
    snap rotation.txt "update $st"
    sleep 60
  done
  local rel1
  rel1="$(awsr eks describe-nodegroup --cluster-name "$DRILL_EKS_CLUSTER" --nodegroup-name "$ng" --query nodegroup.releaseVersion --output text)"
  say "rotation: update $st after $(( $(date +%s) - t0 ))s; AMI release $rel0 -> $rel1"
  local served=no t1
  t1=$(date +%s)
  while (( $(date +%s) - t1 < 900 )); do
    snap rotation.txt "after the update"
    wait_workers_serving 3 60 && { served=yes; break; }
  done
  say "rotation: 3 workers serving again: $served ($(( $(date +%s) - t1 ))s after the update)"
  # Every recreate sandbox moved and running; every other one stopped (its
  # owner was told), or gone with its machine; none just missing.
  local moved=0 kept_running=0 stopped=0 missing=0 id status
  for id in $recreate_ids; do
    status="$(api get "$id" | jq -r '.status // "missing"')"
    [[ "$status" == started ]] && moved=$((moved + 1))
  done
  for id in $plain_ids; do
    status="$(api get "$id" | jq -r '.status // "missing"')"
    case "$status" in stopped) stopped=$((stopped + 1)) ;; started) kept_running=$((kept_running + 1)) ;; *) missing=$((missing + 1)) ;; esac
  done
  local notices
  notices="$(kc -n "$ns" get events --field-selector reason=Decommissioning -o name 2>/dev/null | wc -l | tr -d ' ')"
  api delete-run --run "$run" >/dev/null || true; api delete-run --run "$run-p" >/dev/null || true
  local detail="node group update $st; recreate sandboxes started after it: $moved of 6; the others: $stopped stopped, $kept_running still running, $missing gone; $notices Decommissioning events"
  if [[ "$st" == Successful && "$moved" == 6 ]]; then
    result PASS rotation "$detail"
  else
    result FAIL rotation "$detail"
    evidence rotation
    local asg
    asg="$(awsr eks describe-nodegroup --cluster-name "$DRILL_EKS_CLUSTER" --nodegroup-name "$ng" --query 'nodegroup.resources.autoScalingGroups[0].name' --output text)"
    awsr autoscaling describe-scaling-activities --auto-scaling-group-name "$asg" --max-items 40 \
      --query 'Activities[].[StartTime,StatusCode,Description]' --output text > "$sd/evidence/rotation/asg-activities.txt" 2>&1 || true
  fi
}

wait_workers_serving() {
  local want="$1" secs="$2" t0 n=0
  t0=$(date +%s)
  while (( $(date +%s) - t0 < secs )); do
    n="$(kc -n "$ns" get aerolnodes -l app.kubernetes.io/component=worker -o json | jq '[.items[] | select(.status.state == "Serving")] | length')"
    (( n >= want )) && return 0
    sleep 10
  done
  return 1
}

for d in "$@"; do
  say "=== drill $d $(date -u +%T)"
  "drill_${d//-/_}" || result FAIL "$d" "the drill itself failed (exit $?)"
done
if grep -q '^FAIL' "$results"; then exit 1; fi

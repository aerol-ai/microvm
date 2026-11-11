#!/usr/bin/env bash
# g5.sh: Phase 1's speed check G5 (plans/kubernetes-v2-architecture.md): a
# gVisor create in the worker pod against the same build on the same
# machine with no Kubernetes.
#
#   cluster.sh up <name>
#   AEROL_BUILD_REF=<commit> g5.sh <name> [count]   # writes .state/<name>/g5-report.txt
#   cluster.sh down <name>
#
# 1. The split worker pod (runtime + agent, C7 on, the chart's CPU and memory
#    for the agent). Cold creates (warm pool off, the README's "cold" row),
#    timed from inside the agent container against 127.0.0.1, each sandbox
#    destroyed before the next. One create first pulls the image.
# 2. The pod removed, the same binaries started on the same machine as one
#    plain systemd service (worker/g5-native.sh).
# 3. The same loop against it, from the machine's own network.
# Pass: the pod's p50 within 10% of the machine's.
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

name="${1:?usage: g5.sh <name> [count]}"
count="${2:-30}"
lib_init "$name" g5-report.txt

# The loop both sides run: P (port), T (token), N (creates). curl and sed
# only: the machine's debug image has no jq.
# shellcheck disable=SC2016
LOOP='set -eu
api() { curl -fsS --max-time 120 -H "Authorization: Bearer $T" -H "Content-Type: application/json" "http://127.0.0.1:$P$1" "${@:2}"; }
body="{\"image\":\"alpine:3.20\",\"runtime\":\"gvisor\"}"
first_id() { grep -o "\"id\":\"[^\"]*\"" | head -1 | cut -d\" -f4; }
id="$(api /v1/sandboxes -X POST -d "$body" | first_id)"
[ -n "$id" ] || { echo "G5 warm-up create failed"; exit 1; }
api "/v1/sandboxes/$id" -X DELETE >/dev/null
i=0
while [ "$i" -lt "$N" ]; do
  i=$((i+1))
  r="$(curl -sS --max-time 120 -o /tmp/g5.json -w "%{http_code} %{time_total}" -H "Authorization: Bearer $T" -H "Content-Type: application/json" "http://127.0.0.1:$P/v1/sandboxes" -X POST -d "$body")"
  id="$(first_id < /tmp/g5.json)"
  echo "G5 $i $r"
  [ -n "$id" ] && api "/v1/sandboxes/$id" -X DELETE >/dev/null
  sleep 1
done'

# host_run <node> <shell>: runs it in a node debug pod (the machine's PID and
# network namespaces, its root at /host) and prints the pod's output.
host_run() {
  local node="$1" before new=""
  before="$(kubectl get pods -o name 2>/dev/null | grep node-debugger || true)"
  kubectl debug "node/$node" --profile=sysadmin --image="$DEBUG_IMAGE" -- bash -c "$2" >/dev/null 2>&1
  for _ in $(seq 1 300); do
    new="$(kubectl get pods -o name 2>/dev/null | grep node-debugger | grep -vxF "$before" | head -1 || true)"
    if [[ -n "$new" ]] && [[ "$(kubectl get "$new" -o jsonpath='{.status.phase}')" =~ ^(Succeeded|Failed)$ ]]; then break; fi
    sleep 2
  done
  [[ -n "$new" ]] || { echo "g5: the debug pod never appeared" >&2; return 1; }
  kubectl logs "$new"
  kubectl delete "$new" --wait=false >/dev/null
}

# stats <file> <label>: p50 and p90 of the G5 lines' times, in ms.
stats() {
  python3 - "$1" "$2" <<'EOF'
import sys
times, bad = [], 0
for line in open(sys.argv[1]):
    f = line.split()
    if len(f) == 4 and f[0] == "G5":
        if f[2].startswith("20"):
            times.append(float(f[3]) * 1000)
        else:
            bad += 1
times.sort()
if not times:
    print(f"{sys.argv[2]}: no successful creates"); sys.exit(1)
q = lambda p: times[min(len(times) - 1, int(round(p * (len(times) - 1))))]
print(f"{sys.argv[2]}: n={len(times)} failed={bad} p50={q(0.5):.0f} ms p90={q(0.9):.0f} ms min={times[0]:.0f} max={times[-1]:.0f}")
EOF
}

publish_build
load_br_netfilter
apply_worker "$LIB_DIR/manifests/worker-s2.yaml" 1
wait_ready
wait_api
node="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')"
say "node: $node ($(kubectl get node "$node" -o jsonpath='{.metadata.labels.node\.kubernetes\.io/instance-type}')); build $(git -C "$LIB_ROOT" rev-parse --short "${AEROL_BUILD_REF:-HEAD}")"

say "agent container: $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.containers[?(@.name=="agent")].resources.limits}'); runtime container: $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.containers[?(@.name=="runtime")].resources.limits}')"
say "--- 1. the worker pod: $count cold gVisor creates"
kubectl -n "$NS" exec "$POD" -c agent -- env P=21212 T="$token" N="$count" bash -c "$LOOP" | tee "$sd/g5-pod.txt"
pod_line="$(stats "$sd/g5-pod.txt" pod)"
say "$pod_line"
remove_worker

say "--- 2. the same build on the same machine, no pod"
b64() { base64 < "$1" | tr -d '\n'; }
host_run "$node" "set -e
mkdir -p /host/opt/g5
echo $(b64 "$LIB_DIR/worker/fetch.sh") | base64 -d > /host/opt/g5/fetch.sh
echo $(b64 "$LIB_DIR/worker/common.sh") | base64 -d > /host/opt/g5/common.sh
echo $(b64 "$LIB_DIR/worker/g5-native.sh") | base64 -d > /host/opt/g5/native.sh
chroot /host systemctl stop aerolvm-g5 2>/dev/null || true
chroot /host systemd-run --unit=aerolvm-g5 --collect \
  --setenv=SANDBOXD_URL='$(url_of sandboxd_url)' --setenv=TOOLBOXD_URL='$(url_of toolboxd_url)' \
  --setenv=CHECKSUMS_URL='$(url_of checksums_url)' --setenv=SB_PAT_TOKEN='$token' \
  /bin/bash /opt/g5/native.sh
for i in \$(seq 1 120); do
  curl -fsS -o /dev/null -H 'Authorization: Bearer $token' http://127.0.0.1:21299/v1/sandboxes && { echo \"g5: host sandboxd answered after \$((i*2))s\"; exit 0; }
  sleep 2
done
echo 'g5: host sandboxd never answered'; chroot /host journalctl -u aerolvm-g5 --no-pager | tail -40; exit 1" | tee -a "$report"

say "--- 3. the machine: $count cold gVisor creates"
host_run "$node" "P=21299 T='$token' N=$count; $LOOP" | tee "$sd/g5-host.txt"
host_line="$(stats "$sd/g5-host.txt" machine)"
say "$host_line"
host_run "$node" "chroot /host systemctl stop aerolvm-g5 || true" >/dev/null

python3 - "$pod_line" "$host_line" <<'EOF' | tee -a "$report"
import re, sys
p50 = lambda s: float(re.search(r"p50=(\d+)", s).group(1))
pod, host = p50(sys.argv[1]), p50(sys.argv[2])
ratio = pod / host
print(f"G5: pod p50 {pod:.0f} ms / machine p50 {host:.0f} ms = {ratio:.2f} -> {'PASS' if ratio <= 1.10 else 'FAIL'} (bar: 1.10)")
EOF

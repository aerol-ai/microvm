#!/usr/bin/env bash
# n1.sh: N1, the side-by-side benchmark (plan §18, the gate before N2-N8).
# agent-sandbox with gVisor and AerolVM's worker pod on one EKS cluster, two
# worker machines of the same type, timed from one bench pod in the cluster.
#
#   cluster.sh up <name> --workers 2
#   n1.sh <name>          # writes .state/<name>/n1-report.txt
#   cluster.sh down <name>
#
# The same sandbox on both sides: alpine:3.20 asleep under gVisor, 0.1 CPU,
# 64 MB. Phases: cold creates (no warm pool), warm creates (a pool of 5), and
# a burst of 20 against a pool of 5; plus how many Kubernetes API writes each
# side makes, counted with watches.
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
AS_VERSION=v1.0.10
N=10
BURST=20

name="${1:?usage: n1.sh <name>}"
lib_init "$name" n1-report.txt
read -r -a nodes <<<"$(kubectl get nodes -l aerolvm.io/pool=phase0 -o jsonpath='{.items[*].metadata.name}')"
[[ ${#nodes[@]} -ge 2 ]] || { echo "n1: needs two worker machines (cluster.sh up --workers 2)" >&2; exit 1; }
kubectl label node "${nodes[0]}" aerolvm.io/n1=aerolvm --overwrite >/dev/null
kubectl label node "${nodes[1]}" aerolvm.io/n1=agent-sandbox --overwrite >/dev/null
say "machines: AerolVM on ${nodes[0]}, agent-sandbox on ${nodes[1]}; both $(kubectl get node "${nodes[0]}" -o jsonpath='{.metadata.labels.node\.kubernetes\.io/instance-type}')"
say "pods allowed per machine (EKS, VPC CNI): $(kubectl get node "${nodes[1]}" -o jsonpath='{.status.allocatable.pods}')"

publish_build
load_br_netfilter

deploy_av() {
  local pool="$1" manifest="$sd/worker-n1.yaml"
  python3 - "$LIB_DIR/manifests/worker-h0.yaml" "$manifest" "$pool" <<'PY'
import sys
s = open(sys.argv[1]).read()
s = s.replace("    aerolvm.io/pool: phase0\n", "    aerolvm.io/pool: phase0\n    aerolvm.io/n1: aerolvm\n", 1)
if sys.argv[3] == "1":
    s = s.replace("        - name: POD_NAME\n", "        - name: SB_CONTAINERD_POOL_ENABLED\n          value: \"true\"\n        - name: SB_CONTAINERD_POOL_DEPTH\n          value: \"5\"\n        - name: POD_NAME\n", 1)
open(sys.argv[2], "w").write(s)
PY
  apply_worker "$manifest" 1
  wait_ready
  wait_api
  kubectl -n "$NS" expose pod "$POD" --name worker-svc --port 21212 --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  say "AerolVM worker up, warm pool $([[ $pool == 1 ]] && echo 'on (depth 5)' || echo off)"
}

# agent-sandbox, with gVisor in the second machine's containerd.
kubectl apply -f "$LIB_DIR/n1/manifests.yaml" >/dev/null
kubectl -n n1 create configmap n1-scripts --from-file=gvisor-node.sh="$LIB_DIR/n1/gvisor-node.sh" \
  --from-file=bench.sh="$LIB_DIR/n1/bench.sh" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
for _ in $(seq 1 60); do
  kubectl -n n1 logs ds/gvisor-node 2>/dev/null | grep -q '^gvisor-node: runsc' && break
  sleep 5
done
say "$(kubectl -n n1 logs ds/gvisor-node 2>/dev/null | grep '^gvisor-node:' | tail -1)"
kubectl apply -f "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AS_VERSION}/sandbox-with-extensions.yaml" >/dev/null
kubectl -n agent-sandbox-system rollout status deploy/agent-sandbox-controller --timeout=5m >/dev/null
kubectl apply -f "$LIB_DIR/n1/template.yaml" >/dev/null
say "agent-sandbox ${AS_VERSION} installed; template and warm pool of 5 applied"

deploy_av 0
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: { name: n1-bench, namespace: n1 }
spec:
  serviceAccountName: n1-bench
  containers:
    - name: bench
      image: public.ecr.aws/amazonlinux/amazonlinux:2023
      command: ["sleep", "infinity"]
      env:
        - { name: AV_URL, value: "http://worker-svc.${NS}.svc:21212" }
        - { name: AV_TOKEN, value: "${token}" }
      volumeMounts: [{ name: scripts, mountPath: /scripts }]
  volumes: [{ name: scripts, configMap: { name: n1-scripts } }]
YAML
kubectl -n n1 wait --for=condition=Ready pod/n1-bench --timeout=5m >/dev/null
bench() { kubectl -n n1 exec n1-bench -- env AV_TOKEN="$token" bash /scripts/bench.sh "$@" 2>&1 | grep '^N1' | tee -a "$report"; }

say "--- agent-sandbox"
bench as-cold "$N"
bench as-warm "$N"
bench as-burst "$BURST"
say "--- AerolVM"
bench av-cold "$N"
deploy_av 1
bench av-warm "$N"
bench av-burst "$BURST"
say "--- done; report in $report"

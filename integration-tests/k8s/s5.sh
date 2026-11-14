#!/usr/bin/env bash
# s5.sh: spike S5 (plans/kubernetes-v2-phase0.md). Can the machines under a
# worker pod be replaced only when AerolVM says so?
#
#   cluster.sh up <name> --karpenter --release 1.36.5-20261031
#   s5.sh <name> [karpenter|upgrade|all]    # writes .state/<name>/s5-report.txt
#   cluster.sh down <name>
#
# karpenter: a worker pod with karpenter.sh/do-not-disrupt on a Karpenter
#   machine (NodePool with expireAfter: Never). The NodePool is changed so
#   the machine drifts. Expected: Karpenter leaves it alone while the
#   annotation is there; a stand-in for the operator then empties the worker
#   (deletes its sandboxes, the stand-in for moving them) and removes the
#   annotation; Karpenter then replaces the machine. Timed.
# upgrade: a worker pod on the managed node group, with a PodDisruptionBudget
#   that blocks its eviction. The node group's AMI is upgraded one release.
#   The operator stand-in watches for the cordon EKS puts on the old machine,
#   empties the worker and lets the pod go. Expected: the upgrade succeeds
#   inside EKS's 15-minute eviction limit. Timed.
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

name="${1:?usage: s5.sh <name> [karpenter|upgrade|all]}"
part="${2:-all}"
lib_init "$name" s5-report.txt
publish_build
load_br_netfilter
tfout() { terraform -chdir="$LIB_DIR/terraform" output -state="$sd/terraform.tfstate" -raw "$1"; }
region="$(tfout region)"
role="$(tfout node_role_name)"
ttl="$(jq -r .ttl "$sd/run.tfvars.json")"

# mk_sandboxes <n>: n gVisor sandboxes through the API.
mk_sandboxes() {
  local i
  for i in $(seq 1 "$1"); do
    api /v1/sandboxes -X POST -d '{"image":"alpine:3.20","runtime":"gvisor","cpu":0.1,"memory_mb":64}' | jq -r '.id' >/dev/null
  done
  say "sandboxes on the worker: $(api /v1/sandboxes | jq length)"
}

# empty_worker is the operator stand-in's drain: it deletes every sandbox,
# standing in for moving them to another worker (Phase 2's live move).
empty_worker() {
  local id
  forward
  for id in $(api /v1/sandboxes | jq -r '.[].id'); do
    api "/v1/sandboxes/$id" -X DELETE >/dev/null || true
  done
}

worker_manifest() {
  local pool="$1" out="$sd/worker-s5-$1.yaml"
  python3 - "$LIB_DIR/manifests/worker-h0.yaml" "$out" "$pool" <<'PY'
import sys
s = open(sys.argv[1]).read()
if sys.argv[3] == "karpenter":
    s = s.replace("    aerolvm.io/pool: phase0\n", "    aerolvm.io/pool: karpenter\n", 1)
    s = s.replace("  labels:\n    app: aerolvm-worker\n",
                  "  labels:\n    app: aerolvm-worker\n  annotations:\n    karpenter.sh/do-not-disrupt: \"true\"\n", 1)
    assert "do-not-disrupt" in s and "pool: karpenter" in s
open(sys.argv[2], "w").write(s)
PY
  echo "$out"
}

part_karpenter() {
  say "=== Karpenter: do-not-disrupt, drift, and the operator's say"
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: karpenter.k8s.aws/v1
kind: EC2NodeClass
metadata: { name: s5 }
spec:
  role: ${role}
  amiSelectorTerms: [{ alias: al2023@latest }]
  subnetSelectorTerms: [{ tags: { karpenter.sh/discovery: ${name} } }]
  securityGroupSelectorTerms: [{ tags: { aws:eks:cluster-name: ${name} } }]
  # The reaper finds machines by these; Karpenter's are not Terraform's.
  tags: { aerol:purpose: k8s-phase0, aerol:owner: itest, aerol:ttl: "${ttl}", aerol:run: ${name} }
  # F2's other answer, the bank's node configuration: load br_netfilter at
  # boot, before the worker pod can start sandboxd.
  userData: |
    MIME-Version: 1.0
    Content-Type: multipart/mixed; boundary="//"

    --//
    Content-Type: text/x-shellscript; charset="us-ascii"

    #!/bin/bash
    modprobe br_netfilter
    --//--
---
apiVersion: karpenter.sh/v1
kind: NodePool
metadata: { name: s5 }
spec:
  template:
    metadata:
      labels: { aerolvm.io/pool: karpenter, aerolvm.io/rev: "1" }
    spec:
      nodeClassRef: { group: karpenter.k8s.aws, kind: EC2NodeClass, name: s5 }
      taints: [{ key: aerolvm.io/worker, value: "true", effect: NoSchedule }]
      expireAfter: Never
      requirements:
        - { key: node.kubernetes.io/instance-type, operator: In, values: [m7i.xlarge] }
        - { key: karpenter.sh/capacity-type, operator: In, values: [on-demand] }
  disruption:
    consolidationPolicy: WhenEmptyOrUnderutilized
    consolidateAfter: 30s
    budgets: [{ nodes: "100%" }]
YAML
  local t0 node nc i
  t0=$(date +%s)
  apply_worker "$(worker_manifest karpenter)" 1
  # F2's stand-in on the new machine, as soon as it is up; the pod's init
  # (fetching binaries) leaves time before sandboxd needs it.
  for i in $(seq 1 90); do
    node="$(kubectl get nodes -l aerolvm.io/pool=karpenter -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    [[ -n "$node" ]] && [[ "$(kubectl get node "$node" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')" == True ]] && break
    sleep 5
  done
  say "Karpenter machine $node Ready $(( $(date +%s) - t0 )) s after the worker pod was applied"
  load_br_netfilter aerolvm.io/pool=karpenter
  wait_ready
  wait_api
  mk_sandboxes 3
  nc="$(kubectl get nodeclaims -o jsonpath="{.items[?(@.status.nodeName==\"$node\")].metadata.name}")"

  say "--- drift: the NodePool's template changes; the machine no longer matches it"
  kubectl patch nodepool s5 --type merge -p '{"spec":{"template":{"metadata":{"labels":{"aerolvm.io/rev":"2"}}}}}' >/dev/null
  t0=$(date +%s)
  for i in $(seq 1 60); do
    [[ "$(kubectl get nodeclaim "$nc" -o jsonpath='{.status.conditions[?(@.type=="Drifted")].status}' 2>/dev/null)" == True ]] && break
    sleep 5
  done
  say "NodeClaim $nc Drifted=$(kubectl get nodeclaim "$nc" -o jsonpath='{.status.conditions[?(@.type=="Drifted")].status}') after $(( $(date +%s) - t0 )) s"
  sleep 180
  say "3 minutes later: machine $(kubectl get node "$node" -o name 2>/dev/null || echo gone); worker $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || echo gone); sandboxes $(forward; api /v1/sandboxes | jq length)"
  say "Karpenter's events on the machine: $(kubectl get events -A --field-selector involvedObject.name="$node" -o jsonpath='{range .items[*]}{.reason}: {.message}{"\n"}{end}' | sort | uniq -c | sort -rn | head -4 | tr '\n' ';')"

  say "--- the operator stand-in empties the worker and lets go"
  t0=$(date +%s)
  empty_worker
  kubectl -n "$NS" annotate pod "$POD" karpenter.sh/do-not-disrupt- >/dev/null
  local gone=0 newnode=""
  for i in $(seq 1 120); do
    kubectl -n "$NS" get pod "$POD" >/dev/null 2>&1 || { [[ $gone == 0 ]] && gone=$(( $(date +%s) - t0 )); }
    kubectl get node "$node" >/dev/null 2>&1 || break
    sleep 5
  done
  say "after the annotation was removed: worker pod gone in ${gone} s, old machine gone in $(( $(date +%s) - t0 )) s"
  newnode="$(kubectl get nodes -l aerolvm.io/pool=karpenter -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  say "replacement machine: ${newnode:-none (Karpenter adds one only for a pending pod)}"
  # The pod was a bare pod; the operator would make it again. Clean up so the
  # upgrade part starts from the managed node group alone.
  kubectl delete nodepool s5 --timeout=5m >/dev/null 2>&1 || true
}

part_upgrade() {
  say "=== managed node group upgrade with the operator stand-in"
  local ng from to node t0 id status t_cordon="" t_done=""
  ng="$(aws eks list-nodegroups --region "$region" --cluster-name "$name" --query 'nodegroups[?starts_with(@, `worker-`)]|[0]' --output text)"
  from="$(aws eks describe-nodegroup --region "$region" --cluster-name "$name" --nodegroup-name "$ng" --query nodegroup.releaseVersion --output text)"
  to="$(aws ssm get-parameter --region "$region" --name "/aws/service/eks/optimized-ami/$(jq -r .kubernetes_version "$sd/run.tfvars.json")/amazon-linux-2023/x86_64/standard/recommended/release_version" --query Parameter.Value --output text)"
  [[ "$from" != "$to" ]] || { say "node group already at $to; start the cluster with --release one behind"; return 1; }
  apply_worker "$LIB_DIR/manifests/worker-h0.yaml" 1
  wait_ready
  wait_api
  mk_sandboxes 3
  node="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')"
  # Without the operator, eviction is refused: EKS would retry for 15
  # minutes and then fail the upgrade.
  kubectl -n "$NS" create poddisruptionbudget worker --selector=app=aerolvm-worker --min-available=1 >/dev/null

  # The operator stand-in. Its signal is the machine being marked
  # unschedulable: a cordon, or any NoSchedule taint besides the worker's
  # own. Which one came, and when, is recorded; if none comes before EKS
  # starts evicting, the PDB holds and the upgrade fails at 15 minutes.
  (
    local sig=""
    while true; do
      sig="$(kubectl get node "$node" -o jsonpath='{.spec.unschedulable}|{range .spec.taints[*]}{.key}={.effect},{end}' 2>/dev/null)"
      [[ "${sig%%|*}" == true ]] && break
      [[ "${sig#*|}" =~ (^|,)([^,=]+)=NoSchedule && "${BASH_REMATCH[2]}" != aerolvm.io/worker ]] && break
      echo "${sig#*|}" | tr ',' '\n' | grep '=NoSchedule' | grep -qv '^aerolvm.io/worker=' && break
      sleep 2
    done
    echo "cordon $(date +%s) $sig" > "$sd/s5-operator.txt"
    empty_worker
    kubectl -n "$NS" delete poddisruptionbudget worker >/dev/null
    kubectl -n "$NS" delete pod "$POD" --wait=true --timeout=3m >/dev/null 2>&1 || true
    echo "done $(date +%s)" >> "$sd/s5-operator.txt"
  ) &
  local op=$!

  t0=$(date +%s)
  id="$(aws eks update-nodegroup-version --region "$region" --cluster-name "$name" --nodegroup-name "$ng" --release-version "$to" --query update.id --output text)"
  say "upgrade $ng from $from to $to (update $id)"
  status=InProgress
  while [[ "$status" == InProgress ]]; do
    sleep 20
    status="$(aws eks describe-update --region "$region" --name "$name" --nodegroup-name "$ng" --update-id "$id" --query update.status --output text)"
  done
  wait "$op" 2>/dev/null || true
  t_cordon="$(awk '$1=="cordon"{print $2}' "$sd/s5-operator.txt" 2>/dev/null || true)"
  t_done="$(awk '$1=="done"{print $2}' "$sd/s5-operator.txt" 2>/dev/null || true)"
  say "upgrade: $status after $(( $(date +%s) - t0 )) s; the operator's signal: $(cut -d' ' -f3- "$sd/s5-operator.txt" 2>/dev/null | head -1) at +$(( ${t_cordon:-t0} - t0 )) s; it let the worker go $(( ${t_done:-0} - ${t_cordon:-0} )) s later"
  say "update errors: $(aws eks describe-update --region "$region" --name "$name" --nodegroup-name "$ng" --update-id "$id" --query 'update.errors' --output json | tr -d '\n ' | cut -c1-300)"
  say "node group now at $(aws eks describe-nodegroup --region "$region" --cluster-name "$name" --nodegroup-name "$ng" --query nodegroup.releaseVersion --output text)"
  # The operator would start the worker on the new machine.
  load_br_netfilter
  apply_worker "$LIB_DIR/manifests/worker-h0.yaml" 1
  wait_ready
  wait_api
  say "worker back on $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}'); sandboxd answers"
}

case "$part" in
  karpenter) part_karpenter ;;
  upgrade) part_upgrade ;;
  all) part_karpenter; part_upgrade ;;
  *) echo "s5: unknown part $part" >&2; exit 2 ;;
esac
say "--- done; report in $report"

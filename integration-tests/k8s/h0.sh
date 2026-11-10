#!/usr/bin/env bash
# h0.sh: put the H0 worker pod on a Phase 0 cluster, smoke-test it, and
# collect spike S1's first evidence (plans/kubernetes-v2-phase0.md).
#
#   cluster.sh up <name>
#   h0.sh <name>          # writes .state/<name>/h0-report.txt
#   cluster.sh down <name>
#
# The smoke test creates one gVisor sandbox through sandboxd's /v1 API and
# runs a command in it. The S1 part records, without judging, where the
# sandbox's processes sit in the cgroup tree compared with the worker pod's
# own cgroup, and which network links exist in the pod and on the machine.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
NS=aerolvm-workers
POD=worker-0

name="${1:?usage: h0.sh <name>}"
KUBECONFIG="$("$HERE/cluster.sh" kubeconfig "$name")"
export KUBECONFIG
sd="$HERE/.state/$name"
report="$sd/h0-report.txt"
: > "$report"
say() { echo "$*" | tee -a "$report"; }

# 1. This branch's sandboxd and toolboxd, through S3 (content-addressed, so an
#    unchanged tree uploads nothing).
#    Built from the last commit, not the working tree: the harness files do
#    not go into sandboxd, so editing them must not force a new build.
ref="$(git -C "$ROOT" rev-parse HEAD)"
"$ROOT/integration-tests/lib/build.sh" build --ref "$ref" --arch amd64 >&2
"$ROOT/integration-tests/lib/build.sh" publish --ref "$ref" --ttl 6h --arch amd64 >&2
"$ROOT/integration-tests/lib/build.sh" urls --ref "$ref" --ttl 6h --arch amd64 > "$sd/urls.tfvars"
url_of() { sed -n "s/^$1 *= *\"\(.*\)\"$/\1/p" "$sd/urls.tfvars"; }
for k in sandboxd_url toolboxd_url checksums_url; do
  [[ -n "$(url_of "$k")" ]] || { echo "h0: build.sh urls gave no $k" >&2; exit 1; }
done
say "build: $(head -1 "$sd/urls.tfvars")"

token="$(openssl rand -hex 24)"
umask 077
echo "$token" > "$sd/api-token"

# 2. The namespace, the boot scripts, the URLs, then the pod.
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl label namespace "$NS" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null
kubectl -n "$NS" create configmap worker-boot \
  --from-file=fetch.sh="$HERE/worker/fetch.sh" --from-file=run.sh="$HERE/worker/run.sh" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create secret generic worker-urls \
  --from-literal=SANDBOXD_URL="$(url_of sandboxd_url)" \
  --from-literal=TOOLBOXD_URL="$(url_of toolboxd_url)" \
  --from-literal=CHECKSUMS_URL="$(url_of checksums_url)" \
  --from-literal=SB_PAT_TOKEN="$token" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" delete pod "$POD" --ignore-not-found --wait=true >/dev/null
kubectl apply -f "$HERE/manifests/worker-h0.yaml" >/dev/null

t_apply=$(date +%s)
# Poll instead of `kubectl wait`: with restartPolicy Never a failed init
# container leaves the pod Failed, and wait would sit out its whole timeout.
ready=0
for _ in $(seq 1 180); do
  phase="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.phase}')"
  cond="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')"
  [[ "$cond" == True ]] && { ready=1; break; }
  [[ "$phase" == Failed || "$phase" == Succeeded ]] && break
  sleep 5
done
if [[ "$ready" != 1 ]]; then
  kubectl -n "$NS" get pod "$POD" -o wide >&2 || true
  kubectl -n "$NS" logs "$POD" -c fetch --tail=50 >&2 || true
  kubectl -n "$NS" logs "$POD" -c worker --tail=80 >&2 || true
  echo "h0: worker pod never became Ready (phase ${phase:-unknown})" >&2
  exit 1
fi
say "qos class: $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.qosClass}')"
say "pod ready after $(( $(date +%s) - t_apply ))s on node $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')"

# 3. The API, through a port-forward. Nothing is exposed outside the cluster.
# kubectl port-forward quits for good after one refused connection, so it is
# restarted whenever it has died.
pf=""
forward() {
  if [[ -z "$pf" ]] || ! kill -0 "$pf" 2>/dev/null; then
    kubectl -n "$NS" port-forward "pod/$POD" 21212:21212 >/dev/null 2>&1 &
    pf=$!
    sleep 2
  fi
}
trap '[[ -n "$pf" ]] && kill $pf 2>/dev/null || true' EXIT
forward
api() {
  local path="$1"; shift
  curl -fsS --max-time 120 -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    "http://127.0.0.1:21212${path}" "$@"
}
up=0
for _ in $(seq 1 90); do
  forward
  if api /v1/sandboxes >/dev/null 2>&1; then up=1; break; fi
  sleep 2
done
if [[ "$up" != 1 ]]; then
  kubectl -n "$NS" logs "$POD" -c worker --tail=80 >&2 || true
  echo "h0: sandboxd API never answered" >&2
  exit 1
fi

# 4. Smoke: one gVisor sandbox, one command.
ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }
t0=$(ms)
created="$(api /v1/sandboxes -X POST -d '{"image":"alpine:3.20","runtime":"gvisor"}')"
t1=$(ms)
id="$(jq -r '.id // empty' <<<"$created")"
[[ -n "$id" ]] || { echo "h0: create returned no id: $created" >&2; exit 1; }
say "create (cold, image pull included, through a port-forward): $(( t1 - t0 )) ms, sandbox $id"
out="$(api "/v1/sandboxes/$id/toolbox/process/execute" -X POST \
  -d '{"command":"echo hello-from-gvisor; uname -r; cat /proc/self/cgroup"}')"
say "exec: $(jq -c '{exit_code, stdout}' <<<"$out")"

# 5. S1 evidence, recorded as found.
say "--- S1: cgroups, seen from the worker container"
kubectl -n "$NS" exec "$POD" -c worker -- bash -c '
  echo "worker container: $(cat /proc/self/cgroup)"
  for p in $(pgrep -f "runsc" || true); do
    echo "pid $p ($(tr "\0" " " < /proc/$p/cmdline | cut -c1-60)): $(cat /proc/$p/cgroup)"
  done
' | tee -a "$report"
say "--- S1: network links inside the pod"
kubectl -n "$NS" exec "$POD" -c worker -- ip -br link | tee -a "$report"
say "--- S1: network namespaces inside the pod"
kubectl -n "$NS" exec "$POD" -c worker -- ip netns list | tee -a "$report" || true
node="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')"
say "--- S1: network links on the machine ($node), from a host-network debug pod"
# kubectl debug node runs a pod in the machine's network namespace, so
# /proc/net/dev lists the machine's links, not the pod's.
kubectl debug "node/$node" --image=public.ecr.aws/amazonlinux/amazonlinux:2023 -- \
  sh -c 'cut -d: -f1 /proc/net/dev | tail -n +3 | tr -d " "' >/dev/null 2>&1 || true
dpod=""
for _ in $(seq 1 30); do
  dpod="$(kubectl get pods -o name 2>/dev/null | grep node-debugger | head -1 || true)"
  if [[ -n "$dpod" ]] && [[ "$(kubectl get "$dpod" -o jsonpath='{.status.phase}')" == Succeeded ]]; then break; fi
  sleep 2
done
if [[ -n "$dpod" ]]; then
  kubectl logs "$dpod" | tee -a "$report"
  kubectl delete "$dpod" --wait=false >/dev/null
else
  say "(the debug pod did not start)"
fi

api "/v1/sandboxes/$id" -X DELETE >/dev/null || true
say "--- done; report in $report"

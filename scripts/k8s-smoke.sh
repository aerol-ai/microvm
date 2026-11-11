#!/usr/bin/env bash
# k8s-smoke.sh: after `make k8s-dev`, use the single-mode install the way a
# client does (plans/kubernetes-v2-architecture.md, Phase 1 exit): create a
# runc and a gVisor sandbox through the API and run a command in each; check
# neither can reach the worker pod's own ports or the Kubernetes API (C24);
# run `aerolvm k8s verify` (P8), which must pass here and fail once a pod
# with the install's labels mounts a host folder; then delete the worker pod
# with both sandboxes running and check it goes away
# (finding F8: leftover namespace mounts kept it in Terminating). CI runs it
# on kind.
set -euo pipefail

cluster="${AEROL_KIND_CLUSTER:-aerolvm}"
namespace="${AEROL_NAMESPACE:-aerolvm}"
port="${AEROL_SMOKE_PORT:-21290}"
root="$(git rev-parse --show-toplevel)"
k() { kubectl --context "kind-$cluster" -n "$namespace" "$@"; }

tmp="$(mktemp -d)"
pf=""
trap '[[ -n "$pf" ]] && kill "$pf" 2>/dev/null; rm -rf "$tmp"' EXIT
(cd "$root" && go build -o "$tmp/aerolvm" ./cmd/aerolvm)
k port-forward svc/aerolvm "$port:21212" >/dev/null 2>&1 &
pf=$!
export SB_API_URL="http://127.0.0.1:$port"
SB_PAT_TOKEN="$(k get secret aerolvm-api-token -o jsonpath='{.data.SB_PAT_TOKEN}' | base64 -d)"
export SB_PAT_TOKEN
for _ in $(seq 1 30); do
  "$tmp/aerolvm" health >/dev/null 2>&1 && break
  sleep 1
done

pod_ip="$(k get pod aerolvm-0 -o jsonpath='{.status.podIP}')"
kube_api="$(kubectl --context "kind-$cluster" get svc kubernetes -o jsonpath='{.spec.clusterIP}')"
# The sandboxes' bridge gateway and the pod's own address, at sandboxd's API
# and SSH ports, and the Kubernetes API: each must refuse a sandbox.
targets="10.88.0.1:21212 10.88.0.1:2220 $pod_ip:21212 $pod_ip:2220 $kube_api:443"
for runtime in docker gvisor; do
  id="$("$tmp/aerolvm" create --image alpine:3.20 --runtime "$runtime" --json | jq -r '.id // empty')"
  [[ -n "$id" ]] || { echo "k8s-smoke: $runtime create failed" >&2; exit 1; }
  out="$("$tmp/aerolvm" exec "$id" -- sh -c 'echo hello-$(uname -r)')"
  echo "k8s-smoke: $runtime sandbox $id: $out"
  [[ "$out" == hello-* ]] || { echo "k8s-smoke: $runtime exec gave $out" >&2; exit 1; }
  open="$("$tmp/aerolvm" exec "$id" -- sh -c "for t in $targets; do nc -z -w 3 \${t%:*} \${t#*:} 2>/dev/null && echo \$t; done; true")"
  if [[ -n "$open" ]]; then
    echo "k8s-smoke: a $runtime sandbox reached $(echo $open) (C24: the worker's ports and the cluster must be closed to it)" >&2
    exit 1
  fi
  echo "k8s-smoke: $runtime sandbox cannot reach the worker's ports or the Kubernetes API"
done

# P8: the install passes; a seeded violation fails. Locally built images
# carry no release signature, so that check is skipped here.
"$tmp/aerolvm" k8s verify --kube-context "kind-$cluster" --namespace "$namespace" --skip-signatures
k run aerolvm-violation --image=registry.k8s.io/pause:3.10 --restart=Never \
  --labels=app.kubernetes.io/name=aerolvm,app.kubernetes.io/instance=aerolvm \
  --overrides='{"spec":{"volumes":[{"name":"host","hostPath":{"path":"/tmp"}}],"containers":[{"name":"violation","image":"registry.k8s.io/pause:3.10","volumeMounts":[{"name":"host","mountPath":"/host"}]}]}}' >/dev/null
if "$tmp/aerolvm" k8s verify --kube-context "kind-$cluster" --namespace "$namespace" --skip-signatures --probe-runtimes docker >"$tmp/violation.txt" 2>&1; then
  cat "$tmp/violation.txt" >&2
  echo "k8s-smoke: aerolvm k8s verify passed with a host folder mounted" >&2
  exit 1
fi
grep -q "FAIL.*no folders mounted from the machine" "$tmp/violation.txt" || { cat "$tmp/violation.txt" >&2; exit 1; }
echo "k8s-smoke: aerolvm k8s verify fails on the seeded host folder"
k delete pod aerolvm-violation --wait=false >/dev/null

kill "$pf"; pf=""
start=$(date +%s)
if ! k delete pod aerolvm-0 --wait=true --timeout=90s >/dev/null; then
  echo "k8s-smoke: the worker pod did not go away with sandboxes running (finding F8)" >&2
  exit 1
fi
echo "k8s-smoke: worker pod deleted with sandboxes running in $(( $(date +%s) - start )) s"

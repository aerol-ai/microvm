#!/usr/bin/env bash
# k8s-smoke.sh: after `make k8s-dev`, use the single-mode install the way a
# client does (plans/kubernetes-v2-architecture.md, Phase 1 exit): create a
# runc and a gVisor sandbox through the API and run a command in each, then
# delete the worker pod with both running and check it goes away (finding
# F8: leftover namespace mounts kept it in Terminating). CI runs it on kind.
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

for runtime in docker gvisor; do
  id="$("$tmp/aerolvm" create --image alpine:3.20 --runtime "$runtime" --json | jq -r '.id // empty')"
  [[ -n "$id" ]] || { echo "k8s-smoke: $runtime create failed" >&2; exit 1; }
  out="$("$tmp/aerolvm" exec "$id" -- sh -c 'echo hello-$(uname -r)')"
  echo "k8s-smoke: $runtime sandbox $id: $out"
  [[ "$out" == hello-* ]] || { echo "k8s-smoke: $runtime exec gave $out" >&2; exit 1; }
done

kill "$pf"; pf=""
start=$(date +%s)
if ! k delete pod aerolvm-0 --wait=true --timeout=90s >/dev/null; then
  echo "k8s-smoke: the worker pod did not go away with sandboxes running (finding F8)" >&2
  exit 1
fi
echo "k8s-smoke: worker pod deleted with sandboxes running in $(( $(date +%s) - start )) s"

#!/usr/bin/env bash
# k8s-smoke.sh: after `make k8s-dev`, use the single-mode install the way a
# client does (plans/kubernetes-v2-architecture.md, Phase 1 exit): create a
# runc and a gVisor sandbox through the API and run a command in each; check
# neither can reach the worker pod's own ports or the Kubernetes API (C24);
# run `aerolvm k8s verify` (P8), which must pass here and fail once a pod
# with the install's labels mounts a host folder; with the edge installed
# (AEROL_K8S_EDGE=1 make k8s-dev), reach the API and a sandbox link over
# HTTPS and check a renewed certificate is served with no restart (C25);
# then delete the worker pod
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
pf="" epf=""
trap 'for p in $pf $epf; do kill "$p" 2>/dev/null; done; rm -rf "$tmp"' EXIT
(cd "$root" && go build -o "$tmp/aerolvm" ./cmd/aerolvm)
# A port-forward exits when its pod goes away, and right after `make
# k8s-dev` replaced the pod it can still pick the old one: start it again
# until the API answers.
forward_api() { k port-forward svc/aerolvm "$port:21212" >/dev/null 2>&1 & pf=$!; }
forward_api
export SB_API_URL="http://127.0.0.1:$port"
SB_PAT_TOKEN="$(k get secret aerolvm-api-token -o jsonpath='{.data.SB_PAT_TOKEN}' | base64 -d)"
export SB_PAT_TOKEN
for _ in $(seq 1 60); do
  "$tmp/aerolvm" health >/dev/null 2>&1 && break
  kill -0 "$pf" 2>/dev/null || forward_api
  sleep 1
done
"$tmp/aerolvm" health >/dev/null || { echo "k8s-smoke: the API never answered through kubectl port-forward" >&2; exit 1; }

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

if k get svc aerolvm-edge >/dev/null 2>&1; then
  edge_port="${AEROL_SMOKE_EDGE_PORT:-21291}"
  forward_edge() { k port-forward svc/aerolvm-edge "$edge_port:443" >/dev/null 2>&1 & epf=$!; }
  forward_edge
  domain="$(k get pod aerolvm-0 -o jsonpath='{.spec.containers[?(@.name=="agent")].env[?(@.name=="SB_DOMAIN")].value}')"
  https() { curl -sk --max-time 10 --resolve "$1:$edge_port:127.0.0.1" "https://$1:$edge_port${2:-/}"; }
  served() { openssl s_client -connect "127.0.0.1:$edge_port" -servername "$domain" </dev/null 2>/dev/null | openssl x509 -noout -serial 2>/dev/null; }
  for _ in $(seq 1 60); do
    https "$domain" /health | grep -q '"status":"ok"' && break
    kill -0 "$epf" 2>/dev/null || forward_edge
    sleep 1
  done
  https "$domain" /health | grep -q '"status":"ok"' || { echo "k8s-smoke: the API does not answer at https://$domain" >&2; exit 1; }
  echo "k8s-smoke: the API answers at https://$domain"

  id="$("$tmp/aerolvm" create --image alpine:3.20 --json | jq -r '.id // empty')"
  [[ -n "$id" ]] || { echo "k8s-smoke: edge sandbox create failed" >&2; exit 1; }
  "$tmp/aerolvm" exec "$id" --background -- sh -c \
    'while true; do printf "HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\nhello\n" | nc -l -p 8080 >/dev/null; done' >/dev/null 2>&1
  url="$("$tmp/aerolvm" expose "$id" 8080 --json | jq -r '.public_url // empty')"
  link="${url#https://}"
  body=""
  for _ in $(seq 1 20); do
    body="$(https "$link")" && [[ "$body" == hello ]] && break
    sleep 1
  done
  [[ "$body" == hello ]] || { echo "k8s-smoke: the sandbox link $url gave '$body'" >&2; exit 1; }
  echo "k8s-smoke: the sandbox link $url answers over HTTPS"

  # A renewal: cert-manager writes a new certificate into the Secret, the
  # kubelet updates the mounted files, and sandboxd has Caddy reload them.
  old="$(served)"
  k delete secret aerolvm-edge-tls >/dev/null
  start=$(date +%s)
  new=""
  while (( $(date +%s) - start < 300 )); do
    new="$(served)"
    [[ -n "$new" && "$new" != "$old" ]] && break
    sleep 5
  done
  [[ -n "$new" && "$new" != "$old" ]] || { echo "k8s-smoke: still serving $old 300 s after the certificate was replaced" >&2; exit 1; }
  restarts="$(k get pod aerolvm-0 -o jsonpath='{range .status.containerStatuses[*]}{.restartCount}{" "}{end}')"
  [[ "$restarts" =~ ^(0 )+$ ]] || { echo "k8s-smoke: containers restarted ($restarts) for the new certificate" >&2; exit 1; }
  echo "k8s-smoke: the renewed certificate served after $(( $(date +%s) - start )) s with no restart"
  [[ "$(https "$link")" == hello ]] || { echo "k8s-smoke: the sandbox link failed after the renewal" >&2; exit 1; }
  kill "$epf"; epf=""
fi

kill "$pf"; pf=""
start=$(date +%s)
if ! k delete pod aerolvm-0 --wait=true --timeout=90s >/dev/null; then
  echo "k8s-smoke: the worker pod did not go away with sandboxes running (finding F8)" >&2
  exit 1
fi
echo "k8s-smoke: worker pod deleted with sandboxes running in $(( $(date +%s) - start )) s"

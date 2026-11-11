#!/usr/bin/env bash
# k8s-dev.sh: AerolVM in single mode on a local kind cluster, built from this
# checkout (plans/kubernetes-v2-architecture.md P4).
#
#   make k8s-dev                   # build the images, start kind, install the chart
#   AEROL_K8S_EDGE=1 make k8s-dev  # the same with the edge (C25): HTTPS sandbox
#                                  # links on aerolvm.test, the certificate from
#                                  # cert-manager with a self-signed issuer
#   make k8s-dev-down              # delete the kind cluster
#
# Needs Docker, kind, kubectl and Helm 3.8 or later (HELM names another).
# sandboxd links glibc, so it is compiled in a golang container; toolboxd, the
# runtime supervisor and Caddy cross-compile here. Nothing is pushed anywhere.
# Running it again replaces the worker pod, ending its sandboxes, so the new
# build runs: the StatefulSet replaces its pod only when the pod is deleted.
set -euo pipefail

cluster="${AEROL_KIND_CLUSTER:-aerolvm}"
namespace="${AEROL_NAMESPACE:-aerolvm}"
edge="${AEROL_K8S_EDGE:-0}"
helm="${HELM:-helm}"
# cert-manager for the edge's certificate, pinned by checksum like Helm and
# kind in CI.
cert_manager_version="v1.21.3"
cert_manager_sha256="c04a51295adda2b1a775146751f973e787190778c7f35180861d9678876e5c74"
root="$(git rev-parse --show-toplevel)"
cd "$root"

if [[ "${1:-}" == down ]]; then
  kind delete cluster --name "$cluster"
  exit 0
fi

case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; *) arch=amd64 ;; esac
dist="$root/dist/k8s-dev"
mkdir -p "$dist"
echo "k8s-dev: building linux/$arch binaries" >&2
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$dist/toolboxd_linux_$arch" ./cmd/toolboxd
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$dist/aerolvm-supervisor_linux_$arch" ./cmd/aerolvm-supervisor
docker run --rm -e GOTOOLCHAIN=auto -e CGO_ENABLED=1 \
  -v "$root":/src -v "$(go env GOMODCACHE)":/go/pkg/mod -v "$dist":/out -w /src \
  golang:1.26 go build -trimpath -o "/out/sandboxd_linux_$arch" ./cmd/sandboxd

images="aerolvm,aerolvm-runtime"
if [[ "$edge" == 1 ]]; then
  # The release's Caddy, from the pins install.sh keeps (the release job
  # builds the same; integration-tests/safety keeps the two in step).
  pin() { sed -n "s/^$1=\"\(.*\)\"$/\1/p" scripts/install.sh; }
  echo "k8s-dev: building Caddy $(pin CADDY_BUILD_VERSION)" >&2
  GOBIN="$dist/bin" go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.6
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$dist/bin/xcaddy" \
    build "$(pin CADDY_BUILD_VERSION)" --output "$dist/caddy_linux_$arch" \
    --with github.com/aerol-ai/microvm/caddymod=./caddymod \
    --with "$(pin CADDY_L4_MODULE)" --with "$(pin CADDY_DNS_CLOUDFLARE_MODULE)" \
    --with "$(pin CADDY_STORAGE_S3_MODULE)"
  images="$images,aerolvm-edge"
fi
scripts/build-images.sh --dist "$dist" --version dev --platforms "linux/$arch" --images "$images"

if ! kind get clusters 2>/dev/null | grep -qx "$cluster"; then
  kind create cluster --name "$cluster"
fi
kind load docker-image --name "$cluster" $(printf 'ghcr.io/aerol-ai/%s:dev ' ${images//,/ })

edge_flags=()
if [[ "$edge" == 1 ]]; then
  if ! kubectl --context "kind-$cluster" get crd certificates.cert-manager.io >/dev/null 2>&1; then
    curl -fsSL -o "$dist/cert-manager.yaml" \
      "https://github.com/cert-manager/cert-manager/releases/download/$cert_manager_version/cert-manager.yaml"
    echo "$cert_manager_sha256  $dist/cert-manager.yaml" | shasum -a 256 -c - >/dev/null
    kubectl --context "kind-$cluster" apply -f "$dist/cert-manager.yaml" >/dev/null
  fi
  kubectl --context "kind-$cluster" -n cert-manager wait --for=condition=Available deployment --all --timeout=5m >/dev/null
  # The webhook answers a little after it reports Available.
  for _ in $(seq 1 30); do
    printf 'apiVersion: cert-manager.io/v1\nkind: ClusterIssuer\nmetadata: {name: aerolvm-dev}\nspec: {selfSigned: {}}\n' |
      kubectl --context "kind-$cluster" apply -f - >/dev/null 2>&1 && break
    sleep 2
  done
  edge_flags=(--set edge.enabled=true --set edge.domain=aerolvm.test
    --set edge.certManager.issuerRef.name=aerolvm-dev --set edge.service.type=ClusterIP)
fi

kubectl --context "kind-$cluster" create namespace "$namespace" --dry-run=client -o yaml | kubectl --context "kind-$cluster" apply -f - >/dev/null
# The worker pod is privileged (plan §8.7): only its namespace allows it.
kubectl --context "kind-$cluster" label namespace "$namespace" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null
existing=0
kubectl --context "kind-$cluster" -n "$namespace" get pod aerolvm-0 >/dev/null 2>&1 && existing=1
"$helm" --kube-context "kind-$cluster" upgrade --install aerolvm charts/aerolvm -n "$namespace" \
  --set image.tag=dev --set image.pullPolicy=Never ${edge_flags[@]+"${edge_flags[@]}"}
if [[ "$existing" == 1 ]]; then
  kubectl --context "kind-$cluster" -n "$namespace" delete pod aerolvm-0 --wait=true --timeout=2m >/dev/null
fi
# Helm does not wait for a StatefulSet that updates OnDelete; wait for the pod.
# Created only after the install, so give it a moment to appear.
for _ in $(seq 1 30); do
  kubectl --context "kind-$cluster" -n "$namespace" get pod aerolvm-0 >/dev/null 2>&1 && break
  sleep 2
done
kubectl --context "kind-$cluster" -n "$namespace" wait --for=condition=Ready pod/aerolvm-0 --timeout=5m
echo "k8s-dev: ready. Next: kubectl -n $namespace port-forward svc/aerolvm 21212:21212" >&2
if [[ "$edge" == 1 ]]; then
  echo "k8s-dev: the edge: kubectl -n $namespace port-forward svc/aerolvm-edge 8443:443, then https://aerolvm.test:8443 (resolve aerolvm.test and *.aerolvm.test to 127.0.0.1)" >&2
fi

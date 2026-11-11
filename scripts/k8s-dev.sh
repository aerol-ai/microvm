#!/usr/bin/env bash
# k8s-dev.sh: AerolVM in single mode on a local kind cluster, built from this
# checkout (plans/kubernetes-v2-architecture.md P4).
#
#   make k8s-dev        # build the images, start kind, install the chart
#   make k8s-dev-down   # delete the kind cluster
#
# Needs Docker, kind, kubectl and Helm 3.8 or later (HELM names another).
# sandboxd links glibc, so it is compiled in a golang container; toolboxd and
# the runtime supervisor cross-compile here. Nothing is pushed anywhere.
set -euo pipefail

cluster="${AEROL_KIND_CLUSTER:-aerolvm}"
namespace="${AEROL_NAMESPACE:-aerolvm}"
helm="${HELM:-helm}"
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

scripts/build-images.sh --dist "$dist" --version dev --platforms "linux/$arch" --images aerolvm,aerolvm-runtime

if ! kind get clusters 2>/dev/null | grep -qx "$cluster"; then
  kind create cluster --name "$cluster"
fi
kind load docker-image --name "$cluster" ghcr.io/aerol-ai/aerolvm:dev ghcr.io/aerol-ai/aerolvm-runtime:dev

kubectl --context "kind-$cluster" create namespace "$namespace" --dry-run=client -o yaml | kubectl --context "kind-$cluster" apply -f - >/dev/null
# The worker pod is privileged (plan §8.7): only its namespace allows it.
kubectl --context "kind-$cluster" label namespace "$namespace" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null
"$helm" --kube-context "kind-$cluster" upgrade --install aerolvm charts/aerolvm -n "$namespace" \
  --set image.tag=dev --set image.pullPolicy=Never
# Helm does not wait for a StatefulSet that updates OnDelete; wait for the pod.
# Created only after the install, so give it a moment to appear.
for _ in $(seq 1 30); do
  kubectl --context "kind-$cluster" -n "$namespace" get pod aerolvm-0 >/dev/null 2>&1 && break
  sleep 2
done
kubectl --context "kind-$cluster" -n "$namespace" wait --for=condition=Ready pod/aerolvm-0 --timeout=5m
echo "k8s-dev: ready. Next: kubectl -n $namespace port-forward svc/aerolvm 21212:21212" >&2

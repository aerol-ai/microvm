#!/usr/bin/env bash
# k8s-dev.sh: AerolVM in single mode on a local kind cluster, built from this
# checkout (plans/kubernetes-v2-architecture.md P4).
#
#   make k8s-dev                   # build the images, start kind, install the chart
#   AEROL_K8S_EDGE=1 make k8s-dev  # the same with the edge (C25): HTTPS sandbox
#                                  # links on aerolvm.test, the certificate from
#                                  # cert-manager with a self-signed issuer
#   make k8s-dev-down              # delete the kind cluster
#   AEROL_K8S_MODE=cluster make k8s-dev
#                                  # cluster mode (P2): the operator, three
#                                  # servers, gateways and a worker pool on a
#                                  # kind cluster of three nodes, one per zone
#
# Needs Docker, kind, kubectl and Helm 3.8 or later (HELM names another).
# sandboxd links glibc, so it is compiled in a golang container; toolboxd, the
# runtime supervisor and Caddy cross-compile here. Nothing is pushed anywhere.
# Running it again replaces the worker pod, ending its sandboxes, so the new
# build runs: the StatefulSet replaces its pod only when the pod is deleted.
set -euo pipefail

mode="${AEROL_K8S_MODE:-single}"
case "$mode" in
  single) cluster="${AEROL_KIND_CLUSTER:-aerolvm}" namespace="${AEROL_NAMESPACE:-aerolvm}" ;;
  cluster) cluster="${AEROL_KIND_CLUSTER:-aerolvm-cluster}" namespace="${AEROL_NAMESPACE:-aerolvm-system}" ;;
  *) echo "k8s-dev: AEROL_K8S_MODE is single or cluster, got $mode" >&2; exit 2 ;;
esac
edge="${AEROL_K8S_EDGE:-0}"
# The images' tag, and in cluster mode the version sandboxd reports: an
# AerolCluster's version is a release tag, and the operator upgrades any
# node that reports another (AEROL_K8S_VERSION=v0.0.0-dev.2 builds a
# second version to upgrade to).
tag="dev"
[[ "$mode" == cluster ]] && tag="${AEROL_K8S_VERSION:-v0.0.0-dev.1}"
ldflags="-X github.com/aerol-ai/microvm/internal/version.Version=$tag"
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
if [[ "$mode" == cluster ]]; then
  # The operator is its own Go module (operator/).
  (cd operator && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$dist/aerolvm-operator_linux_$arch" ./cmd/aerolvm-operator)
fi
# As this user, not root: the module cache is this machine's, and folders
# root makes in it stop a later `go install` here (CI's xcaddy step).
# -buildvcs=false: the container's git refuses a checkout another user owns
# (a CI runner's), and sandboxd's version comes from ldflags anyway.
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOPATH=/tmp/go -e GOMODCACHE=/go/pkg/mod \
  -e GOCACHE=/tmp/go-build -e GOTOOLCHAIN=auto -e CGO_ENABLED=1 \
  -v "$root":/src -v "$(go env GOMODCACHE)":/go/pkg/mod -v "$dist":/out -w /src \
  golang:1.26 go build -buildvcs=false -trimpath -ldflags "$ldflags" -o "/out/sandboxd_linux_$arch" ./cmd/sandboxd

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
[[ "$mode" == cluster ]] && images="$images,aerolvm-operator"
scripts/build-images.sh --dist "$dist" --version "$tag" --platforms "linux/$arch" --images "$images"

if ! kind get clusters 2>/dev/null | grep -qx "$cluster"; then
  if [[ "$mode" == cluster ]]; then
    # Three nodes, one per zone, so the operator spreads servers, gateways
    # and workers as it would across a cloud region's zones.
    cat >"$dist/kind-cluster.yaml" <<'KIND'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
    labels: { topology.kubernetes.io/zone: z-a }
  - role: worker
    labels: { topology.kubernetes.io/zone: z-b }
  - role: worker
    labels: { topology.kubernetes.io/zone: z-c }
KIND
    kind create cluster --name "$cluster" --config "$dist/kind-cluster.yaml"
  else
    kind create cluster --name "$cluster"
  fi
fi
kind load docker-image --name "$cluster" $(printf "ghcr.io/aerol-ai/%s:$tag " ${images//,/ })

edge_flags=()
if [[ "$edge" == 1 || "$mode" == cluster ]]; then
  # cert-manager: the edge's certificate, and in cluster mode the
  # operator's webhook certificate too.
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
  if [[ "$edge" == 1 ]]; then
    edge_flags=(--set edge.enabled=true --set edge.domain=aerolvm.test
      --set edge.certManager.issuerRef.name=aerolvm-dev --set edge.service.type=ClusterIP)
  fi
fi

if [[ "$mode" == cluster ]]; then
  # Small requests: kind's nodes all share this machine. Each node reports
  # the whole machine, so the pods fit on paper; little runs in them.
  cat >"$dist/cluster-values.yaml" <<'VALUES'
mode: cluster
cluster:
  zones: [z-a, z-b, z-c]
  servers:
    count: 3
    storage: { size: 1Gi }
    resources: { requests: { cpu: 100m, memory: 256Mi }, limits: { cpu: "1", memory: 1Gi } }
  gateways:
    minReplicas: 3
    resources: { requests: { cpu: 100m, memory: 256Mi }, limits: { cpu: "1", memory: 1Gi } }
    service: { type: ClusterIP }
  workerPools:
    - name: general
      runtimes: [runc, gvisor]
      machine: { cpu: 4, memoryGiB: 8 }
      minWorkers: 3
      maxWorkers: 6
      headroomPercent: 15
      decommission: { drainWindow: 30s, deadline: 5m }
  operator:
    replicas: 1
VALUES
  kubectl --context "kind-$cluster" create namespace "$namespace" --dry-run=client -o yaml | kubectl --context "kind-$cluster" apply -f - >/dev/null
  # Servers, gateways and the operator run under `restricted` (C5).
  kubectl --context "kind-$cluster" label namespace "$namespace" pod-security.kubernetes.io/enforce=restricted --overwrite >/dev/null
  "$helm" --kube-context "kind-$cluster" upgrade --install aerolvm charts/aerolvm -n "$namespace" \
    -f "$dist/cluster-values.yaml" --set image.tag="$tag" --set cluster.version="$tag" --set image.pullPolicy=Never ${edge_flags[@]+"${edge_flags[@]}"}
  # The operator replaces nothing a new image changes on its own: restart it
  # so a rebuilt operator runs.
  kubectl --context "kind-$cluster" -n "$namespace" rollout restart deployment/aerolvm-operator >/dev/null
  echo "k8s-dev: waiting for the AerolCluster to be Ready (servers, gateways, workers)" >&2
  for _ in $(seq 1 120); do
    phase="$(kubectl --context "kind-$cluster" -n "$namespace" get aerolcluster aerolvm -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [[ "$phase" == Ready ]] && break
    sleep 5
  done
  kubectl --context "kind-$cluster" -n "$namespace" get aerolcluster,aerolnodes >&2
  [[ "$phase" == Ready ]] || { echo "k8s-dev: the AerolCluster is $phase, not Ready" >&2; exit 1; }
  echo "k8s-dev: ready. Next: kubectl -n $namespace port-forward svc/aerolvm-gateway 21212:21212" >&2
  exit 0
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

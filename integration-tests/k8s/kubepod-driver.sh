#!/usr/bin/env bash
# kubepod-driver.sh: the pod-mode driver (internal/runtime/kubepod,
# plans/security-gaps-m1-m4.md M4, PR 1 of the M4 stack) against a real API
# server, on a local kind cluster. Nothing in sandboxd uses the driver yet;
# this runs its own test, TestKindDriver, inside a pod.
#
#   kind create cluster --name aerolvm-kubepod --kubeconfig /path/to/kubeconfig
#   AEROL_KIND_CLUSTER=aerolvm-kubepod KUBECONFIG=/path/to/kubeconfig \
#     integration-tests/k8s/kubepod-driver.sh
#
# It builds toolboxd and the test as static binaries, puts each in an image
# of its own with nothing else in it, loads them into kind, and runs the
# test in a pod. The pod and its namespaces show what pod mode needs:
#   worker     the test runs as the worker would: a pod in a namespace with
#              Pod Security "restricted" (not root, no capabilities, read-only
#              root disk) whose service account may only create, delete, get,
#              list and watch pods, and only in the sandbox namespace;
#   sandboxes  the namespace of the sandbox pods, with Pod Security
#              "baseline": no privileged pod, no host path, no host network;
#   toolbox    the toolbox image holds toolboxd alone (no shell, no cp): its
#              init container copies toolboxd with --install-to.
# The test then creates a sandbox, reads toolboxd's /health from the worker
# pod, checks a second create is a duplicate, stops, starts and destroys it.
# TestKindDriverWatch does it again with the driver's pod watch running
# (M4 PR 2): the waits use the watch, and each start, stop and pod deleted
# behind the worker's back comes as an event with the kubelet's time.
# First, a privileged pod is refused in the sandbox namespace, so the Pod
# Security labels are known to be enforced.
#
# Env: AEROL_KUBEPOD_IMAGE is the sandbox image (default busybox:1.36.1,
# pulled once by Docker if it is not there; any local image works, with a
# tag other than "latest", for which the kubelet would pull again);
# AEROL_KUBEPOD_KEEP=1 keeps the namespaces for a look afterwards. Exits 0
# when every step passed. It refuses any cluster but a local kind one.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cluster="${AEROL_KIND_CLUSTER:-aerolvm-kubepod}"
kc="${KUBECONFIG:?set KUBECONFIG to the kubeconfig file of the kind cluster}"
sandbox_image="${AEROL_KUBEPOD_IMAGE:-busybox:1.36.1}"
worker_ns=kubepod-worker
sandbox_ns=kubepod-sandboxes

if ! kind get clusters 2>/dev/null | grep -qx "$cluster"; then
  echo "kubepod-driver.sh: no kind cluster named $cluster; it runs only on a local kind cluster" >&2
  exit 2
fi
k() { kubectl --kubeconfig "$kc" --context "kind-$cluster" "$@"; }

case "$(docker info --format '{{.Architecture}}')" in
  aarch64 | arm64) goarch=arm64 ;;
  x86_64 | amd64) goarch=amd64 ;;
  *) echo "kubepod-driver.sh: unknown Docker architecture" >&2; exit 2 ;;
esac

work="$(mktemp -d)"
tag="m4-$(date +%s)"
toolbox_image="aerolvm-toolbox:$tag"
test_image="aerolvm-kubepod-test:$tag"
mkdir -p "$work/toolbox" "$work/test"
# The build folder holds only the files named here; they go on any exit.
cleanup_work() {
  rm -f "$work/toolbox/toolboxd" "$work/toolbox/Dockerfile" "$work/test/kubepod.test" "$work/test/Dockerfile"
  rmdir "$work/toolbox" "$work/test" "$work" 2>/dev/null || true
}
trap cleanup_work EXIT
echo "== build ($goarch, static) in $work"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -o "$work/toolbox/toolboxd" ./cmd/toolboxd)
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go test -c -tags integration -o "$work/test/kubepod.test" ./internal/runtime/kubepod)
printf 'FROM scratch\nCOPY toolboxd /toolboxd\n' >"$work/toolbox/Dockerfile"
printf 'FROM scratch\nCOPY kubepod.test /kubepod.test\n' >"$work/test/Dockerfile"
docker build -q -t "$toolbox_image" "$work/toolbox" >/dev/null
docker build -q -t "$test_image" "$work/test" >/dev/null
docker image inspect "$sandbox_image" >/dev/null 2>&1 || docker pull -q "$sandbox_image" >/dev/null
kind load docker-image --name "$cluster" "$toolbox_image" "$test_image" "$sandbox_image" >/dev/null
cleanup_work

echo "== namespaces, RuntimeClass, the worker's Role"
k apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $worker_ns
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: v1
kind: Namespace
metadata:
  name: $sandbox_ns
  labels:
    pod-security.kubernetes.io/enforce: baseline
---
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: runc
handler: runc
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kubepod-worker
  namespace: $worker_ns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kubepod-worker
  namespace: $sandbox_ns
rules:
  - apiGroups: [""]
    resources: [pods]
    verbs: [create, delete, get, list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kubepod-worker
  namespace: $sandbox_ns
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: kubepod-worker
subjects:
  - kind: ServiceAccount
    name: kubepod-worker
    namespace: $worker_ns
EOF

failed=0
echo "== a privileged pod is refused in the sandbox namespace"
if out="$(k apply --dry-run=server -f - 2>&1 <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: refused
  namespace: $sandbox_ns
spec:
  containers:
    - name: c
      image: $sandbox_image
      securityContext:
        privileged: true
EOF
)"; then
  echo "FAIL a privileged pod was admitted: $out"
  failed=1
else
  echo "PASS refused: $(grep -o 'violates PodSecurity[^:]*' <<<"$out" | head -1)"
fi

echo "== the test, as the worker"
k -n "$worker_ns" delete pod kubepod-driver-test --ignore-not-found --wait=true >/dev/null
k apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: kubepod-driver-test
  namespace: $worker_ns
spec:
  serviceAccountName: kubepod-worker
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: test
      image: $test_image
      imagePullPolicy: Never
      command: [/kubepod.test, -test.run, TestKindDriver, -test.v, -test.count=1]
      env:
        - {name: AEROL_KUBEPOD_KIND, value: "1"}
        - {name: AEROL_KUBEPOD_NAMESPACE, value: $sandbox_ns}
        - {name: AEROL_KUBEPOD_WORKER, value: kind-worker-0}
        - {name: AEROL_KUBEPOD_CLASS, value: runc}
        - {name: AEROL_KUBEPOD_TOOLBOX_IMAGE, value: "$toolbox_image"}
        - {name: AEROL_KUBEPOD_TOOLBOX_PATH, value: /toolboxd}
        - {name: AEROL_KUBEPOD_IMAGE, value: "$sandbox_image"}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
      volumeMounts:
        - {name: tmp, mountPath: /tmp}
  volumes:
    - name: tmp
      emptyDir: {}
EOF

phase=Pending
for _ in $(seq 1 240); do
  phase="$(k -n "$worker_ns" get pod kubepod-driver-test -o jsonpath='{.status.phase}')"
  [[ "$phase" == Succeeded || "$phase" == Failed ]] && break
  sleep 3
done
k -n "$worker_ns" logs kubepod-driver-test | grep -E 'PASS|FAIL|^---|^ok|^panic|kind_integration_test' || true
if [[ "$phase" == Succeeded ]]; then
  echo "PASS TestKindDriver"
else
  echo "FAIL TestKindDriver: the test pod ended $phase"
  failed=1
fi
left="$(k -n "$sandbox_ns" get pods -o name)"
if [[ -n "$left" ]]; then
  echo "FAIL sandbox pods left behind: $left"
  failed=1
fi

if [[ "${AEROL_KUBEPOD_KEEP:-}" != 1 ]]; then
  k delete namespace "$worker_ns" "$sandbox_ns" --wait=false >/dev/null
  k delete runtimeclass runc --ignore-not-found >/dev/null
fi
exit "$failed"

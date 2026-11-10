#!/usr/bin/env bash
# lib.sh: the steps every Phase 0 run shares (h0.sh, s2.sh). Source it, then
# call lib_init <cluster name> <report name>.
#
# Each step was proven on a live run before it moved here; the comments say
# what broke when it was missing.

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_ROOT="$(cd "$LIB_DIR/../.." && pwd)"
NS=aerolvm-workers
POD=worker-0
DEBUG_IMAGE=public.ecr.aws/amazonlinux/amazonlinux:2023

lib_init() {
  local name="$1" rname="$2"
  KUBECONFIG="$("$LIB_DIR/cluster.sh" kubeconfig "$name")"
  export KUBECONFIG
  sd="$LIB_DIR/.state/$name"
  report="$sd/$rname"
  : > "$report"
  pf=""
  trap '[[ -n "$pf" ]] && kill $pf 2>/dev/null || true' EXIT
}

say() { echo "$*" | tee -a "$report"; }
ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }

# publish_build puts this branch's sandboxd and toolboxd in S3 and writes
# presigned URLs to $sd/urls.tfvars. Built from the last commit, not the
# working tree: harness files do not go into sandboxd, so editing them must
# not force a new build or upload.
publish_build() {
  local ref k
  ref="$(git -C "$LIB_ROOT" rev-parse HEAD)"
  "$LIB_ROOT/integration-tests/lib/build.sh" build --ref "$ref" --arch amd64 >&2
  "$LIB_ROOT/integration-tests/lib/build.sh" publish --ref "$ref" --ttl 6h --arch amd64 >&2
  "$LIB_ROOT/integration-tests/lib/build.sh" urls --ref "$ref" --ttl 6h --arch amd64 > "$sd/urls.tfvars"
  for k in sandboxd_url toolboxd_url checksums_url; do
    [[ -n "$(url_of "$k")" ]] || { echo "lib: build.sh urls gave no $k" >&2; return 1; }
  done
  say "build: $(head -1 "$sd/urls.tfvars")"
}
url_of() { sed -n "s/^$1 *= *\"\(.*\)\"$/\1/p" "$sd/urls.tfvars"; }

# load_br_netfilter is the stand-in for finding F2: stock EKS nodes do not
# load br_netfilter, and sandboxd refuses to start without it. modprobe runs
# in a node debug pod against the host's /lib/modules (at /host), because
# Bottlerocket's host has no shell to chroot into.
load_br_netfilter() {
  local n d
  for n in $(kubectl get nodes -l aerolvm.io/pool=phase0 -o jsonpath='{.items[*].metadata.name}'); do
    kubectl debug "node/$n" --profile=sysadmin --image="$DEBUG_IMAGE" -- \
      sh -c 'dnf -y -q install kmod >/dev/null && modprobe -d /host br_netfilter && echo "br_netfilter: $(grep -c ^br_netfilter /proc/modules) loaded"' >/dev/null 2>&1 || true
  done
  sleep 45
  for d in $(kubectl get pods -o name 2>/dev/null | grep node-debugger || true); do
    kubectl logs "$d" 2>/dev/null | tail -2 >&2 || true
    kubectl delete "$d" --wait=false >/dev/null
  done
  say "br_netfilter loaded on the worker nodes (F2 stand-in)"
}

# apply_worker <manifest> <c7 0|1>: namespace, boot scripts, URLs and token,
# then a fresh pod (a pod's spec cannot change, so the old one is deleted).
apply_worker() {
  local manifest="$1" c7="$2"
  token="$(openssl rand -hex 24)"
  ( umask 077; echo "$token" > "$sd/api-token" )
  kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl label namespace "$NS" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null
  kubectl -n "$NS" create configmap worker-boot \
    --from-file=fetch.sh="$LIB_DIR/worker/fetch.sh" --from-file=common.sh="$LIB_DIR/worker/common.sh" \
    --from-file=run.sh="$LIB_DIR/worker/run.sh" --from-file=runtime.sh="$LIB_DIR/worker/runtime.sh" \
    --from-file=agent.sh="$LIB_DIR/worker/agent.sh" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n "$NS" create secret generic worker-urls \
    --from-literal=SANDBOXD_URL="$(url_of sandboxd_url)" \
    --from-literal=TOOLBOXD_URL="$(url_of toolboxd_url)" \
    --from-literal=CHECKSUMS_URL="$(url_of checksums_url)" \
    --from-literal=SB_PAT_TOKEN="$token" \
    --from-literal=AEROL_C7_CGROUP_PARENT="$c7" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  remove_worker
  kubectl apply -f "$manifest" >/dev/null
}

# remove_worker deletes the worker pod and waits until it is gone. With S2's
# Bidirectional /run/netns, the network namespaces sandboxd mounted stay in
# the machine's own mount table after the pod dies, so the kubelet cannot
# remove the volume and the pod sticks in Terminating (finding F8). The
# stand-in unmounts them in the machine's mount namespace (nsenter -t 1 -m)
# once the containers have stopped.
remove_worker() {
  local uid node
  uid="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
  [[ -n "$uid" ]] || return 0
  node="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')"
  kubectl -n "$NS" delete pod "$POD" --wait=false >/dev/null
  sleep 20
  if [[ -n "$node" ]]; then
    kubectl debug "node/$node" --profile=sysadmin --image="$DEBUG_IMAGE" -- chroot /host nsenter -t 1 -m -- \
      sh -c "for m in \$(grep $uid /proc/self/mountinfo | awk '{print \$5}' | grep /netns/); do umount \$m && echo unmounted \${m##*/}; done" >/dev/null 2>&1 || true
  fi
  if ! kubectl -n "$NS" wait --for=delete "pod/$POD" --timeout=5m >/dev/null 2>&1; then
    echo "lib: the old worker pod would not go" >&2
    return 1
  fi
  for d in $(kubectl get pods -o name 2>/dev/null | grep node-debugger || true); do
    kubectl delete "$d" --wait=false >/dev/null
  done
}

# wait_ready polls instead of `kubectl wait`: with restartPolicy Never a
# failed init container leaves the pod Failed, and wait would sit out its
# whole timeout.
wait_ready() {
  local t0 phase cond ready=0 c
  t0=$(date +%s)
  for _ in $(seq 1 180); do
    phase="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.phase}')"
    cond="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')"
    [[ "$cond" == True ]] && { ready=1; break; }
    [[ "$phase" == Failed || "$phase" == Succeeded ]] && break
    sleep 5
  done
  if [[ "$ready" != 1 ]]; then
    kubectl -n "$NS" get pod "$POD" -o wide >&2 || true
    for c in $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}'); do
      echo "--- logs of $c" >&2
      kubectl -n "$NS" logs "$POD" -c "$c" --tail=60 >&2 || true
    done
    echo "lib: worker pod never became Ready (phase ${phase:-unknown})" >&2
    return 1
  fi
  say "qos class: $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.qosClass}')"
  say "pod ready after $(( $(date +%s) - t0 ))s on node $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')"
}

# forward keeps a port-forward to the API alive: kubectl port-forward quits
# for good after one refused connection, so it is restarted when it has died.
forward() {
  if [[ -z "$pf" ]] || ! kill -0 "$pf" 2>/dev/null; then
    kubectl -n "$NS" port-forward "pod/$POD" 21212:21212 >/dev/null 2>&1 &
    pf=$!
    sleep 2
  fi
}

# (route, not path: in zsh `path` is tied to PATH, and sourcing this there
# once broke every call.)
api() {
  local route="$1"; shift
  curl -fsS --max-time 120 -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    "http://127.0.0.1:21212${route}" "$@"
}

# wait_api waits for sandboxd's /v1 to answer through the port-forward.
wait_api() {
  local _
  for _ in $(seq 1 90); do
    forward
    if api /v1/sandboxes >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  echo "lib: sandboxd API never answered" >&2
  return 1
}

# node_debug <shell> runs a command in a node debug pod and appends its output
# to the report. No chroot: Bottlerocket's host has no shell. The debug pod
# shares the machine's PID and network namespaces, and as a privileged
# container it sees the machine's whole cgroup tree, so /proc and
# /sys/fs/cgroup there are the machine's.
node_debug() {
  local node before after
  node="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')"
  before="$(kubectl get pods -o name 2>/dev/null | grep node-debugger || true)"
  kubectl debug "node/$node" --profile=sysadmin --image="$DEBUG_IMAGE" -- \
    sh -c "$1" >/dev/null 2>&1 || true
  after=""
  for _ in $(seq 1 45); do
    after="$(kubectl get pods -o name 2>/dev/null | grep node-debugger | grep -vxF "$before" | head -1 || true)"
    if [[ -n "$after" ]] && [[ "$(kubectl get "$after" -o jsonpath='{.status.phase}')" =~ ^(Succeeded|Failed)$ ]]; then break; fi
    sleep 2
  done
  if [[ -n "$after" ]]; then
    kubectl logs "$after" | tee -a "$report"
    kubectl delete "$after" --wait=false >/dev/null
  else
    say "(the debug pod did not finish)"
  fi
}

# pod_uid is the pod's UID as it appears in its cgroup slice name.
pod_uid() { kubectl -n "$NS" get pod "$POD" -o jsonpath='{.metadata.uid}' | tr - _; }

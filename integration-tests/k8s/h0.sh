#!/usr/bin/env bash
# h0.sh: put the H0 worker pod on a Phase 0 cluster, smoke-test it, and
# collect spike S1's evidence (plans/kubernetes-v2-phase0.md).
#
#   cluster.sh up <name>
#   h0.sh <name> [--c7]     # writes .state/<name>/h0-report.txt
#   cluster.sh down <name>
#
# The smoke test creates one gVisor sandbox through sandboxd's /v1 API and
# runs a command in it. The S1 part records, without judging, where the
# worker pod's processes sit in the cgroup tree, how memory is charged, and
# which network links exist on the machine. --c7 turns on the C7 cgroup
# placement (SB_CONTAINERD_CGROUP_PARENT).
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

name="${1:?usage: h0.sh <name> [--c7] [--s7]}"
c7=0; manifest="$LIB_DIR/manifests/worker-h0.yaml"; rname=h0-report.txt
for a in "${@:2}"; do
  case "$a" in
    --c7) c7=1 ;;
    # S7: the same worker with a named list of rights, not privileged.
    --s7) manifest="$LIB_DIR/manifests/worker-s7.yaml"; rname=s7-report.txt ;;
    *) echo "h0: unknown flag $a" >&2; exit 2 ;;
  esac
done
lib_init "$name" "$rname"

publish_build
load_br_netfilter
apply_worker "$manifest" "$c7"
say "privileged: $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.containers[0].securityContext.privileged}'); added rights: $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.containers[0].securityContext.capabilities.add}')"
wait_ready
wait_api

t0=$(ms)
created="$(api /v1/sandboxes -X POST -d '{"image":"alpine:3.20","runtime":"gvisor"}')"
t1=$(ms)
id="$(jq -r '.id // empty' <<<"$created")"
[[ -n "$id" ]] || { echo "h0: create returned no id: $created" >&2; exit 1; }
say "create (cold, image pull included, through a port-forward): $(( t1 - t0 )) ms, sandbox $id"
out="$(api "/v1/sandboxes/$id/toolbox/process/execute" -X POST \
  -d '{"command":"echo hello-from-gvisor; uname -r; cat /proc/self/cgroup"}')"
say "exec: $(jq -c '{exit_code, stdout}' <<<"$out")"

uid="$(pod_uid)"
say "--- S1: pod uid ${uid}; C7 cgroup placement: $([[ $c7 == 1 ]] && echo on || echo off)"
if kubectl -n "$NS" exec "$POD" -c worker -- true >/dev/null 2>&1; then
  say "kubectl exec into the worker: works"
else
  say "kubectl exec into the worker: FAILS ($(kubectl -n "$NS" exec "$POD" -c worker -- true 2>&1 | tail -1 | cut -c1-160))"
fi
say "--- S1: every process in the worker pod's cgroup, from the machine"
node_debug "for d in /proc/[0-9]*; do g=\$(cut -d: -f3 \$d/cgroup 2>/dev/null); case \$g in *pod${uid}*) echo \${d#/proc/} \$(cat \$d/comm 2>/dev/null) \$g;; esac; done"
say "--- S1: memory charged to the worker container's group and to its sandboxes"
node_debug "for d in /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/cri-containerd-*.scope /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/cri-containerd-*.scope/sandboxes /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/cri-containerd-*.scope/sandboxes/*/; do [ -d \$d ] && echo \$d memory.current=\$(cat \$d/memory.current) memory.max=\$(cat \$d/memory.max); done"
say "--- S1: network links on the machine"
node_debug "cut -d: -f1 /proc/net/dev | tail -n +3 | tr -d ' '"

api "/v1/sandboxes/$id" -X DELETE >/dev/null || true
say "--- done; report in $report"

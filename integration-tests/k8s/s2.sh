#!/usr/bin/env bash
# s2.sh: spike S2 (plans/kubernetes-v2-phase0.md). Upgrade the agent in place
# and check that no sandbox restarts.
#
#   cluster.sh up <name>
#   s2.sh <name>          # writes .state/<name>/s2-report.txt
#   cluster.sh down <name>
#
# 1. Put the split worker pod (runtime + agent, C7 on) on the cluster.
# 2. Create a gVisor sandbox; read its uptime from inside, leave a marker file,
#    and list its processes from the machine.
# 3. Change the agent container's image in place (another tag of the same
#    Amazon Linux image, so the kubelet sees a changed image).
# 4. Check: only the agent restarted; the sandbox still answers; its uptime
#    kept counting; the marker is there; its processes are the same ones; and
#    a new sandbox can be created through the new agent.
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

name="${1:?usage: s2.sh <name>}"
# Same registry and repository, another tag: certain to exist, and a changed
# image string is what makes the kubelet restart the container.
NEW_AGENT_IMAGE=public.ecr.aws/amazonlinux/amazonlinux:latest
lib_init "$name" s2-report.txt

publish_build
load_br_netfilter
apply_worker "$LIB_DIR/manifests/worker-s2.yaml" 1
wait_ready
wait_api

restarts() {
  kubectl -n "$NS" get pod "$POD" -o jsonpath='{range .status.containerStatuses[*]}{.name}={.restartCount} {end}'
}
uptime_of() {
  api "/v1/sandboxes/$1/toolbox/process/execute" -X POST -d '{"command":"cut -d\" \" -f1 /proc/uptime"}' |
    jq -r '.stdout' | tr -d '[:space:]'
}
sandbox_procs() {
  # PIDs and names of the gVisor sandbox's processes, from the machine.
  node_debug "for d in /proc/[0-9]*; do g=\$(cut -d: -f3 \$d/cgroup 2>/dev/null); case \$g in *pod$(pod_uid)*/sandboxes/*) echo \${d#/proc/} \$(cat \$d/comm 2>/dev/null);; esac; done" | sort
}

id="$(api /v1/sandboxes -X POST -d '{"image":"alpine:3.20","runtime":"gvisor"}' | jq -r '.id // empty')"
[[ -n "$id" ]] || { echo "s2: create returned no id" >&2; exit 1; }
api "/v1/sandboxes/$id/toolbox/process/execute" -X POST -d '{"command":"echo s2-marker > /tmp/marker"}' >/dev/null
sleep 5
up_before="$(uptime_of "$id")"
say "sandbox $id; uptime inside before the swap: ${up_before}s; restarts: $(restarts)"
say "--- sandbox processes before the swap (pid name)"
procs_before="$(sandbox_procs)"

# The swap. Only the image of the agent container changes.
say "--- swapping the agent image to $NEW_AGENT_IMAGE"
t_swap=$(ms)
idx="$(kubectl -n "$NS" get pod "$POD" -o json | jq '.spec.containers | map(.name) | index("agent")')"
kubectl -n "$NS" patch pod "$POD" --type=json \
  -p "[{\"op\":\"replace\",\"path\":\"/spec/containers/${idx}/image\",\"value\":\"${NEW_AGENT_IMAGE}\"}]" >/dev/null

# Wait for the new agent: a restart counted and the API answering again. The
# time until the API answers is what callers see. Not the reported image:
# :latest and :2023 are one image, and the node keeps reporting the first name
# it pulled it under (first S2 run, 2026-11-10).
back=0
for _ in $(seq 1 240); do
  rc="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')"
  if [[ "${rc:-0}" -ge 1 ]]; then
    forward
    if api /v1/sandboxes >/dev/null 2>&1; then back=1; break; fi
  fi
  sleep 1
done
t_back=$(ms)
if [[ "$back" != 1 ]]; then
  kubectl -n "$NS" logs "$POD" -c agent --tail=60 >&2 || true
  say "S2 FAIL: the new agent never answered"
  exit 1
fi
say "agent answered again $(( t_back - t_swap )) ms after the image change; restarts: $(restarts)"

state="$(api "/v1/sandboxes/$id" | jq -r '.status // .state // empty')"
up_after="$(uptime_of "$id" || echo "")"
marker="$(api "/v1/sandboxes/$id/toolbox/process/execute" -X POST -d '{"command":"cat /tmp/marker"}' | jq -r '.stdout' | tr -d '[:space:]' || true)"
say "sandbox $id after the swap: status ${state:-unknown}; uptime ${up_after:-none}s; marker '${marker}'"
say "--- sandbox processes after the swap (pid name)"
procs_after="$(sandbox_procs)"

t0=$(ms)
id2="$(api /v1/sandboxes -X POST -d '{"image":"alpine:3.20","runtime":"gvisor"}' | jq -r '.id // empty')"
say "new sandbox through the new agent: ${id2:-FAILED} in $(( $(ms) - t0 )) ms"

# Verdict.
verdict=PASS
rt_restarts="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[?(@.name=="runtime")].restartCount}')"
[[ "$rt_restarts" == 0 ]] || { verdict=FAIL; say "fail: the runtime container restarted ($rt_restarts)"; }
python3 -c "import sys; sys.exit(0 if float('${up_after:-0}') > float('${up_before:-0}') else 1)" ||
  { verdict=FAIL; say "fail: uptime did not keep counting (${up_before} -> ${up_after:-none})"; }
[[ "$marker" == s2-marker ]] || { verdict=FAIL; say "fail: the marker file is gone"; }
[[ -n "$procs_before" && "$procs_before" == "$procs_after" ]] || { verdict=FAIL; say "fail: the sandbox's processes changed"; }
[[ -n "${id2:-}" ]] || { verdict=FAIL; say "fail: no new sandbox through the new agent"; }
say "S2 verdict: $verdict"

api "/v1/sandboxes/$id" -X DELETE >/dev/null || true
[[ -n "${id2:-}" ]] && api "/v1/sandboxes/$id2" -X DELETE >/dev/null || true
say "--- done; report in $report"
[[ "$verdict" == PASS ]]

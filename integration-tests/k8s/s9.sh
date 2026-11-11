#!/usr/bin/env bash
# s9.sh: spike S9 (plan §8.7). The H0 worker in a pod with its own user
# namespace (hostUsers: false), not privileged. The pod first runs
# s9-probe.sh, which answers S9's three questions (cgroup limits, sandbox
# networking, gVisor), then tries the real worker. This script records the
# probe's answers and how far the worker gets, and, if it gets all the way,
# creates a gVisor sandbox and checks which user its processes run as on the
# machine.
#
#   cluster.sh up <name>
#   s9.sh <name>          # writes .state/<name>/s9-report.txt
#   cluster.sh down <name>
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

name="${1:?usage: s9.sh <name>}"
lib_init "$name" s9-report.txt

publish_build
load_br_netfilter
apply_worker "$LIB_DIR/manifests/worker-s9.yaml" 1

# The pod may never become Ready here, which is itself the answer, so wait for
# Ready, Failed, or the probe's output plus time for the worker to try.
state=waiting
for _ in $(seq 1 120); do
  phase="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.phase}')"
  cond="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')"
  if [[ "$cond" == True ]]; then state=ready; break; fi
  if [[ "$phase" == Failed || "$phase" == Succeeded ]]; then state="$phase"; break; fi
  if kubectl -n "$NS" logs "$POD" -c worker 2>/dev/null | grep -q 'sandboxd exited with error\|run: containerd did not start'; then state=worker-stopped; break; fi
  sleep 5
done
say "pod state after the wait: $state"
say "hostUsers: $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.hostUsers}')"
say "--- the probe's answers"
kubectl -n "$NS" logs "$POD" -c worker 2>/dev/null | grep '^s9: ' | tee -a "$report" >/dev/null || true
say "--- where the worker stopped (errors and its own messages)"
kubectl -n "$NS" logs "$POD" -c worker 2>/dev/null |
  grep -E '^run: |level=ERROR|did not start|Permission denied|Operation not permitted|Read-only' |
  grep -v 'docker' | tail -12 | cut -c1-400 | tee -a "$report" >/dev/null || true

if [[ "$state" == ready ]]; then
  wait_api
  created="$(api /v1/sandboxes -X POST -d '{"image":"alpine:3.20","runtime":"gvisor"}' 2>&1 || true)"
  id="$(jq -r '.id // empty' <<<"$created" 2>/dev/null || true)"
  if [[ -n "$id" ]]; then
    out="$(api "/v1/sandboxes/$id/toolbox/process/execute" -X POST -d '{"command":"echo hello-from-gvisor"}' | jq -r '.stdout' || true)"
    say "gVisor sandbox in the user-namespaced pod: $id, exec: $out"
    say "--- the user the pod's processes run as, on the machine (S9's point)"
    node_debug "for d in /proc/[0-9]*; do g=\$(cut -d: -f3 \$d/cgroup 2>/dev/null); case \$g in *pod$(pod_uid)*) echo \${d#/proc/} \$(cat \$d/comm 2>/dev/null) uid=\$(awk '/^Uid:/{print \$2}' \$d/status);; esac; done | sort -u -k2,3 | head -12"
  else
    say "gVisor create failed: $(echo "$created" | tail -1 | cut -c1-200)"
    kubectl -n "$NS" logs "$POD" -c worker 2>/dev/null | grep 'request failed' | tail -2 | cut -c1-400 | tee -a "$report" >/dev/null || true
  fi
fi
say "--- done; report in $report"

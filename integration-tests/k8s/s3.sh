#!/usr/bin/env bash
# s3.sh: spike S3 (plans/kubernetes-v2-phase0.md). Memory pressure, and what
# the kubelet and cAdvisor pay per sandbox.
#
#   cluster.sh up <name> --type m7i.4xlarge
#   s3.sh <name>          # writes .state/<name>/s3-report.txt
#   cluster.sh down <name>
#
# 1. A machine-sized worker pod (15 CPUs, 54 GiB, Guaranteed, C7 on).
# 2. At 0, 100, 500 and 1,000 small gVisor sandboxes (0.1 CPU, 64 MB each):
#    cAdvisor series for the pod, the kubelet's CPU time and memory, the
#    pod's memory and the machine's free memory.
# 3. Every sandbox fills 48 MB of its /dev/shm at once, pushing the pod past
#    its limit. Recorded: what the kernel killed, whether the kubelet evicted
#    the pod, the node's MemoryPressure, and whether sandboxd still answers.
#
# --supervisor runs F10's full fix as it ships instead of the shell stand-in:
# the split pod (worker-s2.yaml) with Phase 1's Go supervisor as the runtime
# container (worker/runtime-supervisor.sh; sandboxes/ capped at the
# container's limit minus a reserve, its own memory protected, containerd in
# sandboxes/_runtime) and sandboxd in the agent container marking each
# sandbox as one OOM unit. The supervisor is built from AEROL_BUILD_REF and
# published to the artifact bucket like sandboxd.
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

name="${1:?usage: s3.sh <name> [--pressure-only] [--no-keeper] [--supervisor]}"
pressure_only=0 keeper=1 supervisor=0
for a in "${@:2}"; do
  case "$a" in
    --pressure-only) pressure_only=1 ;;
    # sandboxd, not the harness's loop, sets the sandboxes' OOM settings.
    --no-keeper) keeper=0 ;;
    --supervisor) supervisor=1 ;;
    *) echo "s3: unknown flag $a" >&2; exit 2 ;;
  esac
done
if [[ "$pressure_only" == 1 ]]; then lib_init "$name" s3-pressure-report.txt
elif [[ "$supervisor" == 1 ]]; then lib_init "$name" s3-supervisor-report.txt
else lib_init "$name" s3-report.txt; fi

# publish_supervisor builds cmd/aerolvm-supervisor at the build's commit and
# puts it in the artifact bucket; sets sup_url (presigned) and sup_sha.
publish_supervisor() {
  local ref wt bucket key
  ref="$(git -C "$LIB_ROOT" rev-parse "${AEROL_BUILD_REF:-HEAD}^{commit}")"
  wt="$(mktemp -d)"
  git -C "$LIB_ROOT" worktree add --detach --force "$wt" "$ref" >/dev/null 2>&1
  (cd "$wt" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$sd/aerolvm-supervisor" ./cmd/aerolvm-supervisor)
  git -C "$LIB_ROOT" worktree remove --force "$wt"
  bucket="aerol-itest-artifacts-$(aws sts get-caller-identity --query Account --output text)"
  key="builds/supervisor-${ref:0:12}/aerolvm-supervisor_linux_amd64"
  aws s3 cp --only-show-errors --region us-east-1 "$sd/aerolvm-supervisor" "s3://$bucket/$key"
  sup_url="$(aws s3 presign --region us-east-1 "s3://$bucket/$key" --expires-in 21600)"
  sup_sha="$(shasum -a 256 "$sd/aerolvm-supervisor" | cut -d' ' -f1)"
  say "supervisor built at ${ref:0:12} and published"
}
STAGES=(100 500 1000)
PARALLEL=20

if [[ "$pressure_only" == 0 ]]; then
publish_build
load_br_netfilter

if [[ "$supervisor" == 1 ]]; then
publish_supervisor
# The split worker, sized to an m7i.4xlarge: the runtime container holds the
# sandboxes, the agent sandboxd (it used 615 MB at 1,000 sandboxes in S3).
manifest="$sd/worker-s3-supervisor.yaml"
python3 - "$LIB_DIR/manifests/worker-s2.yaml" "$manifest" "$sup_url" "$sup_sha" <<'PY'
import sys
s = open(sys.argv[1]).read()
def rep(old, new):
    global s
    assert s.count(old) == 1, old
    s = s.replace(old, new)
rep('command: ["bash", "/boot/runtime.sh"]\n',
    'command: ["bash", "/boot/runtime-supervisor.sh"]\n      env:\n'
    '        - { name: SUPERVISOR_URL, value: "%s" }\n        - { name: SUPERVISOR_SHA256, value: "%s" }\n' % (sys.argv[3], sys.argv[4]))
rep('requests: { cpu: 2500m, memory: 11Gi }', 'requests: { cpu: "13", memory: 50Gi }')
rep('limits: { cpu: 2500m, memory: 11Gi }', 'limits: { cpu: "13", memory: 50Gi }')
rep('requests: { cpu: 500m, memory: 1Gi }', 'requests: { cpu: 1500m, memory: 2Gi }')
rep('limits: { cpu: 500m, memory: 1Gi }', 'limits: { cpu: 1500m, memory: 2Gi }')
rep('        - name: POD_NAME\n', '        - name: SB_CONTAINERD_NETNS_POOL_SIZE\n          value: "1200"\n        - name: POD_NAME\n')
open(sys.argv[2], "w").write(s)
PY
apply_worker "$manifest" 1
wait_ready
say "runtime container: $(kubectl -n "$NS" logs "$POD" -c runtime | grep -m1 'sandboxes go under' | cut -c1-240)"
else
# The H0 worker, sized to an m7i.4xlarge and with room for 1,200 network
# namespaces (the default pool of 256 would otherwise be what S3 measures).
manifest="$sd/worker-s3.yaml"
python3 - "$LIB_DIR/manifests/worker-h0.yaml" "$manifest" "$keeper" <<'EOF'
import sys
s = open(sys.argv[1]).read()
if sys.argv[3] == "0":
    s = s.replace('        - name: POD_NAME\n', '        - name: AEROL_KEEPER\n          value: "0"\n        - name: POD_NAME\n', 1)
s = s.replace('requests: { cpu: "3", memory: 12Gi }', 'requests: { cpu: "15", memory: 54Gi }')
s = s.replace('limits: { cpu: "3", memory: 12Gi }', 'limits: { cpu: "15", memory: 54Gi }')
s = s.replace('        - name: POD_NAME\n', '        - name: SB_CONTAINERD_NETNS_POOL_SIZE\n          value: "1200"\n        - name: POD_NAME\n', 1)
open(sys.argv[2], "w").write(s)
EOF
grep -q 'memory: 54Gi' "$manifest" && grep -q 'NETNS_POOL_SIZE' "$manifest" || { echo "s3: manifest edit failed" >&2; exit 1; }
apply_worker "$manifest" 1
wait_ready
fi
fi
# --pressure-only reuses the worker and sandboxes already on the cluster.
token="$(cat "$sd/api-token")"
wait_api
node="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')"
uid="$(pod_uid)"

measure() {
  local label="$1" series total
  series="$(kubectl get --raw "/api/v1/nodes/$node/proxy/metrics/cadvisor" | grep -c 'pod="worker-0"' || true)"
  total="$(kubectl get --raw "/api/v1/nodes/$node/proxy/metrics/cadvisor" | grep -vc '^#' || true)"
  say "--- $label: cAdvisor series for the worker pod: $series; all cAdvisor series on the node: $total"
  # kubelet's CPU seconds so far (utime + stime) and memory; the pod's memory;
  # the machine's available memory.
  node_debug "hz=\$(getconf CLK_TCK); for d in /proc/[0-9]*; do [ \"\$(cat \$d/comm 2>/dev/null)\" = kubelet ] && awk -v hz=\$hz '{printf \"kubelet cpu_seconds=%.1f \", (\$14+\$15)/hz}' \$d/stat && grep VmRSS \$d/status | tr -s ' '; done; echo pod memory.current=\$(cat /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/memory.current) machine MemAvailable=\$(grep MemAvailable /proc/meminfo | tr -s ' ' | cut -d' ' -f2)kB"
}

count_sandboxes() { api /v1/sandboxes | jq 'length'; }

ramp_to() {
  local target="$1" have need t0 ok
  have="$(count_sandboxes)"
  need=$(( target - have ))
  (( need > 0 )) || return 0
  t0=$(ms)
  forward
  seq 1 "$need" | xargs -P "$PARALLEL" -I{} sh -c \
    "curl -fsS --max-time 120 -o /dev/null -H 'Authorization: Bearer $token' -H 'Content-Type: application/json' \
       -d '{\"image\":\"alpine:3.20\",\"runtime\":\"gvisor\",\"cpu\":0.1,\"memory_mb\":64,\"disk_gb\":1}' \
       http://127.0.0.1:21212/v1/sandboxes && echo ok || echo fail" > "$sd/ramp-$target.txt" 2>/dev/null || true
  ok="$(grep -c '^ok' "$sd/ramp-$target.txt" || true)"
  say "ramp to $target: $ok of $need creates ok in $(( ($(ms) - t0) / 1000 )) s (parallel $PARALLEL); sandboxes now: $(count_sandboxes)"
}

if [[ "$pressure_only" == 0 ]]; then
  measure "0 sandboxes"
  for n in "${STAGES[@]}"; do
    ramp_to "$n"
    sleep 30
    measure "$n sandboxes"
  done
fi

say "--- OOM settings before the pressure: memory.oom.group of the pod, the worker container and sandboxes/; OOM score by process"
node_debug "for d in /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/cri-containerd-*.scope /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/cri-containerd-*.scope/sandboxes; do echo \${d##*/} memory.oom.group=\$(cat \$d/memory.oom.group); done; for d in /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/cri-containerd-*.scope/sandboxes /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/cri-containerd-*.scope/sandboxes/_runtime /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/cri-containerd-*.scope/supervisor; do [ -d \$d ] && echo \${d##*/} memory.max=\$(cat \$d/memory.max) memory.min=\$(cat \$d/memory.min) memory.current=\$(cat \$d/memory.current); done; echo sandbox groups with memory.oom.group=1: \$(cat /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/cri-containerd-*.scope/sandboxes/*/memory.oom.group 2>/dev/null | grep -c 1); for d in /proc/[0-9]*; do g=\$(cut -d: -f3 \$d/cgroup 2>/dev/null); case \$g in *pod${uid}*) echo \$(cat \$d/comm) oom_score_adj=\$(cat \$d/oom_score_adj);; esac; done | sort | uniq -c | sort -rn | head -12"

# Memory pressure: each sandbox writes 48 MB to its tmpfs at once. Within each
# sandbox's own 64 MB limit, but together about 48 GB on top of the gVisor
# processes, past the pod's 54 GiB.
say "--- pressure: every sandbox fills 48 MB of /dev/shm"
forward
api /v1/sandboxes | jq -r '.[].id' > "$sd/ids.txt"
# One small script per sandbox: macOS xargs -I caps a replaced argument at
# 255 bytes, and a command with the token inside is longer, so xargs ran
# nothing on the first S3 run.
cat > "$sd/fill-one.sh" <<EOF
#!/bin/sh
curl -fsS --max-time 120 -o /dev/null -H 'Authorization: Bearer $token' -H 'Content-Type: application/json' \\
  -d '{"command":"dd if=/dev/zero of=/dev/shm/fill bs=1M count=48 2>/dev/null; echo done"}' \\
  "http://127.0.0.1:21212/v1/sandboxes/\$1/toolbox/process/execute" && echo ok || echo fail
EOF
xargs -P 40 -n 1 sh "$sd/fill-one.sh" < "$sd/ids.txt" > "$sd/fill.txt" 2>/dev/null || true
say "fill: $(grep -c '^ok' "$sd/fill.txt" || true) ok, $(grep -c '^fail' "$sd/fill.txt" || true) failed"
sleep 60
say "worker pod: phase $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.phase}') reason '$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.reason}')' restarts $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{range .status.containerStatuses[*]}{.name}={.restartCount} {end}') state $(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].state}' | cut -c1-120)"
say "node MemoryPressure: $(kubectl get node "$node" -o jsonpath='{.status.conditions[?(@.type=="MemoryPressure")].status}')"
say "--- events in the worker namespace"
kubectl -n "$NS" get events --sort-by=.lastTimestamp 2>/dev/null | grep -iE 'evict|oom|kill|memory' | tail -8 | cut -c1-200 | tee -a "$report" >/dev/null || true
say "--- the kernel's OOM events and victims on the machine"
node_debug "chroot /host journalctl -k --since '-40 min' --no-pager > /tmp/k.txt 2>/dev/null; echo oom-events: \$(grep -c 'oom-kill:constraint' /tmp/k.txt); grep -o 'oom_memcg=[^,]*' /tmp/k.txt | sed 's#.*kubepods-pod[^/]*##' | sort | uniq -c | sort -rn | head -4; echo victims:; grep -o 'Killed process [0-9]* ([^)]*)' /tmp/k.txt | sed 's/Killed process [0-9]* //' | sort | uniq -c | sort -rn | head -8"
forward
sleep 60
forward
if alive="$(count_sandboxes 2>/dev/null)"; then
  say "sandboxd still answers; sandboxes listed: $alive"
  t0=$(ms)
  id="$(api /v1/sandboxes -X POST -d '{"image":"alpine:3.20","runtime":"gvisor","cpu":0.1,"memory_mb":64}' 2>/dev/null | jq -r '.id // empty')"
  say "a new create after the pressure: $([[ -n "$id" ]] && echo "ok in $(( $(ms) - t0 )) ms" || echo failed)"
else
  say "sandboxd does not answer"
fi
say "--- memory of the groups after the pressure"
# memory.events counts this group and everything under it; .local counts
# only the group's own limit. The container's own "max" events say whether
# the pod's limit was hit, which is what the cap on sandboxes/ must prevent.
node_debug "for d in /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/cri-containerd-*.scope /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/cri-containerd-*.scope/sandboxes /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/cri-containerd-*.scope/sandboxes/_runtime /sys/fs/cgroup/kubepods.slice/kubepods-pod${uid}.slice/cri-containerd-*.scope/supervisor; do [ -f \$d/memory.events ] && echo \${d##*/} memory.current=\$(cat \$d/memory.current) memory.max=\$(cat \$d/memory.max) events: \$(tr '\\n' ' ' < \$d/memory.events) local: \$(tr '\\n' ' ' < \$d/memory.events.local); done"
measure "after pressure"
say "--- done; report in $report"

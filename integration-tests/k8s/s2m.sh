#!/usr/bin/env bash
# s2m.sh: S2's external-mount check (eng review OV-E2). Does I/O on a
# sandbox's external mount keep going when the agent is upgraded in place?
#
#   cluster.sh up <name>
#   s2m.sh <name>         # writes .state/<name>/s2m-report.txt
#   cluster.sh down <name>
#
# The split worker pod (S2), with rclone in it. A gVisor sandbox gets an
# rclone mount at /mnt/ext. rclone's "local" backend stands in for a remote
# store: it keeps the files in /var/lib/sandboxd/remote, a folder both
# containers share, so they outlive the agent. (Raw mounts are for the
# operator's token only; that is what the harness uses.)
#
# 1. Does the mount reach the sandbox at all? sandboxd (agent container)
#    runs rclone and mounts under /var/lib/sandboxd/mounts; runsc, which
#    gives the sandbox its files, runs in the runtime container.
# 2. A loop in the sandbox appends a line to /mnt/ext/log every 0.2 s. The
#    agent's image changes in place (as in S2). Does the loop keep writing,
#    and do its lines keep reaching the store?
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

name="${1:?usage: s2m.sh <name>}"
NEW_AGENT_IMAGE=public.ecr.aws/amazonlinux/amazonlinux:latest
lib_init "$name" s2m-report.txt
publish_build
load_br_netfilter

manifest="$sd/worker-s2m.yaml"
python3 - "$LIB_DIR/manifests/worker-s2.yaml" "$manifest" <<'PY'
import sys
s = open(sys.argv[1]).read()
old = "      envFrom:\n        - secretRef:\n            name: worker-urls\n      volumeMounts:\n        - { name: bin, mountPath: /opt/aerolvm }\n        - { name: boot, mountPath: /boot }\n  containers:"
assert old in s, "fetch container"
s = s.replace(old, old.replace("      envFrom:", "      env:\n        - { name: AEROL_FETCH_RCLONE, value: \"1\" }\n      envFrom:"), 1)
open(sys.argv[2], "w").write(s)
PY
apply_worker "$manifest" 1
wait_ready
wait_api
in_agent() { kubectl -n "$NS" exec "$POD" -c agent -- sh -c "$1"; }
in_runtime() { kubectl -n "$NS" exec "$POD" -c runtime -- sh -c "$1"; }
run_in() { api "/v1/sandboxes/$1/toolbox/process/execute" -X POST -d "$(jq -cn --arg c "$2" '{command: $c}')"; }
restarts() { kubectl -n "$NS" get pod "$POD" -o jsonpath='{range .status.containerStatuses[*]}{.name}={.restartCount} {end}'; }

in_agent "mkdir -p /var/lib/sandboxd/remote && echo from-the-store > /var/lib/sandboxd/remote/seed"
body="$(jq -cn '{image: "alpine:3.20", runtime: "gvisor",
  mounts: [{type: "rclone", source: "store:/var/lib/sandboxd/remote", target: "/mnt/ext",
            credentials: {rclone_conf: "[store]\ntype = local\n"}}]}')"
created="$(api /v1/sandboxes -X POST -d "$body" 2>&1 || true)"
id="$(jq -r '.id // empty' <<<"$created" 2>/dev/null || true)"
if [[ -z "$id" ]]; then
  say "create with an rclone mount FAILED: $(echo "$created" | tail -1 | cut -c1-300)"
  say "agent log: $(kubectl -n "$NS" logs "$POD" -c agent --tail=200 | grep -iE 'mount|rclone|fuse' | tail -5 | tr '\n' ';' | cut -c1-600)"
  exit 1
fi
say "sandbox $id created with an rclone mount at /mnt/ext"

say "--- 1. does the mount reach the sandbox?"
say "agent container sees: $(in_agent "grep -c ' fuse.rclone ' /proc/self/mountinfo; grep ' fuse.rclone ' /proc/self/mountinfo | awk '{print \$5}' | head -1")"
say "runtime container sees: $(in_runtime "grep -c ' fuse.rclone ' /proc/self/mountinfo || true")"
say "sandbox reads the store's file: '$(run_in "$id" 'cat /mnt/ext/seed 2>&1' | jq -r '.stdout' | tr -d '\n')'"
run_in "$id" 'echo from-the-sandbox > /mnt/ext/hello' >/dev/null
sleep 2
say "the store sees the sandbox's file: '$(in_agent 'cat /var/lib/sandboxd/remote/hello 2>&1' | tr -d '\n')'"

say "--- 2. a writer in the sandbox, then the agent swap"
run_in "$id" 'setsid sh -c "i=0; while true; do i=\$((i+1)); echo \$i >> /mnt/ext/log 2>>/tmp/writer.err; sleep 0.2; done" </dev/null >/dev/null 2>&1 &' >/dev/null
sleep 5
# Both print "none" rather than fail: a missing log is a result here, and
# set -e would end the run on it (second OV-E2 run).
lines_in() { run_in "$id" 'wc -l < /mnt/ext/log 2>/dev/null || echo none' | jq -r '.stdout' | tr -d '[:space:]'; }
lines_store() { in_agent 'wc -l < /var/lib/sandboxd/remote/log 2>/dev/null || echo none' | tr -d '[:space:]'; }
say "before the swap: lines seen in the sandbox $(lines_in), in the store $(lines_store); restarts: $(restarts)"

t_swap=$(ms)
idx="$(kubectl -n "$NS" get pod "$POD" -o json | jq '.spec.containers | map(.name) | index("agent")')"
kubectl -n "$NS" patch pod "$POD" --type=json \
  -p "[{\"op\":\"replace\",\"path\":\"/spec/containers/${idx}/image\",\"value\":\"${NEW_AGENT_IMAGE}\"}]" >/dev/null
back=0
for _ in $(seq 1 240); do
  rc="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')"
  if [[ "${rc:-0}" -ge 1 ]]; then
    forward
    if api /v1/sandboxes >/dev/null 2>&1; then back=1; break; fi
  fi
  sleep 1
done
[[ "$back" == 1 ]] || { say "OV-E2: the new agent never answered"; exit 1; }
say "agent back $(( $(ms) - t_swap )) ms after the image change; restarts: $(restarts)"

a1="$(lines_in)"; s1="$(lines_store)"
sleep 10
a2="$(lines_in)"; s2="$(lines_store)"
say "after the swap: lines seen in the sandbox $a1 then $a2 ten seconds later; in the store $s1 then $s2"
say "the writer's errors: '$(run_in "$id" 'tail -2 /tmp/writer.err 2>/dev/null' | jq -r '.stdout' | tr '\n' ';')'"
say "reading the mount now: '$(run_in "$id" 'ls /mnt/ext 2>&1 | head -3' | jq -r '.stdout' | tr '\n' ' ')'"
# No pgrep in the runtime container's image; count by /proc.
say "the new agent's FUSE mounts: $(in_agent "grep -c ' fuse.rclone ' /proc/self/mountinfo || true"); sandboxd's view: $(api "/v1/sandboxes/$id" | jq -c '{status, mounts: [.mounts[]? | .target]}')"
say "rclone processes now: agent $(in_agent 'grep -lx rclone /proc/[0-9]*/comm 2>/dev/null | wc -l'), runtime $(in_runtime 'grep -lx rclone /proc/[0-9]*/comm 2>/dev/null | wc -l')"
verdict=PASS
[[ "$a2" =~ ^[0-9]+$ && "$a1" =~ ^[0-9]+$ && "$a2" -gt "$a1" ]] || verdict=FAIL
[[ "$s2" =~ ^[0-9]+$ && "$s1" =~ ^[0-9]+$ && "$s2" -gt "$s1" ]] || verdict=FAIL
say "OV-E2 verdict: $verdict (the writer must keep adding lines that reach the store across the swap)"
say "--- done; report in $report"

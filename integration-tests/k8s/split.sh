#!/usr/bin/env bash
# split.sh: privilege mode split on a local kind cluster
# (plans/security-gaps-m1-m4.md M1 PR 11, regression contract D10). Run it
# after single mode came up in split:
#
#   AEROL_KIND_CLUSTER=<name> AEROL_K8S_PRIVILEGE_MODE=split HELM=<helm 3.8+> scripts/k8s-dev.sh
#   AEROL_KIND_CLUSTER=<name> integration-tests/k8s/split.sh [step...]
#
# Steps (all by default), each printing PASS or FAIL lines; the script exits
# 1 if any failed:
#   shape     the agent runs as uid 65531 with no capabilities and a read-only
#             root, has no containerd root, socket or /run/netns, and reaches
#             the helper's socket; the pod has no two-way mount and no shared
#             process namespace; the runtime container runs the signed helper
#   sandboxes a runc and a gVisor sandbox: create, exec, a file copied in and
#             out, the worker's ports and the Kubernetes API refused (C24)
#   egress    no network (--block-network) and an allow list (--allow-host)
#   hostport  a raw TCP port (expose --tcp) answers from another pod
#   mount     an rclone mount of a MinIO bucket (../minio-store.sh) reaches
#             the store from a gVisor sandbox
#   restarts  an agent restart, then a root helper restart: every sandbox
#             (and the mount's writes) keep going, and new creates work
#   verify    aerolvm k8s verify passes and reports the worker in split
#   f8        deleting the pod with sandboxes running finishes, and leaves
#             no namespace or mount behind on the machine
#
# It refuses any kubectl context but a local kind cluster's. No -e: each
# check records its result and the run goes on to the next.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cluster="${AEROL_KIND_CLUSTER:-aerolvm}"
namespace="${AEROL_NAMESPACE:-aerolvm}"
port="${AEROL_SPLIT_PORT:-21296}"
pod=aerolvm-0
if ! kind get clusters 2>/dev/null | grep -qx "$cluster"; then
  echo "split.sh: no kind cluster named $cluster; it runs only on a local kind cluster" >&2
  exit 2
fi
k() { kubectl --context "kind-$cluster" -n "$namespace" "$@"; }
node="$(k get pod "$pod" -o jsonpath='{.spec.nodeName}')"
steps=("$@")
[[ ${#steps[@]} -eq 0 ]] && steps=(shape sandboxes egress hostport mount restarts verify f8)

failed=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; failed=1; }
check() { local what="$1"; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }

tmp="$(mktemp -d)"
pf=""
trap '[[ -n "$pf" ]] && kill "$pf" 2>/dev/null; true' EXIT
(cd "$ROOT" && go build -o "$tmp/aerolvm" ./cmd/aerolvm) || exit 1
cli() { "$tmp/aerolvm" "$@"; }
forward() {
  for _ in $(seq 1 60); do
    if [[ -z "$pf" ]] || ! kill -0 "$pf" 2>/dev/null; then
      k port-forward "pod/$pod" "$port:21212" >/dev/null 2>&1 & pf=$!
      sleep 1
    fi
    cli health >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
export SB_API_URL="http://127.0.0.1:$port"
SB_PAT_TOKEN="$(k get secret aerolvm-api-token -o jsonpath='{.data.SB_PAT_TOKEN}' | base64 -d)" || exit 1
export SB_PAT_TOKEN
forward || { echo "split.sh: the API never answered" >&2; exit 1; }
api() { curl -sS -m 300 -H "Authorization: Bearer $SB_PAT_TOKEN" -H 'Content-Type: application/json' "$@"; }
agent() { k exec "$pod" -c agent -- "$@"; }
runtime() { k exec "$pod" -c runtime -- "$@"; }
# The root helper's pid in the runtime container: the process whose program
# is a verified copy in the supervisor's folder.
helper_pid() {
  runtime sh -c 'for d in /proc/[0-9]*; do case "$(readlink "$d/exe" 2>/dev/null)" in /var/lib/aerolvm-supervisor/rootd/aerolvm-rootd-*) basename "$d";; esac; done' | head -1
}
mk() {
  local out
  out="$(cli create --image alpine:3.20 --json "$@" 2>&1)"
  [[ "$out" == *'"id"'* ]] || echo "  create $*: $(head -c 300 <<<"$out")" >&2
  jq -r '.id // empty' <<<"$out" 2>/dev/null
}
ok_exec() { [[ "$(cli exec "$1" -- sh -c 'echo ok' 2>/dev/null)" == ok ]]; }
created=()

step_shape() {
  local sc
  sc="$(k get pod "$pod" -o jsonpath='{.spec.containers[?(@.name=="agent")].securityContext}')"
  check "shape: SB_PRIVILEGE_MODE=split on the agent" test "$(k get pod "$pod" -o jsonpath='{.spec.containers[?(@.name=="agent")].env[?(@.name=="SB_PRIVILEGE_MODE")].value}')" = split
  check "shape: agent securityContext has no privilege ($sc)" bash -c '[[ "$1" != *privileged\":true* && "$1" == *\"runAsUser\":65531* && "$1" == *\"readOnlyRootFilesystem\":true* && "$1" == *RuntimeDefault* ]]' _ "$sc"
  check "shape: the agent runs as uid 65531" test "$(agent id -u)" = 65531
  check "shape: the agent holds no capability" test "$(agent sh -c 'sed -n "s/^CapEff:[[:space:]]*//p" /proc/self/status')" = 0000000000000000
  check "shape: the agent cannot write its root disk" bash -c '! kubectl --context "kind-$1" -n "$2" exec "$3" -c agent -- touch /root-write-test 2>/dev/null' _ "$cluster" "$namespace" "$pod"
  check "shape: no containerd root, socket or /run/netns in the agent" agent sh -c '! test -e /var/lib/containerd && ! test -e /run/containerd/containerd.sock && ! test -e /run/netns'
  check "shape: the agent reaches the helper's socket" agent test -S /run/aerolvm-rootd/shared/sock/root.sock
  check "shape: no two-way mount, no shared process namespace" bash -c '! kubectl --context "kind-$1" -n "$2" get pod "$3" -o json | grep -q -e Bidirectional -e "\"shareProcessNamespace\": true"' _ "$cluster" "$namespace" "$pod"
  local hp
  hp="$(helper_pid)"
  check "shape: the runtime container runs the verified helper (pid ${hp:-none})" test -n "$hp"
}

step_sandboxes() {
  local rt id out
  for rt in docker gvisor; do
    id="$(mk --runtime "$rt")"
    if [[ -z "$id" ]]; then fail "sandboxes: $rt create"; continue; fi
    created+=("$id")
    out="$(cli exec "$id" -- sh -c 'echo hello-$(id -u)')"
    check "sandboxes: $rt exec ($out)" test "$out" = hello-0
    printf 'split-%s\n' "$rt" > "$tmp/in.txt"
    cli cp "$tmp/in.txt" "$id:/tmp/in.txt" >/dev/null
    cli exec "$id" -- sh -c 'cp /tmp/in.txt /tmp/out.txt' >/dev/null
    cli cp "$id:/tmp/out.txt" "$tmp/out-$rt.txt" >/dev/null
    check "sandboxes: $rt file in and out" test "$(cat "$tmp/out-$rt.txt")" = "split-$rt"
    local pod_ip kube_api open
    pod_ip="$(k get pod "$pod" -o jsonpath='{.status.podIP}')"
    kube_api="$(kubectl --context "kind-$cluster" get svc kubernetes -o jsonpath='{.spec.clusterIP}')"
    open="$(cli exec "$id" -- sh -c "for t in 10.88.0.1:21212 10.88.0.1:2220 $pod_ip:21212 $pod_ip:2220 $kube_api:443; do nc -z -w 3 \${t%:*} \${t#*:} 2>/dev/null && echo \$t; done; true")"
    check "sandboxes: $rt cannot reach the worker's ports or the Kubernetes API (C24)${open:+: reached $open}" test -z "$open"
  done
}

step_egress() {
  local id
  id="$(mk --block-network)"
  created+=("$id")
  check "egress: --block-network reaches nothing" bash -c '[[ -n "$1" ]] && ! "$2" exec "$1" -- nc -z -w 3 1.1.1.1 443' _ "$id" "$tmp/aerolvm"
  id="$(mk --allow-host 1.1.1.1/32)"
  created+=("$id")
  check "egress: an allow list opens 1.1.1.1" cli exec "$id" -- nc -z -w 5 1.1.1.1 443
  check "egress: and refuses 1.0.0.1" bash -c '[[ -n "$1" ]] && ! "$2" exec "$1" -- nc -z -w 3 1.0.0.1 443' _ "$id" "$tmp/aerolvm"
  # A hostname allow list goes through the egress gateway, whose control
  # socket a split agent must reach.
  id="$(mk --allow-host example.com)"
  created+=("$id")
  check "egress: a hostname allow list (through the egress gateway) opens example.com" cli exec "$id" -- wget -q -T 10 -O /dev/null http://example.com/
  check "egress: and refuses another host" bash -c '[[ -n "$1" ]] && ! "$2" exec "$1" -- wget -q -T 5 -O /dev/null http://1.0.0.1/' _ "$id" "$tmp/aerolvm"
}

step_hostport() {
  local id hp pod_ip got
  # A raw TCP port is served by the edge's Caddy (layer 4), in single and
  # split alike; with no edge nothing listens on it.
  if ! k get svc aerolvm-edge >/dev/null 2>&1; then
    echo "SKIP hostport: no edge (AEROL_K8S_EDGE=1); raw TCP ports are the edge's"
    return
  fi
  id="$(mk --runtime gvisor)"
  created+=("$id")
  cli exec "$id" --background -- sh -c 'while true; do echo split-tcp | nc -l -p 9000; done' >/dev/null 2>&1
  hp="$(cli expose "$id" 9000 --tcp --json | jq -r '.host_port // empty')"
  pod_ip="$(k get pod "$pod" -o jsonpath='{.status.podIP}')"
  got=""
  for _ in $(seq 1 10); do
    got="$(k run "split-tcp-$RANDOM" --rm -i --restart=Never --image=busybox:1.36 --quiet -- nc -w 5 "$pod_ip" "$hp" 2>/dev/null | head -1)" && [[ "$got" == split-tcp ]] && break
    sleep 2
  done
  check "hostport: $pod_ip:${hp:-?} answers from another pod ($got)" test "$got" = split-tcp
}

store_lines() { minio_mc ls "store/$MINIO_BUCKET/" 2>/dev/null | grep -c ' log-' || true; }
mount_id=""
step_mount() {
  # shellcheck source=minio-store.sh
  . "$HERE/minio-store.sh"
  minio_store_up kubectl --context "kind-$cluster" -n "$namespace" || { fail "mount: MinIO did not start"; return; }
  # The worker's NetworkPolicy shuts private addresses, MinIO's among them.
  "${HELM:-helm}" --kube-context "kind-$cluster" upgrade aerolvm "$ROOT/charts/aerolvm" -n "$namespace" --reuse-values \
    --set "networkPolicy.extraEgressCIDRs={$MINIO_IP/32}" >/dev/null
  echo seed-ok | minio_mc pipe "store/$MINIO_BUCKET/seed.txt" >/dev/null
  local body out
  body="$(jq -nc --arg src "store:$MINIO_BUCKET" --arg conf "$MINIO_RCLONE_CONF" \
    '{runtime:"gvisor", image:"alpine:3.20", mounts:[{type:"rclone", source:$src, target:"/mnt/ext", credentials:{rclone_conf:$conf}}]}')"
  out="$(api -X POST "$SB_API_URL/v1/sandboxes" -d "$body")"
  mount_id="$(jq -r '.id // empty' <<<"$out")"
  if [[ -z "$mount_id" ]]; then fail "mount: create refused: $(head -c 300 <<<"$out")"; return; fi
  created+=("$mount_id")
  check "mount: the sandbox reads the store" test "$(cli exec "$mount_id" -- cat /mnt/ext/seed.txt)" = seed-ok
  cli exec "$mount_id" -- sh -c 'setsid nohup sh -c "i=0; while true; do i=\$((i+1)); echo \$i > /mnt/ext/log-\$i; sleep 1; done" </dev/null >/dev/null 2>&1 &' >/dev/null
  sleep 20
  local n
  n="$(store_lines)"
  check "mount: the sandbox's writes reach the store ($n files)" test "${n:-0}" -ge 5
  # rclone as the mount tools' own user (aerolvm-mounts, 65530) in the
  # runtime container; the agent, in a process namespace of its own, sees
  # none.
  local tools agent_tools
  tools="$(runtime sh -c 'for d in /proc/[0-9]*; do case "$(tr "\0" " " < "$d/cmdline" 2>/dev/null)" in rclone\ *) awk "/^Uid:/{print \$2}" "$d/status";; esac; done' | sort -u | tr '\n' ' ')"
  agent_tools="$(agent sh -c 'for d in /proc/[0-9]*; do case "$(tr "\0" " " < "$d/cmdline" 2>/dev/null)" in rclone\ *) echo x;; esac; done' | wc -l | tr -d ' ')"
  check "mount: rclone runs in the runtime container as uid 65530 (uids: ${tools:-none}), none in the agent ($agent_tools)" \
    bash -c '[[ "$1" == "65530 " && "$2" == 0 ]]' _ "$tools" "$agent_tools"
}

# restart waits for a container's restart count to grow and it to be ready.
wait_restarted() {
  local name="$1" before="$2" n r
  for _ in $(seq 1 90); do
    n="$(k get pod "$pod" -o jsonpath="{.status.containerStatuses[?(@.name==\"$name\")].restartCount}")"
    r="$(k get pod "$pod" -o jsonpath="{.status.containerStatuses[?(@.name==\"$name\")].ready}")"
    [[ "${n:-0}" -gt "$before" && "$r" == true ]] && return 0
    sleep 2
  done
  return 1
}
all_exec() {
  local id
  for id in "${created[@]}"; do
    [[ -n "$id" ]] || continue
    # The --block-network sandbox needs no network for this.
    ok_exec "$id" || { echo "  exec failed in $id"; return 1; }
  done
}
step_restarts() {
  [[ ${#created[@]} -gt 0 ]] || step_sandboxes
  local before cid s1 s2 hp1 hp2 id
  before="$(k get pod "$pod" -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')"
  cid="$(k get pod "$pod" -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].containerID}')"
  [[ -n "$mount_id" ]] && s1="$(store_lines)"
  docker exec "$node" crictl --timeout 60s stop --timeout 30 "${cid#containerd://}" >/dev/null
  check "restarts: the agent came back" wait_restarted agent "$before"
  forward
  check "restarts: every sandbox answers after the agent restart" all_exec
  id="$(mk)"
  created+=("$id")
  check "restarts: a new create works after the agent restart" test -n "$id"
  hp1="$(helper_pid)"
  runtime kill "$hp1"
  hp2=""
  for _ in $(seq 1 60); do
    hp2="$(helper_pid)"
    [[ -n "$hp2" && "$hp2" != "$hp1" ]] && break
    sleep 1
  done
  check "restarts: the supervisor started the helper again ($hp1 -> ${hp2:-none})" bash -c '[[ -n "$1" && "$1" != "$2" ]]' _ "$hp2" "$hp1"
  check "restarts: every sandbox answers after the helper restart" all_exec
  id="$(mk --runtime gvisor)"
  created+=("$id")
  check "restarts: a new create works after the helper restart" test -n "$id"
  if [[ -n "$mount_id" ]]; then
    sleep 15
    s2="$(store_lines)"
    check "restarts: the mount kept writing across both restarts ($s1 -> $s2 files)" test "${s2:-0}" -gt "${s1:-0}"
  fi
}

step_verify() {
  local out
  out="$(cli k8s verify --kube-context "kind-$cluster" --namespace "$namespace" --skip-signatures 2>&1)" && pass "verify: aerolvm k8s verify passes" || { fail "verify: aerolvm k8s verify"; echo "$out"; }
  check "verify: it reports the worker in split" grep -q "privilege mode.*split 1" <<<"$out"
  check "verify: it allows the agent's read-only cgroup view" grep -q "/sys/fs/cgroup read only in the agent of $pod" <<<"$out"
}

step_f8() {
  local start
  [[ -n "$pf" ]] && kill "$pf" 2>/dev/null
  pf=""
  start=$(date +%s)
  check "f8: the worker pod went away with sandboxes running" k delete pod "$pod" --wait=true --timeout=120s
  echo "  in $(( $(date +%s) - start )) s"
  # The kubelet's own pod namespaces are /run/netns/cni-*; any other there,
  # or anything of the helper's, would be one of ours left behind.
  check "f8: no sandbox namespace or mount left on the machine" bash -c \
    '! docker exec "$1" grep -e aerolvm-rootd -e /run/netns/ /proc/self/mountinfo | grep -qv /run/netns/cni-' _ "$node"
}

for s in "${steps[@]}"; do
  "step_$s"
done
[[ "$failed" == 0 ]] && echo "split.sh: every check passed" || echo "split.sh: some checks failed"
exit "$failed"

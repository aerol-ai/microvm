# m1-lib.sh: helpers for m1-eks.sh (the M1 EKS drill). Source it; it needs
# name, sd, dry, sha and K8S (integration-tests/k8s) set first.
# shellcheck shell=bash
#
# Every call that reaches AWS or the cluster goes through x (or k, hm), so a
# dry run (DRY_RUN=1) prints it and runs nothing. kr is a kubectl read whose
# answer the script uses: empty in a dry run. Every kubectl and Helm call
# names the run's own kubeconfig ($sd/kubeconfig, written by cluster.sh);
# KUBECONFIG and ~/.kube/config are never read or changed.

HELM="${HELM:-helm}"
ns=aerolvm-system
workers=aerolvm-workers
cname=aerolvm
release=aerolvm
gw_lport="${M1_GW_PORT:-21410}"
DEBUG_IMAGE=public.ecr.aws/amazonlinux/amazonlinux:2023
ALPINE=public.ecr.aws/docker/library/alpine:3.20
# Not the warm pool's image: a gVisor sandbox that must move with its memory
# must not come from the pool, which moves only by recreate (its spec
# carries the pool's park socket; live run m1d-2).
BUSYBOX=public.ecr.aws/docker/library/busybox:1.36

say() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$sd/m1.log" >&2; }
# result PASS|FAIL|SKIP|INFO <item> <detail>: one line in $sd/m1.txt.
result() {
  if [[ "$dry" == 1 ]]; then echo "dry-run: (a result line for $2; no verdict in a dry run)" >&2; return 0; fi
  echo "$1 $2 $3" | tee -a "$sd/m1.txt" "$sd/m1.log"
}
now() { date +%s; }

x() {
  if [[ "$dry" == 1 ]]; then
    printf 'dry-run:' >&2; printf ' %q' "$@" >&2; printf '\n' >&2
    # A manifest on stdin (-f -) is shown too.
    local a
    for a in "$@"; do
      if [[ "$a" == - && ! -t 0 ]]; then sed 's/^/dry-run:   | /' >&2; break; fi
    done
    return 0
  fi
  "$@"
}
k() { x kubectl --kubeconfig "$sd/kubeconfig" "$@"; }
hm() { x "$HELM" --kubeconfig "$sd/kubeconfig" "$@"; }
kr() { [[ "$dry" == 1 ]] && return 0; kubectl --kubeconfig "$sd/kubeconfig" "$@"; }

tfout() {
  if [[ "$dry" == 1 ]]; then
    case "$1" in
      zones) echo '["us-east-1a","us-east-1b"]' ;;
      region) echo us-east-1 ;;
      ecr_registry) echo "111122223333.dkr.ecr.us-east-1.amazonaws.com/$name" ;;
      *) echo "dry-$1" ;;
    esac
    return 0
  fi
  TF_DATA_DIR="$sd/.terraform" terraform -chdir="$K8S/terraform" output -state="$sd/terraform.tfstate" -json "$1" |
    jq -r 'if type == "string" then . else tojson end'
}

# gate: every step after up talks only to the cluster cluster.sh made for
# $name, with this machine's AWS credentials in that cluster's account. A
# refusal changes nothing (eks-bank.sh's gate, without the bank flag).
# A refusal tears nothing down unless this process made the cluster
# (on_exit reads refused and made_here): it may be the wrong credentials
# or another cluster's kubeconfig. gated says a gate passed in this run.
refused=0
gated=0
refuse() { echo "m1-eks.sh: refusing to run: $*" >&2; refused=1; exit 2; }
# caller_account: this machine's AWS account, or "" when STS does not
# answer. Asked up to three times: one STS blip right after up must not
# read as other credentials.
caller_account() {
  local a="" try
  for try in 1 2 3; do
    a="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
    [[ "$a" =~ ^[0-9]{12}$ ]] && { echo "$a"; return 0; }
    [[ "$try" == 3 ]] || sleep 2
  done
  echo ""
}
# ctx_ok: the run's kubeconfig names the run's own EKS cluster.
ctx_ok() {
  local ctx
  [[ -f "$sd/kubeconfig" ]] || return 1
  ctx="$(KUBECONFIG="$sd/kubeconfig" kubectl config current-context 2>/dev/null || true)"
  [[ "$ctx" =~ ^arn:aws:eks:us-east-1:[0-9]{12}:cluster/${name}$ ]]
}
gate() {
  [[ "$dry" == 1 ]] && return 0
  [[ -f "$sd/kubeconfig" && -f "$sd/run.tfvars.json" ]] || refuse "no cluster.sh state for $name in $sd"
  [[ "$(jq -r .name "$sd/run.tfvars.json")" == "$name" ]] || refuse "$sd/run.tfvars.json is not $name's"
  local ctx acct
  ctx="$(KUBECONFIG="$sd/kubeconfig" kubectl config current-context 2>/dev/null || true)"
  [[ "$ctx" =~ ^arn:aws:eks:us-east-1:[0-9]{12}:cluster/${name}$ ]] || refuse "the run's kubeconfig names context \"$ctx\", not EKS cluster $name"
  acct="$(caller_account)"
  [[ -n "$acct" ]] || refuse "STS did not answer three times: this machine's AWS account is unknown"
  [[ "$(cut -d: -f5 <<<"$ctx")" == "$acct" ]] || refuse "this machine's AWS credentials are not the cluster's account"
  gated=1
}
same_account() {
  [[ "$dry" == 1 ]] && return 0
  local want got
  want="$(jq -r '.aws_account // ""' "$sd/run.tfvars.json" 2>/dev/null || true)"
  [[ -n "$want" ]] || return 0
  got="$(caller_account)"
  [[ "$got" == "$want" ]] || refuse "this machine's AWS credentials (\"$got\") are not the account $name was made in"
}

# wait_until <seconds> <what> <cmd...>: polls every 5 s. A dry run waits not.
wait_until() {
  local limit="$1" what="$2" end
  shift 2
  [[ "$dry" == 1 ]] && { echo "dry-run: (wait up to ${limit}s) $what" >&2; return 0; }
  end=$(( $(now) + limit ))
  while (( $(now) < end )); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 5
  done
  say "timed out after ${limit}s: $what"
  return 1
}

# --- the API, through one gateway port-forward ----------------------------------
# One keeper, started once from the main shell (gw_keeper_start), owns the
# forward for the whole run and starts it again when kubectl quits. Every
# check step runs in a subshell, and api() is often called inside $(...):
# a forward started there outlived its subshell and held the port, so the
# next step's api() refused to start one ("no port-forward"; live run m1d-1,
# 2026-11-24). Callers now only wait for the port to answer.
gwkeeper=""
gw_keeper_start() {
  [[ "$dry" == 1 ]] && { echo "dry-run: gateway port-forward keeper on 127.0.0.1:$gw_lport" >&2; return 0; }
  [[ -n "$gwkeeper" ]] && kill -0 "$gwkeeper" 2>/dev/null && return 0
  (
    trap '[[ -s "$sd/gw-kubectl.pid" ]] && kill "$(cat "$sd/gw-kubectl.pid")" 2>/dev/null; exit 0' TERM
    while :; do
      command kubectl --kubeconfig "$sd/kubeconfig" -n "$ns" port-forward svc/aerolvm-gateway "$gw_lport:21212" >/dev/null 2>&1 &
      echo $! > "$sd/gw-kubectl.pid"
      # m1-eks.sh runs with errexit, and this subshell inherits it: a bare
      # `wait` on kubectl's exit status 1 (a lost stream) ended the keeper
      # instead of starting a new forward (live run m1d-2, switch3).
      wait $! || true
      sleep 1
    done
  ) &
  gwkeeper=$!
  echo "$gwkeeper" > "$sd/gw-keeper.pid"
}
# pid_runs <pid> <text>: that process is alive and its command line holds
# text.
pid_runs() {
  [[ "$1" =~ ^[0-9]+$ && "$1" != "$$" ]] || return 1
  local c
  c="$(ps -o command= -p "$1" 2>/dev/null || true)"
  [[ -n "$c" && "$c" == *"$2"* ]]
}
gw_keeper_stop() {
  local k f
  k="$(cat "$sd/gw-keeper.pid" 2>/dev/null || true)"
  f="$(cat "$sd/gw-kubectl.pid" 2>/dev/null || true)"
  # A keeper already gone makes kill fail; under errexit that failure (the
  # last command of an && list) ended step_down and on_exit before the
  # teardown (live run m1d-2). A pid is signalled only while it is still
  # what this run wrote down: the keeper (a subshell of this script, so its
  # command line is this run's m1-eks.sh <name> ...) or kubectl
  # port-forward on this run's port with this run's kubeconfig. A pid the
  # system has given to another process since is left alone. The files are
  # emptied once read.
  if [[ -n "$k" ]] && pid_runs "$k" "m1-eks.sh $name "; then kill "$k" 2>/dev/null || true; fi
  if [[ -n "$f" ]] && pid_runs "$f" "port-forward svc/aerolvm-gateway $gw_lport:21212" && pid_runs "$f" "$sd/kubeconfig"; then
    kill "$f" 2>/dev/null || true
  fi
  : > "$sd/gw-keeper.pid" 2>/dev/null || true
  : > "$sd/gw-kubectl.pid" 2>/dev/null || true
  gwkeeper=""
  return 0
}
gw_up() { # the keeper's forward answers (up to 30 s)
  [[ "$dry" == 1 ]] && return 0
  local _
  for _ in $(seq 1 30); do
    curl -s -o /dev/null -m 2 "http://127.0.0.1:$gw_lport/health" && return 0
    sleep 1
  done
  return 1
}
gw_down() { :; }
# token_file: the admin token's file (0600), read once from the cluster.
# The token itself never goes on a command line: curl reads its header
# from auth_header (0600) and the bench pod's Secret is made from the file.
token_file() {
  if [[ ! -s "$sd/admin-token" && "$dry" != 1 ]]; then
    ( umask 077; kr -n "$ns" get secret "$cname-admin" -o jsonpath='{.data.token}' | base64 -d | tr -d '\n' > "$sd/admin-token" )
  fi
  echo "$sd/admin-token"
}
auth_header() {
  local f="$sd/admin-auth-header"
  if [[ ! -s "$f" ]]; then
    ( umask 077; printf 'Authorization: Bearer %s\n' "$(cat "$(token_file)")" > "$f" )
  fi
  echo "$f"
}
# api <method> <path> [json]: prints the HTTP code, then the body. A broken
# forward (a gateway's agent restarts in the rollout) is made again once.
api() {
  if [[ "$dry" == 1 ]]; then echo "dry-run: API $1 $2 ${3:-}" >&2; echo 200; echo '{}'; return 0; fi
  local out try
  for try in 1 2; do
    gw_up || { echo 000; echo '{"error":"no port-forward"}'; return 0; }
    out="$(curl -sS -m 300 -w '\n%{http_code}' -X "$1" -H "@$(auth_header)" \
      -H 'Content-Type: application/json' ${3:+-d "$3"} "http://127.0.0.1:$gw_lport$2" 2>/dev/null || true)"
    [[ "$(tail -1 <<<"$out")" != 000 ]] && break
    gw_down
  done
  tail -1 <<<"$out"; sed '$d' <<<"$out"
}
code_of() { head -1 <<<"$1"; }
body_of() { sed 1d <<<"$1"; }

# create <json>: the new sandbox's id, or nothing (the answer goes to the
# evidence log either way).
create() {
  local out id
  out="$(api POST /v1/sandboxes "$1")"
  echo "$(date -u +%T) create $1 -> $(code_of "$out") $(body_of "$out" | head -c 300)" >> "$sd/evidence/creates.log"
  [[ "$dry" == 1 ]] && { echo "dry-sb-$RANDOM"; return 0; }
  id="$(body_of "$out" | jq -r '.id // ""' 2>/dev/null || true)"
  echo "$id"
}
# body <runtime> <image> [placement mode single|split] [extra json fields]
# The mode argument says which worker the caller pinned; it adds nothing to
# the request. Placement never matches the gVisor-moves label (live run
# m1d-2: "placement_unsatisfiable" while every worker reported it), so
# callers pin a worker with AerolVM's cordon on the others (only_on).
body() {
  echo "{\"runtime\":\"$1\",\"image\":\"$2\",\"cpu\":0.25,\"memory_mb\":256${4:+,$4}}"
}
# sh_in <id> <command>: the command's stdout ("" on any failure).
sh_in() {
  local out
  out="$(api POST "/v1/sandboxes/$1/toolbox/process/execute" "$(jq -cn --arg c "$2" '{command: $c}')")"
  [[ "$(code_of "$out")" == 200 ]] || return 1
  body_of "$out" | jq -r '.stdout // ""'
}
answers() { [[ "$(sh_in "$1" 'echo ok' 2>/dev/null | tr -d '\n')" == ok ]]; }
# owner <id>: the worker pod that runs it (the placement record's owner; on
# Kubernetes a node's id is its worker pod's name).
owner() {
  [[ "$dry" == 1 ]] && { echo dry-worker; return 0; }
  body_of "$(api GET "/v1/cluster/placements/$1")" | jq -r '.owner.node_id // ""'
}
# A live counter, kept in the sandbox's memory-backed /dev/shm: a move that
# keeps memory keeps counting; a recreate starts again from 1.
start_counter() { sh_in "$1" 'setsid nohup sh -c "i=0; while :; do i=\$((i+1)); echo \$i > /dev/shm/count; sleep 1; done" </dev/null >/dev/null 2>&1 & echo started' >/dev/null; }
count_of() { sh_in "$1" 'cat /dev/shm/count 2>/dev/null' | tr -d '\n'; }

# --- workers ----------------------------------------------------------------------
worker_pods() {
  [[ "$dry" == 1 ]] && { echo "aerolvm-worker-a aerolvm-worker-b aerolvm-worker-c"; return 0; }
  kr -n "$workers" get pods -l app.kubernetes.io/component=worker -o jsonpath='{.items[*].metadata.name}'
}
machine_of() { [[ "$dry" == 1 ]] && { echo "dry-machine-1"; return 0; }; kr -n "$workers" get pod "$1" -o jsonpath='{.spec.nodeName}'; }
worker_on() { # worker_on <machine>: the worker pod on that machine
  [[ "$dry" == 1 ]] && { echo dry-worker; return 0; }
  kr -n "$workers" get pods -l app.kubernetes.io/component=worker --field-selector "spec.nodeName=$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
}
mode_of() { # split or single, from the agent's SB_PRIVILEGE_MODE
  if [[ "$dry" == 1 ]]; then case "$1" in *-a|dry-worker) echo split ;; *) echo single ;; esac; return 0; fi
  local m
  m="$(kr -n "$workers" get pod "$1" -o jsonpath='{.spec.containers[?(@.name=="agent")].env[?(@.name=="SB_PRIVILEGE_MODE")].value}')"
  echo "${m:-single}"
}
workers_in() { local p; for p in $(worker_pods); do [[ "$(mode_of "$p")" == "$1" ]] && echo "$p"; done; true; }
serving() { [[ "$(kr -n "$ns" get aerolnode "$1" -o jsonpath='{.status.state}' 2>/dev/null)" == Serving ]]; }
restarts() { kr -n "$workers" get pod "$1" -o jsonpath='{range .status.containerStatuses[*]}{.name}={.restartCount} {end}'; }
uid_of() { [[ "$dry" == 1 ]] && { echo 00000000-0000-0000-0000-00000000d0d0; return 0; }; kr -n "$workers" get pod "$1" -o jsonpath='{.metadata.uid}'; }
rt() { k -n "$workers" exec "$1" -c runtime -- "${@:2}"; }
# helper <pod>: "<pid> <program>" of the running root helper: the process
# whose program is a verified copy in the supervisor's folder (split.sh).
helper() {
  [[ "$dry" == 1 ]] && { echo "1234 /var/lib/aerolvm-supervisor/rootd/aerolvm-rootd-dry"; return 0; }
  local out
  out="$(kubectl --kubeconfig "$sd/kubeconfig" -n "$workers" exec "$1" -c runtime -- sh -c \
    'for d in /proc/[0-9]*; do e="$(readlink "$d/exe" 2>/dev/null)"; case "$e" in /var/lib/aerolvm-supervisor/rootd/aerolvm-rootd-*) echo "${d#/proc/} $e";; esac; done' 2>/dev/null || true)"
  head -1 <<<"$out"
}
# AerolVM's own cordon: admission only (placement skips the node, moves
# never target it). The operator never lifts it, so each cordon a check
# places is written down ($sd/check-cordons) until it lifts it, and the
# check's exit handler (m1-eks.sh check_exit) lifts what is left: a check
# that fails or is stopped part way leaves no worker closed.
api_cordon() { api POST "/v1/cluster/nodes/$1/cordon" >/dev/null; echo "$1" >> "$sd/check-cordons"; }
api_uncordon() {
  api POST "/v1/cluster/nodes/$1/uncordon" >/dev/null
  [[ -f "$sd/check-cordons" ]] || return 0
  grep -vxF -- "$1" "$sd/check-cordons" > "$sd/check-cordons.new" || true
  mv "$sd/check-cordons.new" "$sd/check-cordons"
}
lift_cordons() {
  local n
  [[ -s "$sd/check-cordons" ]] || return 0
  for n in $(sort -u "$sd/check-cordons"); do api_uncordon "$n"; done
}

# node_sh <machine> <shell>: runs the shell as root on the machine (a node
# debug pod, chroot /host; AL2023 has a shell) and prints its output.
node_sh() {
  [[ "$dry" == 1 ]] && { echo "dry-run: on machine $1: $2" >&2; return 0; }
  local before after p
  before="$(kr get pods -o name 2>/dev/null | grep node-debugger || true)"
  kubectl --kubeconfig "$sd/kubeconfig" debug "node/$1" --profile=sysadmin --image="$DEBUG_IMAGE" -- chroot /host sh -c "$2" >/dev/null 2>&1 || true
  after=""
  for _ in $(seq 1 60); do
    p="$(kr get pods -o name 2>/dev/null | grep node-debugger | grep -vxF "$before" || true)"
    after="$(head -1 <<<"$p")"
    if [[ -n "$after" ]] && [[ "$(kr get "$after" -o jsonpath='{.status.phase}')" =~ ^(Succeeded|Failed)$ ]]; then break; fi
    sleep 2
  done
  [[ -n "$after" ]] || { echo "(the debug pod did not finish)"; return 0; }
  kr logs "$after" 2>&1 || true
  kubectl --kubeconfig "$sd/kubeconfig" delete "$after" --wait=false >/dev/null 2>&1 || true
}

# verify <label>: aerolvm k8s verify, built from the build commit's tree.
verify() {
  local out="$sd/evidence/verify-$1.txt" rc=0
  [[ "$dry" == 1 ]] && { echo "dry-run: aerolvm k8s verify ($1), --skip-signatures (dev images)" >&2; return 0; }
  [[ -x "$sd/aerolvm" ]] || (cd "$(src_tree)" && go build -o "$sd/aerolvm" ./cmd/aerolvm)
  gw_up || true
  KUBECONFIG="$sd/kubeconfig" SB_API_URL="http://127.0.0.1:$gw_lport" SB_PAT_TOKEN="$(cat "$(token_file)")" "$sd/aerolvm" k8s verify \
    --namespace "$ns" --worker-namespace "$workers" --release "$release" --cluster "$cname" \
    --skip-signatures --probe-runtimes gvisor --probe-image "$ALPINE" > "$out" 2>&1 || rc=$?
  local modes; modes="$(grep -i 'privilege mode' "$out" | sed -n 1,3p | tr '\n' ' ')"
  if [[ "$rc" == 0 ]]; then result PASS "verify-$1" "aerolvm k8s verify passed; $modes"
  else result FAIL "verify-$1" "aerolvm k8s verify exited $rc: $(grep -iE 'fail|error' "$out" | sed -n 1,4p | tr '\n' ' ')"; fi
}
src_tree() { (cd "$K8S" && sd="$sd" bash -c 'source ./lib.sh; source_tree "$0"' "$sha"); }

# diag <label>: what to read when a step fails, saved before anything goes.
diag() {
  [[ "$dry" == 1 ]] && return 0
  [[ -f "$sd/run.tfvars.json" ]] && ctx_ok || { say "diag: not the run's cluster; nothing read"; return 0; }
  local d="$sd/evidence/diag-$1-$(date +%H%M%S)" p c
  mkdir -p "$d"
  kr -n "$ns" get aerolcluster,aerolnodes -o wide > "$d/nodes.txt" 2>&1 || true
  kr get events -A --sort-by=.lastTimestamp > "$d/events.txt" 2>&1 || true
  kr -n "$ns" logs deploy/aerolvm-operator --tail=400 > "$d/operator.txt" 2>&1 || true
  for p in $(worker_pods); do
    for c in agent runtime egress; do
      kr -n "$workers" logs "$p" -c "$c" --tail=300 > "$d/$p-$c.txt" 2>&1 || true
    done
  done
  for p in $(kr -n "$ns" get pods -l app.kubernetes.io/component=server -o jsonpath='{.items[*].metadata.name}'); do
    kr -n "$ns" logs "$p" --all-containers --tail=400 > "$d/$p.txt" 2>&1 || true
  done
  say "diagnostics in $d"
}

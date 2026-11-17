#!/usr/bin/env bash
# drills-eks.sh: the image-pull storm and SLO-breach drills (issue #1343)
# on an EKS cell, and the drills only EKS can run (the bank run, eks-bank.sh):
#
#   drills-eks.sh <name> <state-dir> <step> [step...]
#
# <name> is a cluster cluster.sh made: the script talks only to the
# kubeconfig cluster.sh wrote for it (.state/<name>/kubeconfig), and only if
# that file's context is that EKS cluster (arn:aws:eks:...:cluster/<name>)
# and the run was made with --bank-drills. It never reads KUBECONFIG,
# KUBECTL_CONTEXT or ~/.kube/config: the steps delete pods, fill workers and
# break a gateway's Caddy. drills-local.sh runs the same drills on kind.
#
# Steps (PASS or FAIL lines in <state-dir>/drills.txt; evidence in
# <state-dir>/evidence/<step>/):
#   setup         the drill registry in the cluster (drills-eks/registry.yaml):
#                 registry:2 behind the fault proxy, over HTTPS with a
#                 certificate the run's private CA signed, which the workers
#                 trust through the chart's worker.registryCA; then
#                 drills-lib.sh's setup (Prometheus, Alertmanager and its
#                 receiver, the alert rules, the client pod, a viewer scrape
#                 token, a smoke create)
#   static pull-storm slo-breach
#                 drills-lib.sh's drills, unchanged
#   large-layers  an image with a 3 GiB layer (DRILL_LARGE_GIB), pushed in the
#                 cluster; one create of it per worker at once. Passes when
#                 every create starts within the create timeout, no worker
#                 pod is evicted or restarted, and no worker stops admitting
#   ecr-push      DRILL_ECR_IMAGES (200) images of DRILL_ECR_LAYERS (40)
#                 small layers each, pushed to the run's ECR repository
#                 (DRILL_ECR_REPO) from a pod in the cluster
#   ecr-storm     one create of each of those images at once, with ECR
#                 credentials. Records every create's answer, the pull
#                 errors by kind and whether ECR throttled. Passes when
#                 every create is answered (none hangs), every throttled
#                 pull is an error the create names, and a create after
#                 the storm starts. ECR not throttling at all is
#                 INCONCLUSIVE, with the rate reached. Run it at 60 workers
#   thresholds    at the current worker count: DRILL_QUIET_MINUTES (10) of
#                 healthy traffic with none of the 7 drilled alerts firing,
#                 each alert's value against its threshold; then the
#                 pull-storm drill for DRILL_STORM_MINUTES (10), whose 3
#                 alerts must fire. Run it at 60 workers (eks-bank.sh scale)
#   fill unfill   DRILL_FILL_COUNT (8) more sandboxes of 1 CPU and 2 GiB that
#                 stay, to fill the cell (eks-bank.sh scale); unfill deletes them
#   shard-routes  past 10 gateways: each sandbox's routes on its 2 owner
#                 gateways only, as /v1/cluster/ingress-route/{id} names them
#                 (eks-bank.sh gateways11)
#   teardown      the drill namespace's objects (the cluster goes with
#                 eks-bank.sh down)
#
# The admin credential: DRILL_TOKEN_FILE, an admin API token (in enterprise
# mode the admin token works only inside a server pod). Without it, one is
# made through a port-forward to server-0's admin port.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
L="$HERE/drills-local"
cluster="${1:?usage: drills-eks.sh <name> <state-dir> <step> [step...]}"; shift
sd="${1:?usage: drills-eks.sh <name> <state-dir> <step> [step...]}"; shift

# --- the gate: this run's own EKS cluster, nothing else -----------------------
refuse() { echo "drills-eks.sh: refusing to run: $*" >&2; exit 2; }
[[ "$cluster" =~ ^[a-z][a-z0-9-]{2,30}$ ]] || refuse "\"$cluster\" is not a cluster.sh run name"
run_dir="$HERE/.state/$cluster"
[[ -f "$run_dir/kubeconfig" && -f "$run_dir/run.tfvars.json" ]] ||
  refuse "no cluster.sh state for $cluster in $run_dir (only a cluster cluster.sh made)"
python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("name") == sys.argv[2] and d.get("bank_drills") is True else 1)' \
  "$run_dir/run.tfvars.json" "$cluster" || refuse "$cluster was not made with cluster.sh --bank-drills"
export KUBECONFIG="$run_dir/kubeconfig"
unset KUBECTL_CONTEXT
ctx="$(kubectl config current-context 2>/dev/null || true)"
[[ "$ctx" =~ ^arn:aws:eks:[a-z0-9-]+:[0-9]{12}:cluster/${cluster}$ ]] ||
  refuse "the kubeconfig cluster.sh wrote for $cluster names context \"$ctx\", not that EKS cluster"
# This machine's AWS credentials are that cluster's account (the ECR token
# the drills read comes from them).
acct="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
[[ "$(cut -d: -f5 <<<"$ctx")" == "$acct" ]] ||
  refuse "this machine's AWS credentials are for account \"$acct\", the cluster is in $(cut -d: -f5 <<<"$ctx")"
# `gate` checks the gate alone (the offline safety tests use it).
if [[ "${1:-}" == gate ]]; then echo "gate: ok, $ctx"; exit 0; fi
mkdir -p "$sd/evidence"

# --- the drill registry, in the cluster ---------------------------------------
drill_reg=drills-registry.drills.svc
ctl_port="${DRILL_PROXY_CONTROL_PORT:-15011}"
ctl_url="http://127.0.0.1:$ctl_port"
ca_issuer="${DRILL_CA_ISSUER:-aerolvm-drills-ca}"
client_image=public.ecr.aws/docker/library/python:3.12-slim
client_pull=IfNotPresent
client_mounts='        - { name: ca, mountPath: /ca }
        - { name: ecr, mountPath: /ecr }'
client_volumes='    - { name: ca, configMap: { name: drills-registry-ca } }
    - { name: ecr, secret: { secretName: drills-ecr, optional: true } }'
registry_where="$drill_reg (in the cluster, HTTPS under the run's private CA)"
# verdict <args>: drills-eks/verdicts.py's judgement, held to its rules by
# the offline safety tests; vfield <json> <field> reads one field of it.
verdict() { python3 -I "$HERE/drills-eks/verdicts.py" "$@"; }
vfield() { jf "$1" "d[\"$2\"]"; }

# pusher <args>: push.py inside the cluster.
pusher() { kc -n drills exec drills-pusher -- python -u /drill/push.py --registry "https://$drill_reg" --cafile /ca/ca.crt "$@"; }
push_tags() { pusher --base drill/app:v1 "$@"; }
push_images() {
  local run="$1" tags=() i
  tags=("drill/dedup:$run" "drill/hot:$run" "drill/hang:$run")
  for i in $(seq 1 12); do tags+=("drill/cold:$run-$i"); done
  push_tags "${tags[@]}" >/dev/null
  say "images pushed for run $run"
}
forwarders() { :; }
registry_log() { kc -n drills logs deploy/drills-registry -c faultproxy --since-time="$(iso "$1")" 2>/dev/null | grep '"path"'; }

setup_registry() {
  sed -e "s|@@CA_ISSUER@@|$ca_issuer|" -e "s|@@WORKER_NS@@|$workers|" "$HERE/drills-eks/registry.yaml" > "$sd/registry.yaml"
  kc create namespace drills --dry-run=client -o yaml | kc apply -f - >/dev/null
  kc -n drills create configmap drills-faultproxy --from-file=faultproxy.py="$L/faultproxy.py" --dry-run=client -o yaml | kc apply -f - >/dev/null
  kc -n drills create configmap drills-pusher --from-file=push.py="$L/push.py" --dry-run=client -o yaml | kc apply -f - >/dev/null
  kc apply -f "$sd/registry.yaml" >/dev/null
  kc -n drills wait certificate/drills-registry-tls --for=condition=Ready --timeout=5m >/dev/null
  # The CA, for the client and the pusher (the workers' copy is the
  # install's worker.registryCA ConfigMap).
  kc -n drills create configmap drills-registry-ca \
    --from-literal=ca.crt="$(kc -n drills get secret drills-registry-tls -o jsonpath='{.data.ca\.crt}' | base64 -d)" \
    --dry-run=client -o yaml | kc apply -f - >/dev/null
  kc -n drills rollout status deploy/drills-registry --timeout=10m >/dev/null
  kc -n drills wait pod/drills-pusher --for=condition=Ready --timeout=5m >/dev/null
  keep_forward drills svc/drills-registry "$ctl_port" 5001 /mode
  # The base: alpine (linux/amd64) from Amazon's public mirror, plus a
  # 4 MiB layer, as kind's docker-built base is.
  pusher --base drill/app:v1 --from https://public.ecr.aws/docker/library/alpine:3.20 >/dev/null
  # Every worker trusts the CA through the chart, or every pull fails.
  local missing
  missing="$(kc -n "$workers" get pods -l app.kubernetes.io/component=worker -o json | python3 -I -c '
import json, sys
bad = [p["metadata"]["name"] for p in json.load(sys.stdin)["items"]
       if not any(e.get("name") == "SSL_CERT_DIR" for c in p["spec"]["containers"] if c["name"] == "agent" for e in c.get("env", []))]
print(" ".join(bad))')"
  [[ -z "$missing" ]] || { result FAIL setup "workers without worker.registryCA: $missing (install with it set)"; return 1; }
}
# The install (eks-bank.sh) already carries the bank-like values, the
# registry CA and the monitoring settings.
setup_values() { :; }
setup_token() {
  if [[ -n "${DRILL_TOKEN_FILE:-}" ]]; then
    ( umask 077; tr -d '\n' < "$DRILL_TOKEN_FILE" > "$sd/token" )
    return
  fi
  local pat pf made
  pat="$(kc -n "$ns" get secret "$cluster_name-admin" -o jsonpath='{.data.token}' | base64 -d | tr -d '\n')"
  kc -n "$ns" port-forward pod/"$cluster_name"-server-0 19213:21219 >/dev/null 2>&1 & pf=$!
  sleep 3
  made="$(curl -fsS -m 30 -H "Authorization: Bearer $pat" -H 'Content-Type: application/json' \
    -d "{\"name\": \"drills-admin-$(date +%s)\", \"role\": \"admin\", \"team\": \"*\", \"expires_in\": \"24h\"}" \
    http://127.0.0.1:19213/v1/tokens)"
  kill "$pf" 2>/dev/null || true
  ( umask 077; jf "$made" 'd["token"]' | tr -d '\n' > "$sd/token" )
}

drills_step() {
  case "$1" in
    large-layers) step_large_layers ;;
    ecr-push) step_ecr_push ;;
    ecr-storm) step_ecr_storm ;;
    thresholds) step_thresholds ;;
    fill) step_fill ;;
    unfill) cleanup_run fill; say "the fill sandboxes deleted" ;;
    shard-routes) step_shard_routes ;;
    teardown) step_teardown ;;
    *) return 127 ;;
  esac
}
# The fault proxy's control port, for every run of the script after setup
# (setup starts it once the registry is up).
drills_begin() {
  [[ " $* " == *" setup "* ]] && return 0
  if kc -n drills get svc drills-registry >/dev/null 2>&1; then
    keep_forward drills svc/drills-registry "$ctl_port" 5001 /mode || say "the fault proxy's control port does not answer"
  fi
}

# worker_state: each worker pod's name, uid and agent restarts.
worker_state() { kc -n "$workers" get pods -l app.kubernetes.io/component=worker -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.uid} {.status.containerStatuses[?(@.name=="agent")].restartCount}{"\n"}{end}' | sort; }

step_large_layers() {
  keep_forward monitoring svc/kube-prometheus-stack-prometheus "$prom_port" 9090 /-/healthy
  local out="$sd/evidence/large-layers" run gib="${DRILL_LARGE_GIB:-3}" n before after t0 r
  mkdir -p "$out"
  run="$(date +%m%d%H%M%S)"
  say "large-layers: pushing drill/big:$run with a ${gib} GiB layer, in the cluster"
  t0=$(now)
  pusher --base drill/app:v1 --size $(( gib << 30 )) "drill/big:$run" > "$out/push.txt" 2>&1
  echo "pushed in $(( $(now) - t0 )) s" >> "$out/push.txt"
  before="$(worker_state)"; echo "$before" > "$out/workers-before.txt"
  n="$(wc -l <<<"$before" | tr -d ' ')"
  storm_start "big-$run" --images "$drill_reg/drill/big:$run" --runtime gvisor --cpu 0.1 --memory-mb 128 \
    --concurrency "$n" --once --delete --client-timeout 1500 --duration 1500
  storm_wait "big-$run" 330 || true
  storm_fetch "big-$run" "$out" > /dev/null
  r="$(sum storm "$out/big-$run.jsonl")"; echo "$r" > "$out/summary.json"
  after="$(worker_state)"; echo "$after" > "$out/workers-after.txt"
  local qx=0 admit
  prom query 'sum by (pod) (aerolvm_host_pressure_can_admit{aerolvm_component="worker"})' > "$out/can-admit.txt" 2> "$out/can-admit.err" || qx=$?
  cleanup_run "big-$run"
  # A query Prometheus did not answer is a FAIL, not "nothing at 0".
  admit="$(verdict admit "$out/can-admit.txt" "$qx" "$n")"
  if [[ "$(jf "$r" 'd["by_outcome"].get("ok", 0)')" == "$n" && "$before" == "$after" && "$(vfield "$admit" verdict)" == PASS ]]; then
    result PASS large-layers "$n creates at once (one per worker) of an image with a ${gib} GiB layer, all started (p50 $(jf "$r" 'd["p50_ms"]') ms, max $(jf "$r" 'd["max_ms"]') ms); no worker pod evicted or restarted; $(vfield "$admit" detail)"
  else
    result FAIL large-layers "creates: $r; workers before/after differ: $([[ "$before" == "$after" ]] && echo no || echo yes); admit: $(vfield "$admit" detail)"
  fi
}

# ecr_secret: ECR's 12-hour pull and push token, read with this machine's
# AWS credentials (a read: nothing is made), into the drill namespace only:
# as auth for push.py and as a create's registry credentials for storm.py.
ecr_secret() {
  local pw host="${ecr_repo%%/*}"
  pw="$(aws ecr get-login-password --region "${DRILL_AWS_REGION:?DRILL_AWS_REGION}")"
  kc -n drills create secret generic drills-ecr --from-literal=auth="AWS:$pw" \
    --from-literal=registry.json="{\"server\": \"$host\", \"username\": \"AWS\", \"password\": \"$pw\"}" \
    --dry-run=client -o yaml | kc apply -f - >/dev/null
  # A secret volume refreshes within a kubelet sync: wait until the pusher
  # and the client both hold the new token.
  local _
  for _ in $(seq 1 36); do
    [[ "$(kc -n drills exec drills-pusher -- cat /ecr/auth 2>/dev/null)" == "AWS:$pw" ]] &&
      kc -n drills exec drills-client -- cat /ecr/registry.json 2>/dev/null | grep -qF -f <(printf '%s\n' "$pw") && return 0
    sleep 5
  done
  say "the ECR token did not reach the drill pods in 3 minutes"
  return 1
}
ecr_repo="${DRILL_ECR_REPO:-}"

# ecr-push: DRILL_ECR_IMAGES (200) images of DRILL_ECR_LAYERS (40) fresh
# 1 KiB layers each, pushed from the pusher pod to the run's ECR
# repository. One pull of one is 40 layer fetches, each a
# GetDownloadUrlForLayer call. Pushed before the storm (eks-bank.sh does it
# at 6 workers), so the 60-worker hour is not spent pushing.
step_ecr_push() {
  [[ -n "$ecr_repo" ]] || { result FAIL ecr-push "DRILL_ECR_REPO is not set (eks-bank.sh sets it)"; return 1; }
  local out="$sd/evidence/ecr-storm" run n="${DRILL_ECR_IMAGES:-200}" layers="${DRILL_ECR_LAYERS:-40}" i refs=() t0
  mkdir -p "$out"
  ecr_secret
  run="$(date +%m%d%H%M%S)"
  say "ecr-push: $n images of $layers layers to $ecr_repo"
  t0=$(now)
  kc -n drills exec drills-pusher -- python -u /drill/push.py --registry "https://${ecr_repo%%/*}" --auth-file /ecr/auth \
    --base "${ecr_repo#*/}:base" --from https://public.ecr.aws/docker/library/alpine:3.20 > "$out/push.txt" 2>&1
  for i in $(seq 1 "$n"); do refs+=("$run-$i"); done
  kc -n drills exec drills-pusher -- python -u /drill/push.py --registry "https://${ecr_repo%%/*}" --auth-file /ecr/auth \
    --base "${ecr_repo#*/}:base" --size 1024 --layers "$layers" "${refs[@]/#/${ecr_repo#*/}:}" >> "$out/push.txt" 2>&1
  echo "$run $n $layers" > "$sd/ecr-run"
  result PASS ecr-push "$n images of $layers layers in $ecr_repo, pushed in $(( $(now) - t0 )) s"
}

# ecr-storm: one create of each pushed image at once, with ECR credentials.
# Passes when every create is answered (none hangs past the client's
# timeout), a create after the storm starts, ECR throttled pulls (the pull
# error counter's rate_limited key moved) and the creates it failed said so
# in their errors (verdicts.py ecr). ECR not throttling is INCONCLUSIVE.
step_ecr_storm() {
  keep_forward monitoring svc/kube-prometheus-stack-prometheus "$prom_port" 9090 /-/healthy
  [[ -f "$sd/ecr-run" ]] || step_ecr_push
  local out="$sd/evidence/ecr-storm" run n layers i images=() t0 t1 r after mins rl rlq after_ok v
  read -r run n layers < "$sd/ecr-run"
  ecr_secret
  for i in $(seq 1 "$n"); do images+=("$ecr_repo:$run-$i"); done
  watch_start "$out"
  t0=$(now)
  storm_start "ecr-$run" --images "${images[*]}" --runtime gvisor --cpu 0.05 --memory-mb 64 \
    --registry-auth-file /ecr/registry.json --concurrency "$n" --once --delete --client-timeout 900 --duration 900
  storm_wait "ecr-$run" 200 || true
  t1=$(now)
  storm_fetch "ecr-$run" "$out" > /dev/null
  r="$(sum storm "$out/ecr-$run.jsonl")"; echo "$r" > "$out/summary.json"
  mins=$(( (t1 - t0) / 60 + 2 ))
  {
    prom query "sum by (key) (increase(aerolvm_image_pull_errors_total[${mins}m]))"
    prom query "sum(increase(aerolvm_image_pull_requests_total[${mins}m]))"
  } > "$out/pulls.txt" 2>&1 || true
  # The registry's 429s, as the pull error counter has them; "error" when
  # Prometheus does not answer.
  if rlq="$(prom query "sum(increase(aerolvm_image_pull_errors_total{key=\"rate_limited\"}[${mins}m]))" 2>> "$out/pulls.txt")"; then
    rl="$(awk 'NR == 1 {print $NF} END {if (NR == 0) print 0}' <<<"$rlq")"
  else
    rl=error
  fi
  # One more create of the first image, after the storm.
  storm_start "ecr-after-$run" --images "${images[0]}" --runtime gvisor --cpu 0.05 --memory-mb 64 \
    --registry-auth-file /ecr/registry.json --concurrency 1 --once --delete --client-timeout 600 --duration 600
  storm_wait "ecr-after-$run" 130 || true
  storm_fetch "ecr-after-$run" "$out" > /dev/null
  after="$(sum storm "$out/ecr-after-$run.jsonl")"
  watch_stop
  cleanup_run "ecr-$run"; cleanup_run "ecr-after-$run"
  after_ok=0
  [[ "$(jf "$after" 'd["by_outcome"].get("ok", 0)')" == 1 ]] && after_ok=1
  v="$(verdict ecr "$out/ecr-$run.jsonl" "$n" "$rl" "$after_ok")"
  echo "$v" > "$out/verdict.json"
  result "$(vfield "$v" verdict)" ecr-storm "$n images x $layers layers in $(( t1 - t0 )) s (about $(( n * (layers + 2) / (t1 - t0 + 1) )) registry calls/s at least): $(vfield "$v" detail); storm $r"
}

# quiet_window <out> <run> <workers> <minutes>: healthy creates on every
# worker for that long; thresholds-quiet's verdict (verdicts.py quiet).
quiet_window() {
  local out="$1" run="$2" n="$3" quiet="$4" t0 a v start_ok=0 end_ok=1
  # Prometheus answers at the start of the window and at its end: a quiet
  # window Prometheus could not see is no PASS.
  prom query 'vector(1)' > /dev/null 2>&1 && start_ok=1
  t0=$(now)
  storm_start "quiet-$run" --images "$drill_reg/drill/app:v1" --runtime gvisor --cpu 0.05 --memory-mb 64 \
    --concurrency "$n" --pause 2 --delete --duration $(( quiet * 60 ))
  # wait ends when every alert fired, or at the timeout: a firing line for
  # any one of them is the FAIL, as is a firing sample in the window's
  # history (a firing the wait missed while its port-forward was down).
  prom wait "${drilled_alerts[@]}" --state firing --timeout $(( quiet * 60 )) > "$out/quiet-fired.jsonl" 2>> "$out/quiet-wait.err" || true
  : > "$out/quiet-history.jsonl"
  for a in "${drilled_alerts[@]}"; do
    prom history "$a" --since "$t0" >> "$out/quiet-history.jsonl" 2>> "$out/quiet-wait.err" || end_ok=0
  done
  prom query 'vector(1)' > /dev/null 2>&1 || end_ok=0
  v="$(verdict quiet "$out/quiet-fired.jsonl" "$out/quiet-history.jsonl" "$start_ok" "$end_ok")"
  result "$(vfield "$v" verdict)" thresholds-quiet "$quiet min of healthy creates on $n workers, ${#drilled_alerts[@]} drilled alerts: $(vfield "$v" detail)"
  storm_stop "quiet-$run"; cleanup_run "quiet-$run"
}

step_thresholds() {
  keep_forward monitoring svc/kube-prometheus-stack-prometheus "$prom_port" 9090 /-/healthy
  local out="$sd/evidence/thresholds" run quiet="${DRILL_QUIET_MINUTES:-10}" n a expr
  mkdir -p "$out"
  : > "$out/quiet-wait.err"
  run="$(date +%m%d%H%M%S)"
  n="$(kc -n "$workers" get pods -l app.kubernetes.io/component=worker --no-headers | wc -l | tr -d ' ')"
  say "thresholds: $quiet min of healthy creates on $n workers; no drilled alert may fire"
  proxy mode/clear
  watch_start "$out"
  # The earlier steps' alerts must have cleared first: one still firing
  # from them would fail a window that was quiet.
  if prom wait "${drilled_alerts[@]}" --state inactive --timeout $(( ${DRILL_CLEAR_MINUTES:-20} * 60 )) > "$out/cleared.jsonl" 2>> "$out/quiet-wait.err"; then
    quiet_window "$out" "$run" "$n" "$quiet"
  else
    result INCONCLUSIVE thresholds-quiet "the earlier steps' alerts did not clear in ${DRILL_CLEAR_MINUTES:-20} min ($out/cleared.jsonl); no quiet window run"
  fi
  # Each alert's expression over the quiet window, beside its threshold.
  : > "$out/margins.txt"
  for a in "${drilled_alerts[@]}"; do
    expr="$(awk -v a="$a" '$0 ~ "alert: "a"$" {f=1; next} f && /expr:/ {sub(/.*expr: */, ""); print; exit}' "$ROOT/setup/prometheus/sandboxd-alerts.yml")"
    echo "$a: $expr -> max over the quiet window: $(prom query "max_over_time(($expr)[${quiet}m:30s])" 2>/dev/null | tr '\n' ' ')" >> "$out/margins.txt"
  done
  watch_stop
  # drills-lib.sh read the hold when sourced; step_pull_storm sees this one.
  local hold_min="${DRILL_HOLD_MINUTES:-5}"
  DRILL_STORM_MINUTES="${DRILL_STORM_MINUTES:-10}" step_pull_storm
}

# fill: DRILL_FILL_COUNT (8) more sandboxes of 1 CPU and 2 GiB that stay,
# all tagged drill-run=fill (eks-bank.sh scale fills the cell with them,
# round by round, until the operator buys machines). unfill deletes them.
step_fill() {
  local out="$sd/evidence/scale" n="${DRILL_FILL_COUNT:-8}"
  mkdir -p "$out"
  storm_start fill --images "$drill_reg/drill/app:v1" --runtime gvisor --cpu 1 --memory-mb 2048 \
    --concurrency "$n" --once --client-timeout 600 --duration 600
  storm_wait fill 130 || true
  storm_fetch fill "$out" > /dev/null
  say "fill: $n more sandboxes of 1 CPU and 2 GiB; every fill create so far: $(sum storm "$out/fill.jsonl")"
}

# caddy_get <gateway pod>: its edge Caddy's whole config, over a port-forward.
caddy_get() {
  local k _
  kc -n "$ns" port-forward "pod/$1" 12020:2019 >/dev/null 2>&1 &
  k=$!
  for _ in $(seq 1 20); do
    curl -s -m 2 -o /dev/null -H "Host: localhost:2019" http://127.0.0.1:12020/config/admin && break
    sleep 1
  done
  curl -sS -m 30 -H "Host: localhost:2019" http://127.0.0.1:12020/config/ 2>/dev/null || true
  kill "$k" 2>/dev/null || true
  wait "$k" 2>/dev/null || true
}

# shard-routes: past 10 gateways (eks-bank.sh gateways11, the shard-aware
# opt-in on every node) a sandbox's public routes live on its two owner
# gateways only, and the router in front asks /v1/cluster/ingress-route/{id}
# which ones. DRILL_SHARD_SANDBOXES (50) public sandboxes. Passes when every
# answer names 2 of the live gateways under one ring version, every gateway
# owns some of them, and each of the first 6 sandboxes' routes sits in its
# owners' Caddy and in no other gateway's.
step_shard_routes() {
  local out="$sd/evidence/gateways11" n="${DRILL_SHARD_SANDBOXES:-50}" run gws gw id ids v
  mkdir -p "$out"
  run="shard-$(date +%m%d%H%M%S)"
  gws="$(kc -n "$ns" get pods -l app.kubernetes.io/component=gateway -o jsonpath='{.items[*].metadata.name}')"
  say "shard-routes: $n public sandboxes over $(wc -w <<<"$gws" | tr -d ' ') gateways"
  storm_start "$run" --images "$drill_reg/drill/app:v1" --runtime gvisor --public --cpu 0.05 --memory-mb 64 \
    --concurrency "$n" --once --client-timeout 600 --duration 600
  storm_wait "$run" 130 || true
  storm_fetch "$run" "$out" > /dev/null
  ids="$(python3 -I -c 'import json, sys; print(" ".join(r["id"] for r in map(json.loads, open(sys.argv[1])) if r.get("id")))' "$out/$run.jsonl")"
  : > "$out/routes.jsonl"
  for id in $ids; do api GET "/v1/cluster/ingress-route/$id" >> "$out/routes.jsonl"; done
  sleep 30 # the owners install the routes
  for gw in $gws; do caddy_get "$gw" > "$out/caddy-$gw.json"; done
  # shellcheck disable=SC2086
  v="$(verdict shard "$out" $gws)"
  # A route not yet in any gateway's Caddy: once more, half a minute on.
  if [[ "$(jf "$v" 'd["detail"]["caddy_route_nowhere"]')" != 0 ]]; then
    sleep 30
    for gw in $gws; do caddy_get "$gw" > "$out/caddy-$gw.json"; done
    # shellcheck disable=SC2086
    v="$(verdict shard "$out" $gws)"
  fi
  echo "$v" > "$out/verdict.json"
  cleanup_run "$run"
  if [[ "$(vfield "$v" verdict)" == PASS ]]; then
    result PASS shard-routes "$(jf "$v" 'd["detail"]["sandboxes"]') public sandboxes over $(jf "$v" 'd["detail"]["gateways"]') gateways: each has 2 owners under one ring version, every gateway owns some ($(jf "$v" 'd["detail"]["owned_per_gateway"]')); $(jf "$v" 'd["detail"]["caddy_checked"]') sandboxes' routes sit in exactly their owners' Caddy, none nowhere"
  else
    result FAIL shard-routes "$(vfield "$v" detail)"
  fi
}

step_teardown() {
  kc -n drills logs deploy/drills-registry -c faultproxy > "$sd/evidence/registry-all.jsonl" 2>/dev/null || true
  kc delete namespace drills --wait=false >/dev/null 2>&1 || true
  kc -n "$workers" delete networkpolicy drills-registry-egress --ignore-not-found >/dev/null 2>&1 || true
  say "the drill namespace and its registry deleted"
}

# shellcheck source=drills-lib.sh
source "$HERE/drills-lib.sh"
drills_main drills-eks.sh "$@"

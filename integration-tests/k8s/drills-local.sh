#!/usr/bin/env bash
# drills-local.sh: the image-pull storm and SLO-breach drills (issue #1343)
# on a local kind cluster in cluster mode. No cloud: the registry and its
# faults, Prometheus, Alertmanager and the alert receiver run on this
# machine.
#
#   AEROL_K8S_MODE=cluster AEROL_KIND_CLUSTER=aerolvm-drills AEROL_K8S_EDGE=1 \
#     HELM=<helm 3.8 or later> scripts/k8s-dev.sh
#   KUBECTL_CONTEXT=kind-aerolvm-drills HELM=<helm> \
#     integration-tests/k8s/drills-local.sh <state-dir> setup static pull-storm slo-breach
#   integration-tests/k8s/drills-local.sh <state-dir> teardown
#
# Needs Docker, kind, kubectl, Helm and python3 on this machine. Steps (each
# prints PASS or FAIL lines into <state-dir>/drills.txt):
#   setup       a registry:2 behind a fault proxy (drills-local/faultproxy.py)
#               on the kind Docker network, the drill images pushed to it;
#               kube-prometheus-stack (pinned) with Alertmanager routed as
#               setup/alertmanager/sandboxd-alertmanager-example.yml says, to
#               an echo receiver; the bank-like values (drills-local/
#               values-bank-kind.yaml) over the install; the sandboxd alerts
#               (setup/prometheus/sandboxd-alerts.yml, which the chart does
#               not ship) as a PrometheusRule; a client pod; and in each
#               worker pod a forwarder, so the pod pulls from localhost:5000
#   static      every metric the drilled alerts read: registered by sandboxd's
#               Go code, scraped from every pod, and which kinds of pod say
#               what; servers and gateways must say can_admit 0; and one
#               cold create must move the pull counter
#   pull-storm  drill 1. One image wanted by many creates at once, from a slow
#               registry: one pull per worker (pull-dedup). Then, for up to
#               DRILL_STORM_MINUTES (25): one image the registry rate-limits
#               (429) and 12 images it serves slowly, each wanted by a steady
#               stream of creates. Passes when SandboxdImagePullQueueBacklog,
#               SandboxdImagePullBackoffRejects and SandboxdImagePullErrors
#               fire (pull-alerts); the registry sees each worker try the
#               rate-limited image at most once per backoff (pull-backoff);
#               no worker runs more pulls than its cap (pull-queue); and
#               after setup/runbooks/image-pull-storm.md's steps every alert
#               resolves and the runbook's recovery checks hold for
#               DRILL_HOLD_MINUTES (15) (pull-recover). About 50 minutes.
#   slo-breach  drill 2. A registry that crawls (2 kB/s) under 130 creates
#               at once (a create backlog), a rate-limited image (create
#               errors), and
#               Caddy's admin API moved off its address on one gateway while
#               public sandboxes come and go (route lag); then workers filled
#               to the last CPU (no worker can admit). Passes when
#               SandboxdCreateQueueBacklog, SandboxdCreateErrors,
#               SandboxdIngressRouteLag and SandboxdNoAdmitWorkers fire
#               (slo-alerts), Alertmanager delivers each to the receiver the
#               example routes it to (slo-routing), and following
#               setup/runbooks/slo-breach.md resolves each, with the
#               receiver told (slo-recover). Each condition is held until the
#               receiver has its notice. About 35 minutes.
#   teardown    the registry and proxy containers (the kind cluster goes with
#               `AEROL_KIND_CLUSTER=aerolvm-drills scripts/k8s-dev.sh down`)
#
# Evidence goes to <state-dir>/evidence/<step>/: a metrics and alert
# timeline (one line each 30 s), every create's answer, the registry's
# request log, the receiver's log and the sandboxd log lines the runbook
# greps for. Each drill puts back what it breaks (the registry's faults,
# Caddy, its sandboxes); setup's Helm values and the forwarders in the
# worker pods stay.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
L="$HERE/drills-local"
sd="${1:?usage: drills-local.sh <state-dir> <step> [step...]}"; shift
mkdir -p "$sd/evidence"
ctx="${KUBECTL_CONTEXT:-kind-aerolvm-drills}"
kind_cluster="${ctx#kind-}"
ns="${AEROL_NS:-aerolvm-system}"
workers="${AEROL_WORKER_NS:-aerolvm-workers}"
release="${AEROL_HELM_RELEASE:-aerolvm}"
cluster_name="${AEROL_CLUSTER_NAME:-aerolvm}"
HELM="${HELM:-helm}"
# kube-prometheus-stack, pinned (2026-10-31).
kps_version="${DRILL_KPS_VERSION:-92.17.0}"
prom_port="${DRILL_PROM_PORT:-19090}"
reg_port="${DRILL_REGISTRY_PORT:-15000}"
ctl_port="${DRILL_PROXY_CONTROL_PORT:-15001}"
backoff_s="${DRILL_PULL_BACKOFF_SECONDS:-30}"
pull_cap="${DRILL_PULL_MAX_CONCURRENT:-4}"
hold_min="${DRILL_HOLD_MINUTES:-15}"
results="$sd/drills.txt"
touch "$results"
kc() { kubectl --context "$ctx" "$@"; }
hm() { "$HELM" --kube-context "$ctx" "$@"; }
say() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$sd/drills.log" >&2; }
result() { echo "$1 $2 $3" | tee -a "$results" "$sd/drills.log"; }
now() { date +%s; }
iso() { date -u -r "$1" +%FT%TZ 2>/dev/null || date -u -d "@$1" +%FT%TZ; }
prom() { python3 "$L/prom.py" --url "http://127.0.0.1:$prom_port" "$@"; }
# val <expr>: the first series' value, or 0 when there is none.
val() { prom query "$1" | awk 'NR==1 {print $NF} END {if (NR==0) print 0}'; }
proxy() { curl -fsS -X POST "http://127.0.0.1:$ctl_port/$1" >/dev/null; }
run_id() { cat "$sd/run"; }
sum() { python3 "$L/summarize.py" "$@"; }
# jf <json> <python expression over d>
jf() { python3 -c "import json, sys; d = json.loads(sys.argv[1]); print($2)" "$1"; }

# A port-forward that comes back: kubectl port-forward quits on the first
# broken connection, and the Prometheus pod may move.
keepers=()
keep_forward() {
  local nsx="$1" target="$2" lport="$3" rport="$4" path="$5"
  (
    k=""
    trap '[[ -z "$k" ]] || kill "$k" 2>/dev/null; exit 0' TERM
    while :; do
      kubectl --context "$ctx" -n "$nsx" port-forward "$target" "$lport:$rport" >/dev/null 2>&1 &
      k=$!
      sleep 3
      while kill -0 "$k" 2>/dev/null && curl -fsS --max-time 5 -o /dev/null "http://127.0.0.1:$lport$path" 2>/dev/null; do sleep 5; done
      kill "$k" 2>/dev/null || true
      wait "$k" 2>/dev/null || true
      sleep 1
    done
  ) 2>/dev/null &
  keepers+=($!)
  local _
  for _ in $(seq 1 30); do
    curl -fsS --max-time 3 -o /dev/null "http://127.0.0.1:$lport$path" 2>/dev/null && return 0
    sleep 2
  done
  return 1
}
watcher=""
cleanup() {
  [[ -z "$watcher" ]] || kill "$watcher" 2>/dev/null || true
  local p kids
  for p in ${keepers[@]+"${keepers[@]}"}; do
    kids="$(pgrep -P "$p" 2>/dev/null || true)"
    kill "$p" 2>/dev/null || true
    [[ -z "$kids" ]] || kill $kids 2>/dev/null || true
  done
}
trap cleanup EXIT

# watch_start <dir>: a line a 30 s of the drilled metrics and alerts.
drilled_alerts=(SandboxdImagePullQueueBacklog SandboxdImagePullBackoffRejects SandboxdImagePullErrors
  SandboxdCreateQueueBacklog SandboxdCreateErrors SandboxdNoAdmitWorkers SandboxdIngressRouteLag)
# The watcher is exec'd in its subshell, so $! is python itself: a shell
# function sent to the background is a subshell, and killing that left the
# python running after the step (three were left over from the first runs).
watch_start() {
  ( exec python3 "$L/prom.py" --url "http://127.0.0.1:$prom_port" watch --out "$1/timeline.jsonl" --interval 30 --alerts "${drilled_alerts[@]}" --exprs \
    'queued=sum by (aerolvm_component) (aerolvm_image_pull_queued)' \
    'inflight=max by (pod) (aerolvm_image_pull_inflight{aerolvm_component="worker"})' \
    'pull_errors_5m=sum by (key) (rate(aerolvm_image_pull_errors_total[5m]))' \
    'backoff_rejects_5m=sum(rate(aerolvm_image_pull_backoff_rejects_total[5m]))' \
    'dedup_waiters=sum(aerolvm_image_pull_dedup_waiters_total)' \
    'create_queue=sum by (aerolvm_component) (aerolvm_create_queue_depth)' \
    'create_errors_5m=sum by (key) (rate(aerolvm_create_errors_total[5m]))' \
    'can_admit=sum by (aerolvm_component) (aerolvm_host_pressure_can_admit)' \
    'route_lag=max by (pod) (aerolvm_ingress_route_lag_versions{aerolvm_component="gateway"})' \
    'caddy_reconcile_errors=sum(aerolvm_ingress_reconcile_errors_total)' ) &
  watcher=$!
}
watch_stop() { [[ -z "$watcher" ]] || kill "$watcher" 2>/dev/null || true; watcher=""; }

# The client pod runs the creates: more than a hundred held for minutes is
# more than a laptop port-forward carries.
storm_start() {
  local name="$1"; shift
  kc -n drills exec drills-client -- sh -c "cd /work && nohup python -u /drill/storm.py --url \"\$AEROL_URL\" \
    --token-file /token/token --run $name --out /work/$name.jsonl $* > /work/$name.out 2>&1 & echo \$! > /work/$name.pid"
}
storm_stop() { kc -n drills exec drills-client -- sh -c "kill \$(cat /work/$1.pid) 2>/dev/null || true"; }
# A finished caller is a zombie until something reaps it: kill -0 alone
# says it still runs (the first run waited out the whole cap on one).
storm_running() {
  kc -n drills exec drills-client -- sh -c "s=\$(cut -d' ' -f3 /proc/\$(cat /work/$1.pid)/stat 2>/dev/null); [ -n \"\$s\" ] && [ \"\$s\" != Z ]"
}
storm_wait() {
  local _
  for _ in $(seq 1 "${2:-360}"); do storm_running "$1" || return 0; sleep 5; done
  return 1
}
# storm_fetch <name> <dir>: copy a run's answers out of the client pod.
storm_fetch() { kc -n drills exec drills-client -- cat "/work/$1.jsonl" > "$2/$1.jsonl" 2>/dev/null || true; }
# api <method> <path> [body]: one call through the client pod.
api() {
  kc -n drills exec drills-client -- python -c "
import sys, json; sys.path.insert(0, '/drill'); from load import call
tok = open('/token/token').read().strip()
import os
c, o = call(os.environ['AEROL_URL'], tok, sys.argv[1], sys.argv[2], json.loads(sys.argv[3]) if len(sys.argv) > 3 else None, timeout=300)
print(json.dumps({'code': c, 'body': o}))" "$@"
}
# cleanup_run <run>: delete every sandbox a run left (a stopped caller's
# creates still finish on the worker, with no one left to delete them).
cleanup_run() {
  kc -n drills exec drills-client -- python -c "
import sys, json, os, urllib.request; sys.path.insert(0, '/drill'); from load import call
tok = open('/token/token').read().strip(); url = os.environ['AEROL_URL']; n = 0
for _ in range(3):
    req = urllib.request.Request(url + '/v1/sandboxes?tag.drill-run=' + sys.argv[1], headers={'Authorization': 'Bearer ' + tok})
    body = json.loads(urllib.request.urlopen(req, timeout=60).read() or b'[]')
    rows = body if isinstance(body, list) else body.get('sandboxes', [])
    if not rows:
        break
    for r in rows:
        call(url, tok, 'DELETE', '/v1/sandboxes/' + r['id'], timeout=120); n += 1
print(n)" "$1" >> "$sd/drills.log" 2>&1 || true
}
# smoke [image]: the runbooks' known-good create, then its delete.
smoke() {
  local img="${1:-localhost:5000/drill/app:v1}" out id code
  out="$(api POST /v1/sandboxes "{\"image\": \"$img\", \"runtime\": \"gvisor\", \"cpu\": 0.1, \"memory_mb\": 128, \"allow_public_traffic\": true, \"tags\": {\"drill-run\": \"smoke\"}}")"
  code="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["code"])' "$out")"
  id="$(python3 -c 'import json,sys; print((json.loads(sys.argv[1])["body"] or {}).get("id",""))' "$out")"
  [[ -z "$id" ]] || api DELETE "/v1/sandboxes/$id" >/dev/null || true
  echo "$code"
}

# The worker pods reach the registry as localhost:5000 (fwd.py): containerd
# speaks plain HTTP only to localhost, and kind has no CA the pods trust.
# An ephemeral container cannot be restarted, so a pod whose forwarder
# stopped gets another under a new name.
forwarders() {
  local pip pod running n
  pip="$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' drills-faultproxy)"
  # Running pods only: a worker the operator asked for that never got a
  # machine stays Pending, and needs no forwarder.
  for pod in $(kc -n "$workers" get pods -l app.kubernetes.io/component=worker --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'); do
    running="$(kc -n "$workers" get pod "$pod" -o json | python3 -c '
import json, sys
p = json.load(sys.stdin)
print(sum(1 for s in p["status"].get("ephemeralContainerStatuses", []) if s["name"].startswith("drills-fwd") and "running" in s["state"]))')"
    [[ "$running" -gt 0 ]] && continue
    n="$(kc -n "$workers" get pod "$pod" -o jsonpath='{.spec.ephemeralContainers[*].name}' | wc -w | tr -d ' ')"
    kc -n "$workers" debug "pod/$pod" --image=python:3.12-slim --image-pull-policy=Never \
      --container="drills-fwd-$n" -- python -u -c "$(cat "$L/fwd.py")" "$pip" 5000 >/dev/null
    say "forwarder drills-fwd-$n added to $pod"
  done
}

# push_images <run>: fresh images for one run, each the base image plus a
# layer of random bytes, so every pull of the run is a cold one. Docker
# builds only the base (alpine plus a file), once; drills-local/push.py
# writes the rest over the registry's API: Docker Desktop spent 45 s on
# each push to "localhost" (a name lookup) and stalled on others for good.
push_images() {
  local run="$1" d tags=() i
  if ! curl -fsS -o /dev/null "http://127.0.0.1:$reg_port/v2/drill/app/manifests/v1" \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json'; then
    d="$(mktemp -d)"
    printf 'FROM alpine:latest\nCOPY blob /blob\n' > "$d/Dockerfile"
    head -c 4194304 /dev/urandom > "$d/blob"
    docker build -q -t "127.0.0.1:$reg_port/drill/app:v1" "$d" >/dev/null
    timeout 300 docker push -q "127.0.0.1:$reg_port/drill/app:v1" >/dev/null
    rm -rf "$d"
  fi
  tags=("drill/dedup:$run" "drill/hot:$run" "drill/hang:$run")
  for i in $(seq 1 12); do tags+=("drill/cold:$run-$i"); done
  python3 "$L/push.py" --registry "http://127.0.0.1:$reg_port" --base drill/app:v1 "${tags[@]}" >/dev/null
  say "images pushed for run $run"
}

# --- setup -------------------------------------------------------------------------
step_setup() {
  local pip
  docker network inspect kind >/dev/null
  if ! docker inspect drills-registry >/dev/null 2>&1; then
    docker run -d --name drills-registry --network kind -p "127.0.0.1:$reg_port:5000" registry:2 >/dev/null
  fi
  if ! docker inspect drills-faultproxy >/dev/null 2>&1; then
    docker run -d --name drills-faultproxy --network kind -p "127.0.0.1:$ctl_port:5001" \
      -v "$L/faultproxy.py:/faultproxy.py:ro" python:3.12-slim \
      python -u /faultproxy.py --upstream http://drills-registry:5000 --listen 5000 --control 5001 >/dev/null
  else
    # A restart loads faultproxy.py afresh. The worker pods' forwarders and
    # the NetworkPolicy hold its address, so it keeps the one it had.
    pip="$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' drills-faultproxy)"
    docker restart drills-faultproxy >/dev/null
    if [[ "$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' drills-faultproxy)" != "$pip" ]]; then
      docker network disconnect kind drills-faultproxy
      docker network connect --ip "$pip" kind drills-faultproxy
    fi
  fi
  pip="$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' drills-faultproxy)"
  [[ -f "$sd/run" ]] || date +%m%d%H%M > "$sd/run"
  push_images "$(run_id)"
  kind load docker-image --name "$kind_cluster" python:3.12-slim >/dev/null

  kc create namespace monitoring --dry-run=client -o yaml | kc apply -f - >/dev/null
  hm upgrade --install kube-prometheus-stack kube-prometheus-stack \
    --repo https://prometheus-community.github.io/helm-charts --version "$kps_version" \
    -n monitoring -f "$L/kps-values.yaml" --wait --timeout 10m >/dev/null
  kc -n monitoring create configmap alert-echo --from-file=echo.py="$L/echo.py" --dry-run=client -o yaml | kc apply -f - >/dev/null
  kc apply -f - >/dev/null <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: alert-echo, namespace: monitoring }
spec:
  replicas: 1
  selector: { matchLabels: { app: alert-echo } }
  template:
    metadata: { labels: { app: alert-echo } }
    spec:
      containers:
        - name: echo
          image: python:3.12-slim
          imagePullPolicy: Never
          command: [python, -u, /app/echo.py, --listen, "8080"]
          ports: [{ containerPort: 8080 }]
          volumeMounts: [{ name: app, mountPath: /app }]
      volumes: [{ name: app, configMap: { name: alert-echo } }]
---
apiVersion: v1
kind: Service
metadata: { name: alert-echo, namespace: monitoring }
spec:
  selector: { app: alert-echo }
  ports: [{ port: 8080, targetPort: 8080 }]
YAML
  # The chart ships the Kubernetes alerts only; a bank that wants the
  # sandboxd SLO and image-pull alerts loads this file itself.
  { printf 'apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nmetadata:\n  name: sandboxd-alerts\n  namespace: monitoring\n  labels: { release: kube-prometheus-stack }\nspec:\n'
    sed 's/^/  /' "$ROOT/setup/prometheus/sandboxd-alerts.yml"; } | kc apply -f - >/dev/null

  # The bank-like values, and the registry's address let out of the worker
  # pods, as a bank adds its own registry's range.
  hm upgrade "$release" "$ROOT/charts/aerolvm" -n "$ns" --reuse-values -f "$L/values-bank-kind.yaml" \
    --set-json "networkPolicy.extraEgressCIDRs=[\"$pip/32\"]" >/dev/null

  kc create namespace drills --dry-run=client -o yaml | kc apply -f - >/dev/null
  kc -n "$ns" get secret "$cluster_name-admin" -o jsonpath='{.data.token}' | base64 -d > "$sd/token"
  chmod 600 "$sd/token"
  kc -n drills create secret generic drills-token --from-file=token="$sd/token" --dry-run=client -o yaml | kc apply -f - >/dev/null
  kc -n drills create configmap drills-scripts --from-file=storm.py="$L/storm.py" \
    --from-file=load.py="$HERE/cell/load.py" --dry-run=client -o yaml | kc apply -f - >/dev/null
  # A pod's spec cannot change in place: start the client afresh.
  kc -n drills delete pod drills-client --ignore-not-found --wait=true >/dev/null
  kc apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: { name: drills-client, namespace: drills }
spec:
  # The pause container is PID 1 and reaps the callers storm_start leaves.
  shareProcessNamespace: true
  containers:
    - name: client
      image: python:3.12-slim
      imagePullPolicy: Never
      command: [sleep, infinity]
      # The gateways' API port, through the chart's headless metrics
      # Service: the Service clients use is the edge's HTTPS.
      env: [{ name: AEROL_URL, value: "http://$release-gateway-metrics.$ns.svc:21212" }]
      volumeMounts:
        - { name: scripts, mountPath: /drill }
        - { name: token, mountPath: /token }
        - { name: work, mountPath: /work }
  volumes:
    - { name: scripts, configMap: { name: drills-scripts } }
    - { name: token, secret: { secretName: drills-token } }
    - { name: work, emptyDir: {} }
YAML
  kc -n drills wait --for=condition=Ready pod/drills-client --timeout=180s >/dev/null
  forwarders
  keep_forward monitoring svc/kube-prometheus-stack-prometheus "$prom_port" 9090 /-/healthy
  local want up _
  want=$(( $(kc -n "$ns" get pods -l app.kubernetes.io/name=aerolvm --no-headers | wc -l) + \
    $(kc -n "$workers" get pods -l app.kubernetes.io/name=aerolvm --no-headers | wc -l) ))
  for _ in $(seq 1 60); do
    up="$(curl -fsS "http://127.0.0.1:$prom_port/api/v1/targets?state=active" | python3 -c '
import json, sys
print(sum(1 for t in json.load(sys.stdin)["data"]["activeTargets"] if t["labels"].get("aerolvm_component") and t["health"] == "up"))')"
    [[ "$up" -ge "$want" ]] && break
    sleep 10
  done
  local code
  code="$(smoke)"
  if [[ "$up" -ge "$want" && "$code" == 201 ]]; then
    result PASS setup "registry at $pip behind the fault proxy; $up of $want AerolVM pods scraped; a create from localhost:5000 answered $code"
  else
    result FAIL setup "$up of $want AerolVM pods scraped (a refused ServiceMonitor shows in the Prometheus Operator's log); smoke create answered $code"
  fi
}

# --- static ------------------------------------------------------------------------
# The alerts the drills fire, and every metric each one reads.
step_static() {
  keep_forward monitoring svc/kube-prometheus-stack-prometheus "$prom_port" 9090 /-/healthy
  local out="$sd/evidence/static" a expr m reg comps bad=0
  mkdir -p "$out"
  : > "$out/static.txt"
  for a in "${drilled_alerts[@]}"; do
    expr="$(awk -v a="$a" '$0 ~ "alert: "a"$" {f=1; next} f && /expr:/ {sub(/.*expr: */, ""); print; exit}' "$ROOT/setup/prometheus/sandboxd-alerts.yml")"
    for m in $(grep -oE 'aerolvm_[a-z0-9_]+' <<<"$expr" | sort -u); do
      reg="$(grep -rlE "\"$m\"" --include='*.go' "$ROOT/cmd" "$ROOT/internal" "$ROOT/pkg" | grep -v _test.go | head -1 || true)"
      comps="$(prom query "count by (aerolvm_component) ($m)" | tr '\n' ' ')"
      echo "$a | $expr | $m | registered: ${reg#"$ROOT/"} | scraped: ${comps:-none}" >> "$out/static.txt"
      if [[ -z "$reg" ]]; then
        result FAIL "static-$a" "$m is in the rule but no Go code registers it"
        bad=1
      elif [[ -z "$comps" && "$m" != *_total ]]; then
        # A counter map has no series until its first key; a gauge always has.
        result FAIL "static-$a" "$m is registered (${reg#"$ROOT/"}) but Prometheus scrapes no series of it"
        bad=1
      fi
    done
  done
  # can_admit: only workers may say 1, or the sum never reaches 0.
  local others
  others="$(val 'sum(aerolvm_host_pressure_can_admit{aerolvm_component=~"server|gateway"})')"
  echo "can_admit on servers and gateways: $others" >> "$out/static.txt"
  if [[ "${others%.*}" != 0 ]]; then
    result FAIL static-SandboxdNoAdmitWorkers "servers and gateways publish can_admit=$others, so sum(...) == 0 cannot happen"
    bad=1
  fi
  # Registered is not enough: the engine must also move them. One cold pull
  # must count as a pull request (the containerd engine moved none of the
  # image-pull metrics before issue #1343).
  local before after probe code
  probe="drill/probe:$(date +%m%d%H%M%S)"
  python3 "$L/push.py" --registry "http://127.0.0.1:$reg_port" --base drill/app:v1 "$probe" >/dev/null
  before="$(val 'sum(aerolvm_image_pull_requests_total)')"
  code="$(smoke "localhost:5000/$probe")"
  sleep 40 # one scrape
  after="$(val 'sum(aerolvm_image_pull_requests_total)')"
  echo "a cold create of $probe answered $code; aerolvm_image_pull_requests_total $before -> $after" >> "$out/static.txt"
  if [[ "$code" != 201 || "${after%.*}" -le "${before%.*}" ]]; then
    result FAIL static-image-pull-metrics "a cold create ($code) did not move aerolvm_image_pull_requests_total ($before -> $after): this engine does not report its pulls"
    bad=1
  fi
  [[ "$bad" == 1 ]] || result PASS static "every metric the 7 drilled alerts read is registered and scraped, and a cold pull moves the pull counter ($out/static.txt)"
}

# --- pull-storm --------------------------------------------------------------------
step_pull_storm() {
  keep_forward monitoring svc/kube-prometheus-stack-prometheus "$prom_port" 9090 /-/healthy
  local out="$sd/evidence/pull-storm" run t0 t1 r
  mkdir -p "$out"
  # Fresh images for every run of the step: a rerun must pull cold too.
  run="$(date +%m%d%H%M%S)"
  echo "$run" > "$out/run"
  push_images "$run"
  forwarders
  watch_start "$out"
  proxy mode/clear; proxy stats/reset

  # 1. One cold image, 24 creates at once, a slow registry: each worker
  #    fetches each part of it once, and the rest of its creates wait on
  #    that pull.
  say "pull-dedup: 24 creates of drill/dedup:$run, registry slow"
  proxy "mode?name=slow&delay=5&bps=200000&repo=drill/dedup"
  local w0 w1 ok max nworkers
  w0="$(val 'sum(aerolvm_image_pull_dedup_waiters_total)')"
  t0=$(now)
  storm_start "dedup-$run" --images "localhost:5000/drill/dedup:$run" --runtime gvisor --concurrency 24 --once --delete --duration 600
  storm_wait "dedup-$run" 120 || true
  sleep 40 # a scrape after the last create
  w1="$(val 'sum(aerolvm_image_pull_dedup_waiters_total)')"
  storm_fetch "dedup-$run" "$out" > /dev/null
  sum storm "$out/dedup-$run.jsonl" > "$out/dedup-summary.json"
  docker logs --since "$(iso "$t0")" drills-faultproxy 2>/dev/null | grep '"path"' > "$out/registry-dedup.jsonl" || true
  r="$(sum dedup "$out/registry-dedup.jsonl" drill/dedup)"
  echo "$r" > "$out/dedup-registry.json"
  ok="$(jf "$(cat "$out/dedup-summary.json")" 'd["by_outcome"].get("ok", 0)')"
  max="$(jf "$r" 'd["max_same_path"]')"
  nworkers="$(jf "$r" 'd["workers"]')"
  if [[ "$ok" -ge 20 && "$max" == 1 && "${w1%.*}" -gt "${w0%.*}" ]]; then
    result PASS pull-dedup "$ok of 24 creates of one cold image started on $nworkers workers; no worker fetched any part of it twice ($r); dedup waiters +$(( ${w1%.*} - ${w0%.*} ))"
  else
    result FAIL pull-dedup "$ok of 24 started; most GETs of one path by one worker: $max (want 1); dedup waiters $w0 -> $w1"
  fi

  # 2. The storm: one image the registry rate-limits, and 12 it serves
  #    slowly: 20 s before each answer, then 20 kB/s, so one pull holds its
  #    slot for minutes. (Not slower to answer: containerd gives up on a
  #    request after 30 s without response headers, which makes a storm of
  #    errors, not a queue; the first run found that.)
  local minutes="${DRILL_STORM_MINUTES:-25}" cold="" i
  for i in $(seq 1 12); do cold="$cold localhost:5000/drill/cold:$run-$i"; done
  proxy stats/reset
  proxy "mode?name=ratelimit&repo=drill/hot"
  proxy "mode?name=slow&delay=20&bps=20000&repo=drill/cold"
  t0=$(now)
  echo "$t0" > "$out/storm-start"
  say "storm: 6 callers on drill/hot (429), 24 on 12 slow drill/cold images, up to $minutes min"
  storm_start "hot-$run" --images "localhost:5000/drill/hot:$run" --runtime gvisor --concurrency 6 --pause 1 --delete --duration $(( minutes * 60 ))
  storm_start "cold-$run" --images $cold --runtime gvisor --concurrency 24 --pause 1 --delete --duration $(( minutes * 60 ))
  prom wait SandboxdImagePullQueueBacklog SandboxdImagePullBackoffRejects SandboxdImagePullErrors \
    --state firing --timeout $(( minutes * 60 )) > "$out/fired.jsonl" || true
  t1=$(now)
  # What the runbook's first checks show on Kubernetes (no journalctl, no
  # curl in the agent image): the agent logs and the scraped metrics.
  local pod
  : > "$out/runbook-first-checks.txt"
  for pod in $(kc -n "$workers" get pods -l app.kubernetes.io/component=worker -o jsonpath='{.items[*].metadata.name}'); do
    kc -n "$workers" logs "$pod" -c agent --since=30m 2>/dev/null > "$out/agent-$pod.log" || true
    # The runbook's grep before and after issue #1343: containerd's backoff
    # refusals and header timeouts matched neither "pull image" nor "rate".
    echo "$pod: of $(grep -ciE 'image pull|resolve reference' "$out/agent-$pod.log" || true) pull failure lines, the old runbook grep matches $(grep -ciE 'pull image|images/create|manifest|unauthorized|too many requests|rate' "$out/agent-$pod.log" || true), the new $(grep -ciE 'pull image|image pull|images/create|resolve reference|manifest|backing off|awaiting response headers|unauthorized|too many requests|rate' "$out/agent-$pod.log" || true)" >> "$out/runbook-first-checks.txt"
  done
  prom query 'sum by (pod) (aerolvm_image_pull_queued)' >> "$out/runbook-first-checks.txt"
  prom query 'sum by (pod, key) (aerolvm_image_pull_errors_total)' >> "$out/runbook-first-checks.txt"
  prom query 'sum by (pod, key) (aerolvm_create_errors_total)' >> "$out/runbook-first-checks.txt"
  docker logs --since "$(iso "$t0")" drills-faultproxy 2>/dev/null | grep '"path"' > "$out/registry-storm.jsonl" || true

  r="$(sum fired "$out/fired.jsonl" "$t0")"
  echo "$r" > "$out/fired-summary.json"
  if [[ "$(jf "$r" 'sum(1 for v in d.values() if v["state"] == "firing")')" == 3 ]]; then
    result PASS pull-alerts "fired after the storm began: $(sum firedline "$out/fired.jsonl" "$t0")"
  else
    result FAIL pull-alerts "not all 3 fired within $minutes min: $r"
  fi
  # Backoff: the registry sees each worker try the rate-limited image at
  # most once per backoff window, however often the callers create.
  local hot gap
  storm_fetch "hot-$run" "$out" > /dev/null
  hot="$(sum storm "$out/hot-$run.jsonl")"
  r="$(sum backoff "$out/registry-storm.jsonl" drill/hot)"
  echo "$r" > "$out/backoff-registry.json"
  gap="$(jf "$r" 'd["min_gap_s"] or 0')"
  if python3 -c "import sys; sys.exit(0 if float('$gap') >= $backoff_s - 1 else 1)" && [[ "$(jf "$hot" 'd["creates"]')" -gt 0 ]]; then
    result PASS pull-backoff "$(jf "$hot" 'd["creates"]') creates of the 429 image; the registry saw $(jf "$r" 'd["attempts"]') pull attempts from $(jf "$r" 'd["workers"]') workers, never two from one worker within $gap s (median $(jf "$r" 'd["median_gap_s"]') s; backoff ${backoff_s}s); creates answered $(jf "$hot" 'd["by_outcome"]')"
  else
    result FAIL pull-backoff "attempts on the 429 image closer than the ${backoff_s}s backoff: $r; creates: $hot"
  fi
  # The queue: never more pulls at once on one worker than the cap.
  local maxinf maxq
  maxinf="$(prom query "max_over_time(max(aerolvm_image_pull_inflight{aerolvm_component=\"worker\"})[$(( (t1 - t0) / 60 + 1 ))m:30s])" | awk '{print $NF}')"
  maxq="$(prom query "max_over_time(sum(aerolvm_image_pull_queued)[$(( (t1 - t0) / 60 + 1 ))m:30s])" | awk '{print $NF}')"
  if [[ "${maxinf%.*}" -le "$pull_cap" && "${maxinf%.*}" -gt 0 && "${maxq%.*}" -gt 0 ]]; then
    result PASS pull-queue "at most ${maxinf%.*} pulls at once on one worker (cap $pull_cap); up to ${maxq%.*} queued behind the cap across the workers"
  else
    result FAIL pull-queue "most pulls at once on a worker: $maxinf (cap $pull_cap); most queued: $maxq"
  fi
  storm_fetch "cold-$run" "$out" > /dev/null || true
  sum storm "$out/cold-$run.jsonl" > "$out/cold-summary.json" || true

  # 3. setup/runbooks/image-pull-storm.md: contain (pause the callers),
  #    fix the registry, wait out the backoff, a known-good create, then
  #    the recovery checks, held for DRILL_HOLD_MINUTES.
  say "recover: callers paused, registry healthy, backoff left to expire"
  local tr code tclear
  storm_stop "hot-$run"; storm_stop "cold-$run"
  proxy mode/clear
  tr=$(now)
  echo "$tr" > "$out/recover-start"
  sleep $(( backoff_s + 5 ))
  code="$(smoke "localhost:5000/drill/hot:$run")"
  cleanup_run "hot-$run"; cleanup_run "cold-$run"
  prom wait SandboxdImagePullQueueBacklog SandboxdImagePullBackoffRejects SandboxdImagePullErrors \
    --state inactive --timeout 1200 > "$out/resolved.jsonl" || true
  tclear=$(now)
  local held ok_since="" _ q e b
  : > "$out/hold.txt"
  for _ in $(seq 1 $(( (hold_min + 15) * 2 ))); do
    q="$(val 'sum(aerolvm_image_pull_queued)')"
    e="$(val 'sum(rate(aerolvm_image_pull_errors_total[5m]))')"
    b="$(val 'sum(rate(aerolvm_image_pull_backoff_rejects_total[5m]))')"
    echo "$(now) queued=$q errors_5m=$e backoff_rejects_5m=$b" >> "$out/hold.txt"
    if python3 -c "import sys; sys.exit(0 if float('$q') == 0 and float('$e') < 0.01 and float('$b') == 0 else 1)"; then
      [[ -n "$ok_since" ]] || ok_since=$(now)
      (( $(now) - ok_since >= hold_min * 60 )) && break
    else
      ok_since=""
    fi
    sleep 30
  done
  held=0
  [[ -n "$ok_since" ]] && (( $(now) - ok_since >= hold_min * 60 )) && held=1
  r="$(sum fired "$out/resolved.jsonl" "$tr")"
  if [[ "$code" == 201 && "$(jf "$r" 'sum(1 for v in d.values() if v["state"] == "inactive")')" == 3 && "$held" == 1 ]]; then
    result PASS pull-recover "a create of the image that had been failing answered $code once the backoff ran out; resolved after the fix: $(sum firedline "$out/resolved.jsonl" "$tr"); then queue 0, pull errors and backoff rejects 0 for $hold_min min ($out/hold.txt)"
  else
    result FAIL pull-recover "create after the fix: $code; resolved: $r; the $hold_min min hold held=$held ($out/hold.txt)"
  fi
  watch_stop
}

# wait_received <since-unix> <path> <status> <alert...>: wait (up to 4 min)
# until the echo receiver logged each alert at that path and status. A
# drill that mitigates the moment an alert fires can end it inside
# Alertmanager's group_wait, and then no notice is sent at all (the first
# run's SandboxdNoAdmitWorkers lived 37 s and never reached its receiver).
wait_received() {
  local since="$1" path="$2" status="$3" _; shift 3
  for _ in $(seq 1 48); do
    if kc -n monitoring logs deploy/alert-echo --since-time="$(iso "$since")" 2>/dev/null | python3 -c '
import json, sys
path, status, want = sys.argv[1], sys.argv[2], set(sys.argv[3:])
got = set()
for l in sys.stdin:
    try:
        e = json.loads(l)
    except ValueError:
        continue
    if e.get("path") == path and e.get("status") == status:
        got.add(e.get("alertname"))
sys.exit(0 if want <= got else 1)' "$path" "$status" "$@"; then
      return 0
    fi
    sleep 5
  done
  return 1
}

# --- slo-breach --------------------------------------------------------------------
# caddy_admin <gateway pod> <admin port> <path> [json body]: one call to
# Caddy's admin API inside the pod, over a port-forward.
caddy_admin() {
  local pod="$1" from="$2" path="$3" body="${4:-}" k
  kubectl --context "$ctx" -n "$ns" port-forward "pod/$pod" "12019:$from" >/dev/null 2>&1 &
  k=$!
  # A fixed 3 s was too short once on a new gateway pod: the call got no
  # answer (000) and Caddy was never moved. Wait for the admin API.
  local _
  for _ in $(seq 1 20); do
    curl -s -m 2 -o /dev/null -H "Host: localhost:$from" "http://127.0.0.1:12019/config/admin" && break
    sleep 1
  done
  curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -X POST -H "Host: localhost:$from" -H 'Content-Type: application/json' \
    ${body:+-d "$body"} "http://127.0.0.1:12019$path" 2>/dev/null || true
  kill "$k" 2>/dev/null || true
  wait "$k" 2>/dev/null || true
}
step_slo_breach() {
  keep_forward monitoring svc/kube-prometheus-stack-prometheus "$prom_port" 9090 /-/healthy
  local out="$sd/evidence/slo-breach" run t0 gw r minutes="${DRILL_SLO_MINUTES:-20}"
  mkdir -p "$out"
  run="$(date +%m%d%H%M%S)"
  echo "$run" > "$out/run"
  push_images "$run"
  forwarders
  watch_start "$out"
  proxy mode/clear
  t0=$(now)
  echo "$t0" > "$out/start"

  # A. Backlog, errors and route lag together.
  gw="$(kc -n "$ns" get pods -l app.kubernetes.io/component=gateway -o jsonpath='{.items[0].metadata.name}')"
  echo "$gw" > "$out/gateway"
  say "slo A: 130 creates on a crawling registry, 6 on a 429 image, Caddy's admin moved off :2019 on $gw, public sandboxes churning"
  # The registry answers at once, then sends 2 kB/s: a 4 MB layer outlasts
  # the create's 600 s, so the creates stay in flight. (A registry that
  # answers nothing fails each pull after containerd's 30 s.)
  proxy "mode?name=slow&delay=1&bps=2000&repo=drill/hang"
  proxy "mode?name=ratelimit&repo=drill/hot"
  echo "move admin: $(caddy_admin "$gw" 2019 /config/admin/listen '"localhost:2020"')" > "$out/caddy-admin.txt"
  storm_start "hang-$run" --images "localhost:5000/drill/hang:$run" --runtime gvisor --cpu 0.05 --memory-mb 64 \
    --concurrency 130 --pause 1 --delete --client-timeout 700 --duration $(( minutes * 60 ))
  storm_start "err-$run" --images "localhost:5000/drill/hot:$run" --runtime gvisor --concurrency 6 --pause 1 --delete --duration $(( minutes * 60 ))
  storm_start "pub-$run" --images localhost:5000/drill/app:v1 --runtime gvisor --public --concurrency 2 --pause 2 --delete --duration $(( minutes * 60 ))
  prom wait SandboxdCreateQueueBacklog SandboxdCreateErrors SandboxdIngressRouteLag \
    --state firing --timeout $(( minutes * 60 )) > "$out/fired-a.jsonl" || true
  wait_received "$t0" /sandboxd firing SandboxdCreateQueueBacklog SandboxdCreateErrors SandboxdIngressRouteLag || true

  # setup/runbooks/slo-breach.md, first five minutes: the evidence, then
  # the branch. Image-pull metrics are high, so the image-pull runbook's
  # containment: pause the callers, fix the registry. Route lag with
  # Caddy's admin calls failing and nothing converging: restart Caddy. On
  # Kubernetes Caddy is the gateway pod's edge container, and the way to
  # restart it is to delete the pod: the operator starts another.
  local tr gw_new
  tr=$(now)
  echo "$tr" > "$out/mitigate-a"
  api GET /v1/cluster/leader > "$out/leader.json" || true
  api GET /v1/cluster/members > "$out/members.json" || true
  {
    prom query 'sum by (aerolvm_component) (aerolvm_create_queue_depth)'
    prom query 'sum by (key) (rate(aerolvm_create_errors_total[5m]))'
    prom query 'max by (pod) (aerolvm_ingress_route_lag_versions{aerolvm_component="gateway"})'
    prom query 'sum by (pod) (aerolvm_ingress_reconcile_errors_total)'
    prom query 'sum(aerolvm_image_pull_queued)'
  } > "$out/first-five.txt"
  kc -n "$ns" logs "$gw" -c agent --since=30m > "$out/gateway-agent.log" 2>/dev/null || true
  kc -n "$ns" logs "$gw" -c edge --since=30m > "$out/gateway-edge.log" 2>/dev/null || true
  say "slo A mitigation: callers paused, registry fixed, gateway $gw deleted (Caddy restart)"
  storm_stop "hang-$run"; storm_stop "err-$run"; storm_stop "pub-$run"
  proxy mode/clear
  kc -n "$ns" delete pod "$gw" --wait=false >/dev/null
  local _
  for _ in $(seq 1 60); do
    gw_new="$(kc -n "$ns" get pods -l app.kubernetes.io/component=gateway --field-selector=status.phase=Running -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.containerStatuses[*].ready}{"\n"}{end}' | grep -v "^$gw " | grep -c "true true$" || true)"
    [[ "$gw_new" -ge 3 ]] && break
    sleep 5
  done
  kc -n "$ns" get pods -l app.kubernetes.io/component=gateway -o wide > "$out/gateways-after.txt"
  local s
  for s in hang err pub; do
    storm_fetch "$s-$run" "$out" > /dev/null || true
    sum storm "$out/$s-$run.jsonl" > "$out/$s-summary.json" || true
    cleanup_run "$s-$run"
  done

  # B. No worker can admit: fill every worker's CPU, largest first.
  say "slo B: filling every worker"
  # A size is done after two refusals in a row: one transient error (a
  # gateway just replaced) must not leave a worker with a CPU to spare.
  local size n=0 code refused
  : > "$out/fill.txt"
  for size in 8 4 2 1; do
    refused=0
    for _ in $(seq 1 14); do
      code="$(api POST /v1/sandboxes "{\"image\": \"localhost:5000/drill/app:v1\", \"runtime\": \"gvisor\", \"cpu\": $size, \"memory_mb\": 128, \"tags\": {\"drill-run\": \"fill-$run\"}}" | tee -a "$out/fill.txt" | python3 -c 'import json,sys; print(json.load(sys.stdin)["code"])')"
      if [[ "$code" == 201 ]]; then
        n=$((n + 1)) refused=0
      else
        refused=$((refused + 1))
        [[ "$refused" -ge 2 ]] && break
      fi
    done
  done
  # Placement can refuse the last CPU on a worker for a moment after the
  # creates before it (its view of the worker trails them), which stopped
  # the first run's fill one CPU short with that worker still admitting.
  # Top up until every worker says it has no room, one CPU at a time: the
  # second run needed 14 (placement refused the first 1-CPU creates for a
  # moment), more than a budget of 12.
  local admitting
  for _ in $(seq 1 40); do
    admitting="$(api GET /v1/cluster/members | python3 -c '
import json, sys
d = json.load(sys.stdin)["body"] or {}
print(sum(1 for m in d.get("members", []) if "worker" in (m.get("role") or "") and (m.get("capacity") or {}).get("can_admit")))')"
    [[ "$admitting" == 0 ]] && break
    code="$(api POST /v1/sandboxes "{\"image\": \"localhost:5000/drill/app:v1\", \"runtime\": \"gvisor\", \"cpu\": 1, \"memory_mb\": 128, \"tags\": {\"drill-run\": \"fill-$run\"}}" | tee -a "$out/fill.txt" | python3 -c 'import json,sys; print(json.load(sys.stdin)["code"])')"
    [[ "$code" == 201 ]] && n=$((n + 1))
    sleep 5
  done
  say "slo B: $n fillers placed; workers still admitting: $admitting"
  local tb
  tb=$(now)
  echo "$tb" > "$out/fill-done"
  prom wait SandboxdNoAdmitWorkers --state firing --timeout 900 > "$out/fired-b.jsonl" || true
  wait_received "$tb" /sandboxd-critical firing SandboxdNoAdmitWorkers || true
  # The runbook: "Check capacity, disk, and drains". The members show no
  # free CPU on any worker and nothing drained; the fix is room (on a cell,
  # more workers; here the fillers go).
  api GET /v1/cluster/members > "$out/members-full.json" || true
  echo "$(now)" > "$out/mitigate-b"
  cleanup_run "fill-$run"

  prom wait SandboxdCreateQueueBacklog SandboxdCreateErrors SandboxdIngressRouteLag SandboxdNoAdmitWorkers \
    --state inactive --timeout 1500 > "$out/resolved.jsonl" || true
  # Alertmanager sends a resolved notice at the group's next
  # group_interval (5m in the example).
  sleep 330
  local smoke_code
  smoke_code="$(smoke)"
  kc -n monitoring logs deploy/alert-echo --since-time="$(iso "$t0")" > "$out/receiver.jsonl" 2>/dev/null || true
  watch_stop

  r="$( { cat "$out/fired-a.jsonl"; cat "$out/fired-b.jsonl"; } > "$out/fired.jsonl"; sum fired "$out/fired.jsonl" "$t0")"
  echo "$r" > "$out/fired-summary.json"
  if [[ "$(jf "$r" 'sum(1 for v in d.values() if v["state"] == "firing")')" == 4 ]]; then
    result PASS slo-alerts "fired: $(sum firedline "$out/fired.jsonl" "$t0") (NoAdmitWorkers after the fill, which ended $(( (tb - t0) / 60 )) min in)"
  else
    result FAIL slo-alerts "not all 4 fired: $r"
  fi
  local routing
  routing="$(sum routing "$out/receiver.jsonl" SandboxdCreateQueueBacklog=/sandboxd SandboxdCreateErrors=/sandboxd \
    SandboxdIngressRouteLag=/sandboxd SandboxdNoAdmitWorkers=/sandboxd-critical)"
  echo "$routing" > "$out/routing.json"
  if [[ "$(jf "$routing" 'len(d["firing"]) == 4 and not d["wrong_route"]')" == True ]]; then
    result PASS slo-routing "each reached its receiver: the warnings at /sandboxd, SandboxdNoAdmitWorkers (critical) at /sandboxd-critical ($routing)"
  else
    result FAIL slo-routing "$routing"
  fi
  r="$(sum fired "$out/resolved.jsonl" "$tr")"
  if [[ "$(jf "$r" 'sum(1 for v in d.values() if v["state"] == "inactive")')" == 4 && "$smoke_code" == 201 && \
        "$(jf "$routing" 'len(d["resolved"])')" == 4 ]]; then
    result PASS slo-recover "after the runbook's steps all 4 resolved ($(sum firedline "$out/resolved.jsonl" "$tr") from the first mitigation) and the receiver got each resolved notice; $gw replaced ($gw_new gateways ready after); smoke create+delete $smoke_code"
  else
    result FAIL slo-recover "resolved: $r; receiver: $routing; smoke $smoke_code; gateways ready after replacing $gw: $gw_new"
  fi
}

# --- teardown ----------------------------------------------------------------------
step_teardown() {
  docker logs drills-faultproxy > "$sd/evidence/registry-all.jsonl" 2>/dev/null || true
  docker rm -f drills-faultproxy drills-registry >/dev/null 2>&1 || true
  say "registry and proxy removed; the kind cluster: AEROL_KIND_CLUSTER=$kind_cluster scripts/k8s-dev.sh down"
}

for step in "$@"; do
  case "$step" in
    setup) step_setup ;;
    static) step_static ;;
    pull-storm) step_pull_storm ;;
    slo-breach) step_slo_breach ;;
    teardown) step_teardown ;;
    *) echo "drills-local.sh: unknown step $step" >&2; exit 2 ;;
  esac
done

#!/usr/bin/env bash
# drills-local.sh: the image-pull storm and SLO-breach drills (issue #1343)
# on a local kind cluster in cluster mode. No cloud: the registry and its
# faults, Prometheus, Alertmanager and the alert receiver run on this
# machine.
#
#   AEROL_K8S_MODE=cluster AEROL_KIND_CLUSTER=aerolvm-drills AEROL_K8S_EDGE=1 \
#     AEROL_K8S_IDENTITY=1 HELM=<helm 3.8 or later> scripts/k8s-dev.sh
#   KUBECTL_CONTEXT=kind-aerolvm-drills HELM=<helm> \
#     integration-tests/k8s/drills-local.sh <state-dir> setup static pull-storm slo-breach
#   integration-tests/k8s/drills-local.sh <state-dir> teardown
#
# It refuses any kubectl context but a local kind cluster's (kind-<name>,
# listed by kind get clusters), whatever the step: the steps delete pods,
# fill workers and break a gateway's Caddy. If a step dies midway, the EXIT
# trap clears the registry's faults, stops the callers and puts Caddy's
# admin API back on its port.
#
# Needs Docker, kind, kubectl, Helm and python3 on this machine. Steps (each
# prints PASS or FAIL lines into <state-dir>/drills.txt):
#   setup       a registry:2 behind a fault proxy (drills-local/faultproxy.py)
#               on the kind Docker network, the drill images pushed to it;
#               kube-prometheus-stack (pinned) with Alertmanager routed as
#               setup/alertmanager/sandboxd-alertmanager-example.yml says, to
#               an echo receiver; the bank-like values (drills-local/
#               values-bank-kind.yaml) over the install, with a viewer token
#               on every team as Prometheus's scrape token; the sandboxd alerts
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
# Every step deletes pods, fills workers and breaks a gateway's Caddy: only
# ever on a local kind cluster, whatever step was asked for.
if [[ "$ctx" != kind-* ]] || ! kind get clusters 2>/dev/null | grep -qx "$kind_cluster"; then
  echo "drills-local.sh: refusing to run against context \"$ctx\": only a local kind cluster (kind-<name>, listed by kind get clusters)" >&2
  exit 2
fi
# --- the kind cluster's registry ----------------------------------------------
# A registry:2 and the fault proxy as Docker containers on the kind network;
# the worker pods reach them as localhost:5000 through a forwarder (fwd.py).
reg_port="${DRILL_REGISTRY_PORT:-15000}"
ctl_port="${DRILL_PROXY_CONTROL_PORT:-15001}"
ctl_url="http://127.0.0.1:$ctl_port"
drill_reg=localhost:5000
client_image=python:3.12-slim
client_pull=Never
client_mounts=""
client_volumes=""
registry_where=""

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
  push_tags "${tags[@]}" >/dev/null
  say "images pushed for run $run"
}

# push_tags <tag>...: fresh images over drill/app:v1 in the local registry.
push_tags() { python3 "$L/push.py" --registry "http://127.0.0.1:$reg_port" --base drill/app:v1 "$@"; }

# registry_log <since-unix>: the fault proxy's request lines since then.
registry_log() { docker logs --since "$(iso "$1")" drills-faultproxy 2>/dev/null | grep '"path"'; }

setup_registry() {
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
  kind load docker-image --name "$kind_cluster" python:3.12-slim >/dev/null
  registry_where="$pip"
}

# The bank-like values, and the registry's address let out of the worker
# pods, as a bank adds its own registry's range.
setup_values() {
  local pip
  pip="$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' drills-faultproxy)"
  hm upgrade "$release" "$ROOT/charts/aerolvm" -n "$ns" --reuse-values -f "$L/values-bank-kind.yaml" \
    --set-json "networkPolicy.extraEgressCIDRs=[\"$pip/32\"]" >/dev/null
}

# The admin token: kind runs without enterprise mode, where it works from
# the client pod.
setup_token() {
  ( umask 077; kc -n "$ns" get secret "$cluster_name-admin" -o jsonpath='{.data.token}' | base64 -d > "$sd/token" )
}

# --- teardown ----------------------------------------------------------------------
step_teardown() {
  docker logs drills-faultproxy > "$sd/evidence/registry-all.jsonl" 2>/dev/null || true
  docker rm -f drills-faultproxy drills-registry >/dev/null 2>&1 || true
  say "registry and proxy removed; the kind cluster: AEROL_KIND_CLUSTER=$kind_cluster scripts/k8s-dev.sh down"
}

drills_step() {
  case "$1" in
    teardown) step_teardown ;;
    *) return 127 ;;
  esac
}

# shellcheck source=drills-lib.sh
source "$HERE/drills-lib.sh"
drills_main drills-local.sh "$@"

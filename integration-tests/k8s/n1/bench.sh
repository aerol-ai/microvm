#!/bin/bash
# bench.sh: N1's measurements, run inside the cluster (pod n1-bench) so both
# systems are timed from the same place. Prints "N1 ..." lines.
#   bench.sh as-cold|as-warm|as-burst|av-cold|av-warm|av-burst [n]
set -uo pipefail
phase="$1"; n="${2:-10}"
now() { date +%s%3N; }
[[ -x /usr/local/bin/kubectl ]] || {
  dnf -y -q install jq findutils >/dev/null 2>&1
  curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
  chmod +x /usr/local/bin/kubectl
}
k() { kubectl -n n1 "$@"; }

# Writes to the Kubernetes API during a phase: every ADDED/MODIFIED/DELETED
# event a watch sees is one write (etcd) of that object.
watch_start() {
  rm -f /tmp/w.*
  local r
  for r in "$@"; do
    kubectl get "$r" -A --watch-only --output-watch-events -o name > "/tmp/w.${r//\//_}" 2>/dev/null &
  done
  sleep 3
}
watch_stop() {
  sleep 3
  kill $(jobs -p) 2>/dev/null; wait 2>/dev/null
  local total=0 f c
  for f in /tmp/w.*; do c=$(wc -l < "$f"); total=$((total + c)); echo "N1 $phase writes ${f#/tmp/w.}: $c"; done
  echo "N1 $phase writes total: $total"
}

sandbox_yaml() {
  cat <<Y
apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata: { name: $1, namespace: n1 }
spec:
  podTemplate:
    spec:
      runtimeClassName: gvisor
      containers:
        - name: sandbox
          image: alpine:3.20
          command: ["sleep", "infinity"]
          resources:
            requests: { cpu: 100m, memory: 64Mi }
            limits: { cpu: 100m, memory: 64Mi }
Y
}
claim_yaml() {
  cat <<Y
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxClaim
metadata: { name: $1, namespace: n1, labels: { n1: "$2" } }
spec:
  warmPoolRef: { name: n1-pool }
Y
}
pool_ready() {
  local want="$1" r
  for _ in $(seq 1 120); do
    r="$(k get sandboxwarmpool n1-pool -o jsonpath='{.status.readyReplicas}' 2>/dev/null)"
    [[ "${r:-0}" -ge "$want" ]] && return 0
    sleep 2
  done
  echo "N1 $phase warning: pool not ready ($r of $want)"
}
av() {
  local route="$1"; shift
  curl -fsS --max-time 120 -H "Authorization: Bearer $AV_TOKEN" -H 'Content-Type: application/json' "$AV_URL$route" "$@"
}
av_create() { av /v1/sandboxes -X POST -d '{"image":"alpine:3.20","runtime":"gvisor","cpu":0.1,"memory_mb":64}' | jq -r '.id // empty'; }

case "$phase" in
  as-cold)
    sandbox_yaml n1-prime | k apply -f - >/dev/null; k wait --for=condition=Ready sandbox/n1-prime --timeout=300s >/dev/null; k delete sandbox n1-prime --wait=false >/dev/null
    watch_start sandboxes.agents.x-k8s.io pods events
    for i in $(seq 1 "$n"); do
      t0=$(now); sandbox_yaml "n1-cold-$i" | k apply -f - >/dev/null
      k wait --for=condition=Ready "sandbox/n1-cold-$i" --timeout=300s >/dev/null && t1=$(now) || t1=0
      echo "N1 as-cold $i: $(( t1 > 0 ? t1 - t0 : -1 )) ms"
      k delete sandbox "n1-cold-$i" --wait=false >/dev/null
    done
    watch_stop ;;
  as-warm)
    for i in $(seq 1 "$n"); do
      pool_ready 5
      t0=$(now); claim_yaml "n1-warm-$i" warm | k apply -f - >/dev/null
      k wait --for=condition=Ready "sandboxclaim/n1-warm-$i" --timeout=300s >/dev/null && t1=$(now) || t1=0
      echo "N1 as-warm $i: $(( t1 > 0 ? t1 - t0 : -1 )) ms"
    done
    k delete sandboxclaim -l n1=warm --wait=false >/dev/null ;;
  as-burst)
    pool_ready 5
    t0=$(now)
    for i in $(seq 1 "$n"); do claim_yaml "n1-burst-$i" burst; echo ---; done | k apply -f - >/dev/null
    k wait --for=condition=Ready sandboxclaim -l n1=burst --timeout=600s >/dev/null; t1=$(now)
    echo "N1 as-burst all $n ready in $(( t1 - t0 )) ms (pool of 5)"
    k get sandboxclaim -l n1=burst -o json | jq -r '.items[] | ((.status.conditions[]? | select(.type=="Ready") | .lastTransitionTime | fromdate) - (.metadata.creationTimestamp | fromdate))' | sort -n | awk '{a[NR]=$1} END {print "N1 as-burst per-claim seconds: min " a[1] " p50 " a[int(NR/2)+1] " max " a[NR]}'
    k delete sandboxclaim -l n1=burst --wait=false >/dev/null ;;
  av-cold|av-warm)
    id="$(av_create)"; [[ -n "$id" ]] && av "/v1/sandboxes/$id" -X DELETE >/dev/null
    [[ "$phase" == av-warm ]] && sleep 20
    [[ "$phase" == av-cold ]] && watch_start pods events
    for i in $(seq 1 "$n"); do
      t0=$(now); id="$(av_create)"; t1=$(now)
      echo "N1 $phase $i: $([[ -n "$id" ]] && echo $(( t1 - t0 )) || echo -1) ms"
      [[ -n "$id" ]] && av "/v1/sandboxes/$id" -X DELETE >/dev/null
      [[ "$phase" == av-warm ]] && sleep 5
    done
    [[ "$phase" == av-cold ]] && watch_stop ;;
  av-burst)
    sleep 20
    t0=$(now)
    seq 1 "$n" | xargs -P "$n" -I{} bash -c 'a=$(date +%s%3N); curl -fsS --max-time 120 -o /dev/null -H "Authorization: Bearer $AV_TOKEN" -H "Content-Type: application/json" -d "{\"image\":\"alpine:3.20\",\"runtime\":\"gvisor\",\"cpu\":0.1,\"memory_mb\":64}" "$AV_URL/v1/sandboxes" && echo $(( $(date +%s%3N) - a ))' > /tmp/burst.txt
    t1=$(now)
    sort -n /tmp/burst.txt | awk -v n="$n" -v tot=$(( t1 - t0 )) '{a[NR]=$1} END {print "N1 av-burst " NR " of " n " created in " tot " ms; per create ms: min " a[1] " p50 " a[int(NR/2)+1] " max " a[NR]}' ;;
esac

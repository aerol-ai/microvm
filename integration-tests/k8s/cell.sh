#!/usr/bin/env bash
# cell.sh: the Phase 2 exit gate on EKS (plans/kubernetes-v2-architecture.md
# §18, §19): a three-zone cell in cluster mode, its chaos step, and the full
# `aerolvm k8s verify`.
#
#   cell.sh <name> [up|build|build2|install|preflight|chaos|verify|drills [drill...]|down|all]
#
# up        EKS over three zones: 3 system nodes with 4 CPUs (servers,
#           gateways, operator; on 2-CPU nodes their requests and the
#           cluster's own pods come within 0.3 CPU of full, and p2-sig-2
#           had a server Pending), 3 worker machines with IMDSv2 and a hop
#           limit of 1, the EBS CSI driver, the VPC CNI enforcing
#           NetworkPolicies, and ECR repositories for this run.
# build     The commit's source (~12 MB) to S3; Go and BuildKit build the
#           images inside the cluster and push them to ECR. No binary or
#           image crosses this machine's uplink.
# install   cert-manager, a gp3 class, the namespace labels, the chart in
#           cluster mode (cell/values.yaml).
# preflight Workers first fail their preflight on br_netfilter (stock
#           AL2023, finding F2), with the reason on their AerolNode; then
#           the module is loaded and they join on the kubelet's next try.
# chaos     50 concurrent creates; meanwhile the Raft leader's pod and one
#           worker pod are deleted. Passes with zero lost creates, zero
#           duplicates and every recreate sandbox back.
# verify    aerolvm k8s verify, every rule (signatures skipped: dev images).
# build2    the same commit's images as <tag>.2: a second version to upgrade
#           to, for the rollout drill.
# drills    drills.sh's Phase 3 drills (§19) on this cell, or the named ones.
# down      cluster.sh down.
#
# The images, the chart and the aerolvm CLI all come from one commit (HEAD,
# or AEROL_BUILD_REF), copied out with git archive, never from the working
# tree; the harness scripts stay this checkout's. AEROL_RELEASE=vX.Y.Z tests
# a published release instead: its signed images from ghcr.io (build does
# nothing), its chart and CLI from its tag, and verify checks the images'
# signatures. The report goes to
# .state/<name>/cell-report.txt.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
name="${1:?usage: cell.sh <name> [up|build|install|preflight|chaos|verify|down|all]}"
step="${2:-all}"
HELM="${HELM:-helm}"
# verify checks a release's image signatures with cosign: without it the run
# makes a cluster only to fail at its last step.
if [[ -n "${AEROL_RELEASE:-}" && "$step" != down ]] && ! command -v cosign >/dev/null; then
  echo "cell.sh: AEROL_RELEASE needs cosign on PATH for verify's signature check" >&2
  exit 2
fi
# The same cert-manager as `make k8s-dev`, checked by its digest.
CERT_MANAGER_VERSION=v1.21.3
CERT_MANAGER_SHA256=c04a51295adda2b1a775146751f973e787190778c7f35180861d9678876e5c74

up() {
  # A release's images come from ghcr.io: no ECR repositories for it.
  local ecr=(--ecr aerolvm,aerolvm-runtime,aerolvm-operator)
  [[ -n "${AEROL_RELEASE:-}" ]] && ecr=()
  "$HERE/cluster.sh" up "$name" --ttl "${AEROL_TTL:-4h}" --zones 3 --system 3 --system-type m7i.xlarge \
    --workers 3 --type m7i.xlarge --imds-hop-limit 1 --ebs-csi --network-policy \
    ${ecr[@]+"${ecr[@]}"}
}

if [[ "$step" == up || "$step" == all ]]; then up; fi
if [[ "$step" == down ]]; then
  # The commit's source copy (lib.sh source_tree) goes too: left in .state
  # it holds every script of that commit, and the safety tests, which walk
  # integration-tests/, then fail on the copies.
  rm -rf "$HERE/.state/$name"/src-*
  exec "$HERE/cluster.sh" down "$name"
fi

# shellcheck source=lib.sh
source "$HERE/lib.sh"
lib_init "$name" cell-report.txt
exec > >(tee -a "$sd/cell-console.log") 2>&1
# Terraform's plugins are per run, as cluster.sh keeps them.
tfout() { TF_DATA_DIR="$sd/.terraform" terraform -chdir="$LIB_DIR/terraform" output -state="$sd/terraform.tfstate" "$@"; }
region="$(tfout -raw region)"
if [[ -n "${AEROL_RELEASE:-}" ]]; then
  registry=ghcr.io/aerol-ai
  sha="$(git -C "$LIB_ROOT" rev-parse "$AEROL_RELEASE^{commit}")"
  tag="$AEROL_RELEASE"
else
  registry="$(tfout -raw ecr_registry)"
  sha="$(git -C "$LIB_ROOT" rev-parse "${AEROL_BUILD_REF:-HEAD}^{commit}")"
  tag="v0.0.0-cell.${sha:0:8}"
fi
ns=aerolvm-system
workers=aerolvm-workers

# build [tag short]: the commit's images as tag (default $tag), by a Job
# named images-<short>. build2 builds the same commit as $tag.2, a second
# version for the rollout drills.
build() {
  if [[ -n "${AEROL_RELEASE:-}" ]]; then
    say "build: none, $AEROL_RELEASE's published images"
    return 0
  fi
  local tag="${1:-$tag}" short="${2:-${sha:0:8}}"
  local key url t0
  t0=$(date +%s)
  artifact_bucket
  key="k8s-cell/$sha.tar.gz"
  if ! aws s3api head-object --region "$bucket_region" --bucket "$bucket" --key "$key" >/dev/null 2>&1; then
    git -C "$LIB_ROOT" archive --format=tar.gz "$sha" | aws s3 cp --region "$bucket_region" - "s3://$bucket/$key" >/dev/null
  fi
  url="$(aws s3 presign "s3://$bucket/$key" --expires-in 21600 --region "$bucket_region")"
  say "build: $sha as $tag, source $(aws s3api head-object --region "$bucket_region" --bucket "$bucket" --key "$key" --query ContentLength --output text) bytes"
  kubectl create namespace aerolvm-build --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  # ECR's push token (12 hours), for BuildKit only, in the build namespace.
  kubectl -n aerolvm-build create secret docker-registry ecr-push --docker-server="${registry%%/*}" \
    --docker-username=AWS --docker-password="$(aws ecr get-login-password --region "$region")" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  # In a sed replacement & means "what matched": the presigned URL's own
  # & signs must be escaped, or S3 refuses the mangled URL with 400.
  sed -e "s|@@SOURCE_URL@@|${url//&/\\&}|" -e "s|@@REGISTRY@@|$registry|g" -e "s|@@TAG@@|$tag|g" \
    -e "s|@@SHA@@|$sha|g" -e "s|@@SHORT@@|$short|g" "$HERE/cell/build-job.yaml" | kubectl apply -f - >/dev/null
  local job="job/images-$short" st=""
  for _ in $(seq 1 120); do
    st="$(kubectl -n aerolvm-build get "$job" -o jsonpath='{.status.succeeded}/{.status.failed}')"
    [[ "$st" == 1/* || "$st" == */1 ]] && break
    sleep 15
  done
  kubectl -n aerolvm-build logs "$job" --all-containers --tail=-1 > "$sd/build.log" 2>&1 || true
  if [[ "$st" != 1/* ]]; then
    say "build: FAILED ($st); last lines:"; tail -30 "$sd/build.log" | tee -a "$report"
    return 1
  fi
  say "build: images pushed to $registry in $(( $(date +%s) - t0 ))s"
}

install() {
  local t0 zones
  t0=$(date +%s)
  curl -fsSL -o "$sd/cert-manager.yaml" \
    "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml"
  echo "$CERT_MANAGER_SHA256  $sd/cert-manager.yaml" | shasum -a 256 -c - >/dev/null
  kubectl apply -f "$sd/cert-manager.yaml" >/dev/null
  kubectl -n cert-manager wait --for=condition=Available deployment --all --timeout=5m >/dev/null
  kubectl apply -f - >/dev/null <<'YAML'
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata: { name: gp3 }
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
parameters: { type: gp3 }
YAML
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl label namespace "$ns" pod-security.kubernetes.io/enforce=restricted --overwrite >/dev/null
  zones="$(tfout -json zones | jq -r 'join(", ")')"
  sed -e "s|@@REGISTRY@@|$registry|" -e "s|@@TAG@@|$tag|g" -e "s|@@ZONES@@|$zones|" "$HERE/cell/values.yaml" > "$sd/values.yaml"
  # The chart labels its own pods by zone: the system nodes carry the zone
  # label already (EKS), so servers spread one per zone.
  "$HELM" upgrade --install aerolvm "$(source_tree "$sha")/charts/aerolvm" -n "$ns" -f "$sd/values.yaml" >/dev/null
  say "install: chart $tag in $ns, zones $zones, in $(( $(date +%s) - t0 ))s"
}

# diagnose saves, before the cluster can be torn down, why each AerolNode
# that is not Serving is stuck: the AerolNode, its pod and every container's
# log (init containers too, and the previous run of each), its volume claim,
# and the namespaces' recent events. The second signed-image run (p2-sig-2)
# had a server Pending for 14 minutes and was destroyed with none of this.
# Every command may fail (no pod yet, no previous run) under set -e, so
# each one is allowed to.
diagnose() {
  local d="$sd/diag-$(date +%H%M%S)" n role pns c
  mkdir -p "$d"
  for n in $(kubectl -n "$ns" get aerolnodes -o json 2>/dev/null | jq -r '.items[] | select(.status.state != "Serving") | .metadata.name' || true); do
    role="$(kubectl -n "$ns" get aerolnode "$n" -o jsonpath='{.spec.role}' 2>/dev/null || true)"
    pns="$ns"; [[ "$role" == worker ]] && pns="$workers"
    {
      kubectl -n "$ns" describe aerolnode "$n" || true
      kubectl -n "$pns" describe pod "$n" || true
      kubectl -n "$pns" get pvc -o wide || true
      for c in $(kubectl -n "$pns" get pod "$n" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}' 2>/dev/null || true); do
        echo "--- $c"; kubectl -n "$pns" logs "$n" -c "$c" --tail=200 || true
        echo "--- $c (previous)"; kubectl -n "$pns" logs "$n" -c "$c" --previous --tail=100 || true
      done
    } > "$d/$n.txt" 2>&1
    say "diagnose: $n ($role) is $(kubectl -n "$ns" get aerolnode "$n" -o jsonpath='{.status.state}: {.status.reason}' 2>/dev/null || true); details in $d/$n.txt"
  done
  { kubectl get events -A --sort-by=.lastTimestamp 2>&1 || true; } | tail -80 > "$d/events.txt"
  kubectl -n "$ns" logs deploy/aerolvm-operator --tail=300 > "$d/operator.txt" 2>&1 || true
}

# wait_phase <phase> <seconds>
wait_phase() {
  local p="" i
  for i in $(seq 1 $(( $2 / 5 ))); do
    p="$(kubectl -n "$ns" get aerolcluster aerolvm -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [[ "$p" == "$1" ]] && return 0
    sleep 5
  done
  say "the AerolCluster is ${p:-missing}, not $1, after $2s"
  kubectl -n "$ns" get aerolcluster,aerolnodes | tee -a "$report"
  diagnose
  return 1
}

# wait_workers <n> <seconds>: n workers Serving. The AerolCluster's Ready
# asks only for the servers and a gateway.
wait_workers() {
  local n=0 i
  for i in $(seq 1 $(( $2 / 5 ))); do
    n="$(kubectl -n "$ns" get aerolnodes -l app.kubernetes.io/component=worker -o json |
      jq '[.items[] | select(.status.state == "Serving")] | length')"
    [[ "$n" -ge "$1" ]] && return 0
    sleep 5
  done
  say "$n of $1 workers Serving after $2s"
  kubectl -n "$ns" get aerolnodes | tee -a "$report"
  diagnose
  return 1
}

# sandboxes <run> lists one load run's sandboxes as a JSON array, every
# page: the cluster list pages over all placements and filters each page by
# the tag, so one page holds only part of a run (the third chaos run read
# 28 of 50 from the first page).
sandboxes() {
  python3 "$HERE/cell/load.py" --url http://127.0.0.1:21212 --token-file "$sd/token" --list-run "$1"
}

preflight() {
  local t0 failed reason i
  t0=$(date +%s)
  # Before br_netfilter is loaded every worker must fail its preflight and
  # say why on its AerolNode (P10).
  for i in $(seq 1 60); do
    failed="$(kubectl -n "$ns" get aerolnodes -l app.kubernetes.io/component=worker -o json |
      jq '[.items[] | select(.status.state == "Failed" and (.status.reason // "" | test("br_netfilter")))] | length')"
    [[ "$failed" -ge 1 ]] && break
    [[ "$(kubectl -n "$ns" get aerolnodes -l app.kubernetes.io/component=worker -o json |
      jq '[.items[] | select(.status.state == "Serving")] | length')" -ge 3 ]] && break
    sleep 10
  done
  reason="$(kubectl -n "$ns" get aerolnodes -l app.kubernetes.io/component=worker -o json |
    jq -r '[.items[] | select(.status.state == "Failed") | .status.reason][0] // ""')"
  if [[ "$failed" -lt 1 ]]; then
    # A machine image that loads br_netfilter itself: nothing to fail on.
    if wait_workers 3 60; then
      say "preflight: br_netfilter already loaded on these machines; every worker passed"
      return 0
    fi
    say "preflight: FAIL: no worker failed on br_netfilter, and not all serve"
    return 1
  fi
  say "preflight: $failed worker(s) Failed after $(( $(date +%s) - t0 ))s: $reason"
  load_br_netfilter aerolvm.io/pool=phase0
  wait_phase Ready 600
  wait_workers 3 900
  say "preflight: workers joined $(( $(date +%s) - t0 ))s after the first failure"
  kubectl -n "$ns" get aerolcluster,aerolnodes | tee -a "$report"
}

# gateway_forward keeps one port-forward to the gateways and waits until it
# answers. It restarts only a dead one: the first cell run killed and
# restarted it on every pass of a wait loop, most passes found nothing
# listening yet, and a recovery that took 12 s was reported as 264 s.
gateway_forward() {
  local _
  if [[ -z "${pf:-}" ]] || ! kill -0 "$pf" 2>/dev/null; then
    pkill -f "port-forward svc/aerolvm-gateway 21212" 2>/dev/null || true
    kubectl -n "$ns" port-forward svc/aerolvm-gateway 21212:21212 >/dev/null 2>&1 &
    pf=$!
  fi
  for _ in $(seq 1 30); do
    curl -fsS --max-time 3 -o /dev/null http://127.0.0.1:21212/health 2>/dev/null && return 0
    sleep 1
  done
  return 1
}

# recreate_times prints, from the workers' own logs, how long after the
# chaos each failed-over sandbox was started again on its new owner.
recreate_times() {
  local w
  for w in $(kubectl -n "$workers" get pods -l app.kubernetes.io/component=worker -o jsonpath='{.items[*].metadata.name}'); do
    kubectl -n "$workers" logs "$w" -c agent --since=30m 2>/dev/null | grep "recreated sandbox after failover" |
      sed -E "s/^time=([^ ]+).*sandbox_id=([^ ]+).*/\1 \2 $w/" || true
  done | python3 -c '
import sys, datetime
ch = float(sys.argv[1]); rows = []
for line in sys.stdin:
    t, sid, w = line.split()
    d = datetime.datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp() - ch
    if d >= 0: rows.append((d, w))
rows.sort()
print(f"{len(rows)} recreated on {sorted({w for _, w in rows})}, {rows[0][0]:.1f}-{rows[-1][0]:.1f} s after the chaos" if rows else "none recreated")
' "$(cat "$sd/chaos-at")"
}

chaos() {
  local leader victim leader_uid victim_uid now_leader rc t0 started back
  kubectl -n "$ns" get secret aerolvm-admin -o jsonpath='{.data.token}' | base64 -d > "$sd/token"
  token="$(cat "$sd/token")"
  gateway_forward
  leader="$(curl -fsS -H "Authorization: Bearer $token" http://127.0.0.1:21212/v1/cluster/leader | jq -r .leader)"
  victim="$(kubectl -n "$workers" get pods -l app.kubernetes.io/component=worker -o jsonpath='{.items[0].metadata.name}')"
  [[ -n "$leader" && "$leader" != null && -n "$victim" ]] || { say "chaos: FAIL: no leader ($leader) or no worker pod ($victim)"; return 1; }
  leader_uid="$(kubectl -n "$ns" get pod "$leader" -o jsonpath='{.metadata.uid}')"
  victim_uid="$(kubectl -n "$workers" get pod "$victim" -o jsonpath='{.metadata.uid}')"
  say "chaos: leader $leader, worker $victim"
  started="$sd/load-started"; rm -f "$started" "$sd/chaos-at"
  # Past the delete guard (C26) before the creates start, so the deletes
  # themselves land at once.
  kubectl -n "$workers" annotate pod "$victim" aerolvm.io/force-delete=true --overwrite >/dev/null
  # The creates start over 20 s, so they are still arriving when the chaos
  # lands (all 50 of the first run finished in 3.9 s, before it did).
  python3 "$HERE/cell/load.py" --url http://127.0.0.1:21212 --token-file "$sd/token" --count 50 \
    --spread 20 --started-file "$started" --chaos-file "$sd/chaos-at" > "$sd/load.json" 2>"$sd/load.err" &
  local load=$!
  for _ in $(seq 1 30); do [[ -f "$started" ]] && break; sleep 1; done
  sleep 4
  t0=$(date +%s)
  local d1 d2 r1=0 r2=0
  kubectl -n "$workers" delete pod "$victim" --wait=false >/dev/null & d1=$!
  kubectl -n "$ns" delete pod "$leader" --wait=false >/dev/null & d2=$!
  wait "$d1" || r1=$?
  wait "$d2" || r2=$?
  # A delete that did not land is no chaos: the run would pass on nothing.
  [[ "$r1" == 0 && "$r2" == 0 ]] || { say "chaos: FAIL: delete of the worker exited $r1, of the leader $r2"; wait "$load" || true; return 1; }
  python3 -c 'import time; print(time.time())' > "$sd/chaos-at"
  say "chaos: deleted the leader and the worker $(( $(date +%s) - t0 ))s after asking, about 5 s into 20 s of creates"
  rc=0; wait "$load" || rc=$?
  cat "$sd/load.json" | tee -a "$report"
  [[ "$rc" == 0 ]] || { say "chaos: FAIL: lost or duplicate creates (see above)"; return 1; }
  # The drill counts only if creates were really arriving through it.
  [[ "$(jq '.in_flight_at_chaos + .started_after_chaos' "$sd/load.json")" -ge 10 ]] ||
    { say "chaos: FAIL: fewer than 10 creates overlapped the chaos; it proved nothing"; return 1; }
  # Every sandbox is back: started, wherever it now runs.
  back=0
  for _ in $(seq 1 36); do
    gateway_forward
    back="$(sandboxes "$(jq -r .run "$sd/load.json")" | jq --arg run "$(jq -r .run "$sd/load.json")" \
      '[.[] | select(.tags["cell-run"] == $run and .status == "started")] | length' 2>/dev/null || echo 0)"
    [[ "$back" == 50 ]] && break
    sleep 5
  done
  say "chaos: $back of 50 sandboxes started, seen $(( $(date +%s) - t0 ))s after the deletes"
  say "chaos: failover from the workers' logs: $(recreate_times)"
  [[ "$back" == 50 ]] || { say "chaos: FAIL"; return 1; }
  wait_phase Ready 600
  wait_workers 3 900
  # Both pods really went (a server pod comes back under its name, as a new
  # pod), and the servers elected a leader after losing theirs.
  [[ "$(kubectl -n "$ns" get pod "$leader" -o jsonpath='{.metadata.uid}' 2>/dev/null)" != "$leader_uid" &&
     "$(kubectl -n "$workers" get pod "$victim" -o jsonpath='{.metadata.uid}' 2>/dev/null)" != "$victim_uid" ]] ||
    { say "chaos: FAIL: the leader's or the worker's pod is still the one the chaos deleted"; return 1; }
  gateway_forward
  now_leader="$(curl -fsS -H "Authorization: Bearer $token" http://127.0.0.1:21212/v1/cluster/leader | jq -r .leader)"
  [[ -n "$now_leader" && "$now_leader" != null ]] || { say "chaos: FAIL: no leader after the chaos"; return 1; }
  if [[ "$now_leader" == "$leader" ]]; then
    say "chaos: PASS; leader $now_leader again, in its new pod"
  else
    say "chaos: PASS; leadership moved from $leader to $now_leader"
  fi
}

verify() {
  local cli="$sd/aerolvm" rc=0
  # Dev images are unsigned; a release's are signed by release.yml.
  local sigs=(--skip-signatures)
  [[ -n "${AEROL_RELEASE:-}" ]] && sigs=()
  (cd "$(source_tree "$sha")" && go build -o "$cli" ./cmd/aerolvm)
  token="$(kubectl -n "$ns" get secret aerolvm-admin -o jsonpath='{.data.token}' | base64 -d)"
  gateway_forward
  SB_API_URL=http://127.0.0.1:21212 SB_PAT_TOKEN="$token" "$cli" k8s verify --namespace "$ns" \
    --worker-namespace "$workers" --release aerolvm --cluster aerolvm ${sigs[@]+"${sigs[@]}"} \
    --probe-runtimes gvisor 2>&1 | tee -a "$report" || rc=$?
  say "verify: exit $rc"
  return "$rc"
}

case "$step" in
  up) ;;
  build) build ;;
  build2) build "$tag.2" "${sha:0:8}-2" ;;
  drills)
    # drills.sh's drills on this cell (§19). The rollout drill needs build2.
    gateway_forward >/dev/null || true
    DRILL_EKS_CLUSTER="$(tfout -raw cluster_name)" DRILL_AWS_REGION="$region" \
      DRILL_VERSION_B="$tag.2" AEROL_CHART="$(source_tree "$sha")/charts/aerolvm" HELM="$HELM" \
      "$HERE/drills.sh" "$sd/drills" "${@:3}" 2>&1 | tee -a "$report"
    exit "${PIPESTATUS[0]}" ;;
  install) install ;;
  preflight) preflight ;;
  chaos) chaos ;;
  verify) verify ;;
  all) build && install && preflight && chaos && verify ;;
  *) echo "cell.sh: unknown step $step" >&2; exit 2 ;;
esac

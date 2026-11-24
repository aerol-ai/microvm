#!/usr/bin/env bash
# m1-eks.sh: the live EKS drill for M1 (plans/security-gaps-m1-m4.md §3.6,
# eng review D10): the proof the chart's default may flip to split.
#
#   m1-eks.sh <name> estimate          # the cost table; makes nothing
#   m1-eks.sh <name> all               # every step below in order, then down
#   m1-eks.sh <name> <step> [step...]
#   DRY_RUN=1 m1-eks.sh <name> all     # print every AWS, kubectl and Helm
#                                      # call; make nothing, call nothing
#
# It spends real AWS money (README.md beside it): the owner says yes first.
#
# Run it from a checkout of the commit under test. cluster.sh and its
# Terraform state (integration-tests/k8s/.state/<name>/) are this
# checkout's; the chart, `aerolvm k8s verify` and the images come from the
# commit AEROL_BUILD_REF names (default HEAD), never from the working tree.
# The images are built inside the cluster from that commit's source
# (~12 MB to S3), with THROWAWAY signing keys made inside the build pod
# (build-job.yaml). Nothing large leaves this machine.
#
# One cluster, used by every item in turn (us-east-1, EKS 1.36, AL2023):
# 2 system machines (m7i.large), 3 worker machines (m7i.xlarge), cluster
# mode, two zones, ECR for the run, AWS's own teardown timer at the TTL.
#
# Steps, in the order `all` runs them:
#   estimate  cost.py: planned and worst case; exit 3 past M1_CEILING ($8)
#   up        estimate, then cluster.sh up
#   setup     br_netfilter on the worker machines (F2 stand-in DaemonSet)
#   build     source to S3; images built in the cluster (T1, T2, variants)
#   install   cert-manager, a gp3 class with the run's tags, the chart in
#             privilegeMode single at T1; 3 workers Serving
#   kernel    every worker machine's kernel (6.12 wanted); verify
#   switch1   privilegeMode=split; worker 1's machine cordoned: decommission,
#             its sandboxes move (single to single), a split worker replaces
#             it; verify (mixed)
#   shape     the split pod's shape and its signed helper; the first create
#             after the helper starts; the image user, split against single
#   n1        N1: paired creates split against single (cold, warm pool,
#             burst), from a pod in the cluster; n1-stats.py's verdict
#   switch2   worker 2 the same way; verify (mixed)
#   moves     a gVisor sandbox moved split to split through both helpers
#             (the single worker cordoned in AerolVM, so it is no target)
#   switch3   the last single worker: its gVisor sandbox cannot move to a
#             split worker (refused before anything is saved); its recreate
#             sandbox moves; verify (all split)
#   s2        OV-E2 and S2: an rclone mount and live sandboxes on split
#             workers; the rollout T1 -> T2 swaps every agent in place; the
#             newer signed helper takes over; then a helper restart
#   variants  in place, on one split worker: an unsigned helper, one signed
#             by another key and an older one are each refused; the running
#             helper keeps serving
#   f10       memory pressure on a split worker kills whole sandboxes only
#   f8        a split worker pod force-deleted with sandboxes running leaves
#             nothing on its machine
#   final     verify, evidence
#   down      the chart and its volumes, cluster.sh down, leak-check.sh
# Not in `all`: verifynow (aerolvm k8s verify on its own, labelled
# M1_VERIFY_LABEL), for a run resumed by hand.
#
# up, setup, build and install are what the rest needs: one that fails ends
# the run (and `all` tears it down unless M1_KEEP=1). Every later step is a
# check: a failure is a FAIL line in .state/<name>/m1.txt, its diagnostics
# are saved, and the run goes on.
#
# Cost guards: up refuses when cost.py's worst case passes M1_CEILING. After
# every step the spend so far and its projection go to .state/<name>/cost.log;
# a projection past M1_COST_LIMIT stops the run and tears it down. down tears
# down by name (cluster.sh down <name>), then leak-check.sh lists anything of
# the run still in AWS.
#
# Settings: DRY_RUN (0|1), AEROL_BUILD_REF (default HEAD), M1_CEILING (8),
# M1_COST_LIMIT (6.15), M1_TTL_HOURS (5), M1_KEEP (0|1), HELM (a Helm 3.8+;
# CI pins 3.22.1), M1_VM_NAME (<name>-vm, vm-n1.sh's run, counted in the
# cost), M1_VM_HOURS (1.5; 0 when no VM runs), M1_N1_COLD (40), M1_N1_WARM
# (120), M1_N1_BURST (20), M1_F10_SANDBOXES (5), M1_F10_FILL_MB (3072),
# M1_GW_PORT (21410, the local end of the API's port-forward).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$K8S/../.." && pwd)"
usage() { sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }
name="${1:-}"; [[ -n "$name" ]] || usage
shift
[[ $# -gt 0 ]] || usage
case "${DRY_RUN:-0}" in
  0|1) dry="${DRY_RUN:-0}" ;;
  *) echo "m1-eks.sh: DRY_RUN must be 0 or 1, not \"$DRY_RUN\"; nothing ran" >&2; exit 2 ;;
esac
[[ "$name" =~ ^[a-z][a-z0-9-]{2,30}$ ]] || { echo "m1-eks.sh: \"$name\" is not a cluster.sh run name" >&2; exit 2; }
sd="$K8S/.state/$name"
mkdir -p "$sd/evidence"
sha="$(git -C "$REPO" rev-parse "${AEROL_BUILD_REF:-HEAD}^{commit}")"
# The versions: T1 is installed, T2 is S2's upgrade, T3 only signs the
# refused variants (newer than T2, so only the signature is wrong).
T1=v0.0.0-m1drill.1 T2=v0.0.0-m1drill.2 T3=v0.0.0-m1drill.3
# shellcheck source=m1-lib.sh
source "$HERE/m1-lib.sh"
CERT_MANAGER_VERSION=v1.21.3
CERT_MANAGER_SHA256=c04a51295adda2b1a775146751f973e787190778c7f35180861d9678876e5c74

chart_dir() { [[ "$dry" == 1 ]] && echo "$REPO/charts/aerolvm" || echo "$(src_tree)/charts/aerolvm"; }
machine() { [[ "$dry" == 1 ]] && { echo "dry-machine-$1"; return 0; }; sed -n "${1}p" "$sd/machines"; }
pod_gone() { ! kr -n "$workers" get pod "$1" >/dev/null 2>&1; }
serving_count() {
  local n=0 p
  for p in $(worker_pods); do serving "$p" && n=$((n + 1)); done
  [[ "$n" -ge "$1" ]]
}
new_on() { local p; p="$(worker_on "$1")"; [[ -n "$p" && "$p" != "$2" ]] && serving "$p"; }
# only_on <pod> <cmd...>: runs cmd while every other worker takes no new
# sandbox (AerolVM's admission-only cordon), so a create lands on <pod>.
only_on() {
  local w="$1" p; shift
  for p in $(worker_pods); do [[ "$p" == "$w" ]] || api_cordon "$p"; done
  "$@"
  for p in $(worker_pods); do [[ "$p" == "$w" ]] || api_uncordon "$p"; done
}
# server_logs <pattern>: lines of every server pod's log that match.
server_logs() {
  [[ "$dry" == 1 ]] && return 0
  local p
  for p in $(kr -n "$ns" get pods -l app.kubernetes.io/component=server -o jsonpath='{.items[*].metadata.name}'); do
    kr -n "$ns" logs "$p" --all-containers --since=2h 2>/dev/null | grep -E "$1" | sed "s/^/$p: /" || true
  done
}

# switch_machine <machine> <label>: cordon the machine (the operator
# decommissions its worker), wait until that worker is gone, uncordon, wait
# for the worker the template now makes. Prints the new worker's name.
switch_machine() {
  local m="$1" label="$2" hook="${3:-}" old new t0
  old="$(worker_on "$m")"
  t0=$(now)
  say "$label: cordon $m (worker $old)"
  k cordon "$m" >/dev/null
  # An optional check that must run while the old worker decommissions.
  [[ -n "$hook" ]] && "$hook" "$old" >&2
  if ! wait_until 1500 "$old decommissioned and its pod gone" pod_gone "$old"; then
    diag "$label"; k uncordon "$m" >/dev/null || true; return 1
  fi
  say "$label: $old gone after $(( $(now) - t0 ))s; uncordon $m"
  k uncordon "$m" >/dev/null
  if ! wait_until 900 "a new worker on $m Serving" new_on "$m" "$old"; then diag "$label"; return 1; fi
  new="$(worker_on "$m")"
  say "$label: $new serving on $m in $(mode_of "$new") mode, $(( $(now) - t0 ))s after the cordon"
  echo "$new"
}

# --- estimate and up ---------------------------------------------------------------
step_estimate() {
  python3 -I "$HERE/cost.py" --ceiling "${M1_CEILING:-8}" --ttl-hours "${M1_TTL_HOURS:-5}" --json "$sd/estimate.json" | tee "$sd/estimate.txt"
}
step_up() {
  step_estimate
  # The running cost (cost_check) counts the cluster from here.
  [[ "$dry" == 1 ]] || date +%s > "$sd/cost-start"
  x "$K8S/cluster.sh" up "$name" --ttl "${M1_TTL_HOURS:-5}h" \
    --zones 2 --system 2 --system-type m7i.large --workers 3 --type m7i.xlarge \
    --imds-hop-limit 1 --ebs-csi --network-policy --ecr aerolvm,aerolvm-runtime,aerolvm-operator --teardown
}

# --- setup, build, install ---------------------------------------------------------
step_setup() {
  gate
  sed "s|@@IMAGE@@|$DEBUG_IMAGE|" "$K8S/cell/node-setup.yaml" | k apply -f - >/dev/null
  k -n kube-system rollout status ds/aerolvm-cell-node-setup --timeout=5m >/dev/null
  say "setup: br_netfilter loaded on every worker machine (F2 stand-in)"
}

step_build() {
  gate
  local region reg bucket key url pass st=""
  region="$(tfout region)"; reg="$(tfout ecr_registry)"
  if [[ "$dry" == 1 ]]; then bucket=aerol-itest-artifacts-111122223333; else
    bucket="aerol-itest-artifacts-$(aws sts get-caller-identity --query Account --output text)"; fi
  key="k8s-m1/$sha.tar.gz"
  if [[ "$dry" == 1 ]]; then
    echo "dry-run: git archive --format=tar.gz $sha | aws s3 cp --region us-east-1 - s3://$bucket/$key (if absent)" >&2
    url="https://$bucket.s3.amazonaws.com/$key?X-Amz-Signature=dry&X-Amz-Expires=21600"
    pass=dry
  else
    aws s3api head-object --region us-east-1 --bucket "$bucket" --key "$key" >/dev/null 2>&1 ||
      git -C "$REPO" archive --format=tar.gz "$sha" | aws s3 cp --region us-east-1 - "s3://$bucket/$key" >/dev/null
    url="$(aws s3 presign "s3://$bucket/$key" --expires-in 21600 --region us-east-1)"
    pass="$(aws ecr get-login-password --region "$region")"
  fi
  say "build: $sha as $T1, $T2 and the variants; source s3://$bucket/$key"
  k create namespace aerolvm-build --dry-run=client -o yaml | k apply -f - >/dev/null
  # ECR's push token (12 hours), for BuildKit only. In a dry run a
  # placeholder: no token is ever printed.
  k -n aerolvm-build create secret docker-registry ecr-push --docker-server="${reg%%/*}" \
    --docker-username=AWS --docker-password="$pass" --dry-run=client -o yaml | k apply -f - >/dev/null
  # In a sed replacement & is "what matched": the presigned URL's & signs
  # are escaped (cell.sh's lesson).
  sed -e "s|@@SOURCE_URL@@|${url//&/\\&}|" -e "s|@@REGISTRY@@|$reg|g" -e "s|@@SHA@@|$sha|g" \
    -e "s|@@SHORT@@|${sha:0:8}|g" -e "s|@@T1@@|$T1|g" -e "s|@@T2@@|$T2|g" -e "s|@@T3@@|$T3|g" \
    "$HERE/build-job.yaml" > "$sd/build-job.yaml"
  k apply -f "$sd/build-job.yaml" >/dev/null
  if [[ "$dry" == 1 ]]; then echo "dry-run: (wait up to 45 min for job/images-${sha:0:8})" >&2; return 0; fi
  for _ in $(seq 1 180); do
    st="$(kr -n aerolvm-build get "job/images-${sha:0:8}" -o jsonpath='{.status.succeeded}/{.status.failed}')"
    [[ "$st" == 1/* || "$st" == */1 ]] && break
    sleep 15
  done
  kr -n aerolvm-build logs "job/images-${sha:0:8}" --all-containers --tail=-1 > "$sd/build.log" 2>&1 || true
  if [[ "$st" != 1/* ]] || ! grep -q 'images: done' "$sd/build.log"; then
    say "build: FAILED ($st); last lines:"; tail -30 "$sd/build.log" >&2
    return 1
  fi
  say "build: images pushed to $reg"
}

step_install() {
  gate
  local zones ttl
  x curl -fsSL -o "$sd/cert-manager.yaml" "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml"
  [[ "$dry" == 1 ]] || echo "$CERT_MANAGER_SHA256  $sd/cert-manager.yaml" | shasum -a 256 -c - >/dev/null
  k apply -f "$sd/cert-manager.yaml" >/dev/null
  k -n cert-manager wait --for=condition=Available deployment --all --timeout=5m >/dev/null
  # The servers' volumes carry the run's tags, so cluster.sh down and
  # reap.sh find any a run leaves (24 untagged ones were found by hand on
  # 2026-11-19).
  ttl="$(jq -r .ttl "$sd/run.tfvars.json" 2>/dev/null || echo dry)"
  k apply -f - >/dev/null <<YAML
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata: { name: gp3 }
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Delete
parameters:
  type: gp3
  tagSpecification_1: "aerol:purpose=k8s-phase0"
  tagSpecification_2: "aerol:run=$name"
  tagSpecification_3: "aerol:ttl=$ttl"
YAML
  k create namespace "$ns" --dry-run=client -o yaml | k apply -f - >/dev/null
  k label namespace "$ns" pod-security.kubernetes.io/enforce=restricted --overwrite >/dev/null
  zones="$(tfout zones | jq -r 'join(", ")')"
  sed -e "s|@@REGISTRY@@|$(tfout ecr_registry)|" -e "s|@@TAG@@|$T1|g" -e "s|@@ZONES@@|$zones|" \
    "$HERE/values.yaml" > "$sd/values.yaml"
  hm upgrade --install "$release" "$(chart_dir)" -n "$ns" -f "$sd/values.yaml" >/dev/null
  if ! wait_until 1200 "3 workers Serving" serving_count 3; then diag install; return 1; fi
  if [[ "$dry" != 1 ]]; then
    local p
    for p in $(worker_pods); do machine_of "$p"; echo; done | grep . | sort > "$sd/machines"
  fi
  local ms="dry"
  [[ -f "$sd/machines" ]] && ms="$(tr '\n' ' ' < "$sd/machines")"
  say "install: chart $T1 in single mode; worker machines: $ms"
}

# --- checks ------------------------------------------------------------------------
step_kernel() {
  gate
  local m out="$sd/evidence/kernel.txt" kv ok=1
  : > "$out"
  for i in 1 2 3; do
    m="$(machine "$i")"
    kv="$(kr get node "$m" -o jsonpath='{.status.nodeInfo.kernelVersion}')"
    echo "$m kernel ${kv:-?} $(kr get node "$m" -o jsonpath='{.status.nodeInfo.osImage}')" >> "$out"
    [[ "$kv" =~ ^6\.(1[2-9]|[2-9][0-9])\. ]] || ok=0
  done
  if [[ "$ok" == 1 ]]; then result PASS kernel "every worker machine runs 6.12 or later: $(tr '\n' ';' < "$out")"
  else result FAIL kernel "not every worker machine runs 6.12 (the 6.12 item cannot be proven on this AMI): $(tr '\n' ';' < "$out")"; fi
  verify single
}

# seed <pod> <tag>: on that worker, a gVisor sandbox with a live counter and
# a runc sandbox with failover recreate. Their ids go to $sd/seed-<tag>.
seed() {
  local w="$1" tag="$2" mode g r
  mode="$(mode_of "$w")"
  for p in $(worker_pods); do [[ "$p" == "$w" ]] || api_cordon "$p"; done
  g="$(create "$(body gvisor "$BUSYBOX" "$mode")")"
  r="$(create "$(body docker "$ALPINE" "$mode" '"failover":{"policy":"recreate"}')")"
  for p in $(worker_pods); do [[ "$p" == "$w" ]] || api_uncordon "$p"; done
  local c0="" t0
  if [[ -n "$g" ]]; then
    start_counter "$g"
    [[ "$dry" == 1 ]] || sleep 5
    c0="$(count_of "$g" || true)"
  fi
  t0=$(now)
  echo "$g $r ${c0:-0} $t0" > "$sd/seed-$tag"
  say "seed $tag on $w: gVisor $g (counter ${c0:-none}), runc $r (recreate)"
}

# after_switch <tag> <old worker>: where the seeds went, and whether they kept
# going.
after_switch() {
  local tag="$1" old="$2" g r og or c
  read -r g r _ < "$sd/seed-$tag" || true
  og="$(owner "$g")"; or="$(owner "$r")"; c="$(count_of "$g" || true)"
  echo "$tag: gVisor $g on ${og:-none} count ${c:-none}; runc $r on ${or:-none}" >> "$sd/evidence/moves.txt"
  if [[ -n "$or" && "$or" != "$old" ]] && answers "$r"; then
    result PASS "$tag-recreate" "runc sandbox $r (failover recreate) moved off $old to $or and answers"
  else result FAIL "$tag-recreate" "runc sandbox $r: owner ${or:-none}, answers: $(answers "$r" && echo yes || echo no)"; fi
}

step_switch1() {
  gate
  local w new
  hm upgrade "$release" "$(chart_dir)" -n "$ns" --reuse-values --set privilegeMode=split >/dev/null
  w="$(worker_on "$(machine 1)")"
  seed "$w" s1
  new="$(switch_machine "$(machine 1)" switch1)" || { result FAIL switch1 "worker 1 did not come back"; return 0; }
  if [[ "$(mode_of "$new")" == split ]]; then result PASS switch1 "$w (single) decommissioned; $new serves in split"
  else result FAIL switch1 "$new came back in $(mode_of "$new") mode"; fi
  after_switch s1 "$w"
  local g c c0 t0
  read -r g _ c0 t0 < "$sd/seed-s1" || true
  c="$(count_of "$g" || true)"
  if kept_counting "$c" "$c0" "$t0"; then result PASS switch1-gvisor-move "gVisor $g moved single to single with its memory: counter $c0 -> $c over $(( $(now) - t0 ))s, now on $(owner "$g")"
  else result FAIL switch1-gvisor-move "gVisor $g: counter $c0 -> ${c:-none} over $(( $(now) - ${t0:-0} ))s on $(owner "$g")"; fi
  verify mixed1
}

# kept_counting <now> <at seed> <seed time>: the /dev/shm counter (one a
# second) went on through the move, by at least half the seconds since: a
# sandbox started again (recreated, or restored without its memory) counts
# from 1.
kept_counting() {
  [[ "$dry" == 1 ]] && return 0
  [[ "${1:-}" =~ ^[0-9]+$ && "${2:-}" =~ ^[0-9]+$ && "${3:-}" =~ ^[0-9]+$ ]] || return 1
  (( $1 >= $2 + ($(now) - $3) / 2 ))
}
need() { [[ -n "$2" ]] || { result FAIL "$1" "no worker of the mode this step needs"; return 1; }; }

# The first create on the new split worker, then the pod's shape.
step_shape() {
  gate
  local w out="$sd/evidence/shape" sc hp
  mkdir -p "$out"
  w="$(workers_in split | head -1)"
  need shape "$w" || return 0
  bench_up
  local wn1 p
  wn1="$(workers_in single | head -1)"
  for p in $(worker_pods); do [[ "$p" == "$w" || "$p" == "$wn1" ]] || api_cordon "$p"; done
  k -n m1-bench exec m1-bench -- env SPLIT_NODE="$w" SINGLE_NODE="$wn1" bash /bench/n1-bench.sh first > "$out/first-create.txt" || true
  for p in $(worker_pods); do [[ "$p" == "$w" || "$p" == "$wn1" ]] || api_uncordon "$p"; done
  say "shape: first create after the helper started: $(grep '^N1 first' "$out/first-create.txt" 2>/dev/null | tr '\n' ';')"
  sc="$(kr -n "$workers" get pod "$w" -o jsonpath='{.spec.containers[?(@.name=="agent")].securityContext}')"
  echo "$sc" > "$out/agent-securitycontext.json"
  chk() {
    local what="$1"; shift
    [[ "$dry" == 1 ]] && { echo "dry-run: (check) shape-$what on $w" >&2; return 0; }
    if "$@" >/dev/null 2>&1; then result PASS "shape-$what" "$w"; else result FAIL "shape-$what" "$w"; fi
  }
  chk agent-uid-65531 test "$(k -n "$workers" exec "$w" -c agent -- id -u)" = 65531
  chk agent-no-capabilities test "$(k -n "$workers" exec "$w" -c agent -- sh -c 'sed -n "s/^CapEff:[[:space:]]*//p" /proc/self/status')" = 0000000000000000
  chk agent-not-privileged bash -c '[[ "$1" != *\"privileged\":true* && "$1" == *\"readOnlyRootFilesystem\":true* ]]' _ "$sc"
  chk agent-no-containerd k -n "$workers" exec "$w" -c agent -- sh -c '! test -e /var/lib/containerd && ! test -e /run/containerd/containerd.sock && ! test -e /run/netns'
  chk agent-reaches-helper k -n "$workers" exec "$w" -c agent -- test -S /run/aerolvm-rootd/shared/sock/root.sock
  chk no-two-way-mount bash -c '! kubectl --kubeconfig "$1" -n "$2" get pod "$3" -o json | grep -q -e Bidirectional -e "\"shareProcessNamespace\": true"' _ "$sd/kubeconfig" "$workers" "$w"
  hp="$(helper "$w")"
  echo "$hp" > "$out/helper.txt"
  if [[ "$hp" == *"aerolvm-rootd-$T1-"* ]]; then result PASS shape-signed-helper "$w runs helper $T1, signed by the run's throwaway key with the release signer ($hp)"
  else result FAIL shape-signed-helper "$w helper: ${hp:-none running}"; fi
  image_user "$w"
}

# image_user <split worker>: the user each image runs as, split against
# single, read from containerd's own spec on each worker (plan PR 7 risk:
# the detached overlay on a 6.12 kernel). Multi-layer and USER images too.
image_user() {
  local ws="$1" wn img sid nid us un ok=1 out="$sd/evidence/image-user.txt"
  wn="$(workers_in single | head -1)"
  : > "$out"
  for img in "$ALPINE" public.ecr.aws/docker/library/node:22-alpine public.ecr.aws/nginx/nginx-unprivileged:alpine; do
    sid="$(only_on "$ws" create "$(body docker "$img" split)")"; nid="$(only_on "$wn" create "$(body docker "$img" single)")"
    us="$(spec_user "$ws" "$sid")"; un="$(spec_user "$wn" "$nid")"
    echo "$img split=$us single=$un" >> "$out"
    [[ -n "$us" && "$us" == "$un" ]] || ok=0
    api DELETE "/v1/sandboxes/$sid" >/dev/null; api DELETE "/v1/sandboxes/$nid" >/dev/null
  done
  if [[ "$ok" == 1 ]]; then result PASS image-user-6.12 "each image's user is the same in split (helper, detached overlay) as in single: $(tr '\n' ';' < "$out")"
  else result FAIL image-user-6.12 "$(tr '\n' ';' < "$out")"; fi
}
# spec_user <worker> <sandbox>: the process user in containerd's spec.
spec_user() {
  [[ "$dry" == 1 ]] && { echo '{"uid":0,"gid":0}'; return 0; }
  [[ -n "$2" ]] || return 0
  kubectl --kubeconfig "$sd/kubeconfig" -n "$workers" exec "$1" -c runtime -- sh -c \
    "c=\$(ctr -n aerolvm c ls -q | grep -F '$2' | head -1); [ -n \"\$c\" ] && ctr -n aerolvm c info \"\$c\"" 2>/dev/null |
    jq -c '.Spec.process.user' 2>/dev/null || true
}

# bench_up: the N1 bench pod (Amazon Linux 2023, bash and curl), in a
# namespace of its own; the admin token reaches it as a Secret.
bench_up() {
  [[ "$dry" != 1 ]] && kr -n m1-bench get pod m1-bench >/dev/null 2>&1 && return 0
  k create namespace m1-bench --dry-run=client -o yaml | k apply -f - >/dev/null
  if [[ "$dry" == 1 ]]; then echo "dry-run: secret m1-bench/bench-token from the admin token (never printed)" >&2
  else kubectl --kubeconfig "$sd/kubeconfig" -n m1-bench create secret generic bench-token --from-literal=TOKEN="$(token)" \
    --dry-run=client -o yaml | kubectl --kubeconfig "$sd/kubeconfig" apply -f - >/dev/null; fi
  k -n m1-bench create configmap bench --from-file=n1-bench.sh="$HERE/n1-bench.sh" --dry-run=client -o yaml | k apply -f - >/dev/null
  k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: { name: m1-bench, namespace: m1-bench }
spec:
  containers:
    - name: bench
      image: $DEBUG_IMAGE
      command: [sleep, infinity]
      env:
        - { name: GW, value: "http://aerolvm-gateway.$ns.svc:21212" }
        - name: TOKEN
          valueFrom: { secretKeyRef: { name: bench-token, key: TOKEN } }
      volumeMounts: [{ name: bench, mountPath: /bench }]
      resources: { requests: { cpu: 500m, memory: 256Mi } }
  volumes: [{ name: bench, configMap: { name: bench } }]
YAML
  k -n m1-bench wait --for=condition=Ready pod/m1-bench --timeout=5m >/dev/null
}

bench_done() { kubectl --kubeconfig "$sd/kubeconfig" -n m1-bench exec m1-bench -- grep -q "^N1 done $1" "/tmp/n1-$1.log" 2>/dev/null; }
step_n1() {
  gate
  local out="$sd/evidence/n1" open=() p
  mkdir -p "$out"
  bench_up
  # One worker of each mode open; the rest take no new sandbox meanwhile.
  open+=("$(workers_in split | head -1)" "$(workers_in single | head -1)")
  need n1 "${open[0]}" || return 0
  need n1 "${open[1]}" || return 0
  for p in $(worker_pods); do [[ " ${open[*]} " == *" $p "* ]] || api_cordon "$p"; done
  echo "split ${open[0]} on $(machine_of "${open[0]}"); single ${open[1]} on $(machine_of "${open[1]}")" > "$out/sides.txt"
  : > "$out/bench.log"
  local ph
  local ph name
  for ph in "cold ${M1_N1_COLD:-40}" "warm ${M1_N1_WARM:-120}" "burst ${M1_N1_BURST:-20}"; do
    name="${ph%% *}"
    # In the pod, in the background, into a file: a phase runs minutes, and
    # one long exec over this machine's link can drop.
    # shellcheck disable=SC2086
    k -n m1-bench exec m1-bench -- env SPLIT_NODE="${open[0]}" SINGLE_NODE="${open[1]}" sh -c "nohup bash /bench/n1-bench.sh $ph > /tmp/n1-$name.log 2>&1 &"
    wait_until 1200 "N1 $name finished" bench_done "$name" || say "n1: phase $name did not finish in 20 min"
    [[ "$dry" == 1 ]] || kubectl --kubeconfig "$sd/kubeconfig" -n m1-bench exec m1-bench -- cat "/tmp/n1-$name.log" >> "$out/bench.log" 2>&1 || true
  done
  for p in $(worker_pods); do [[ " ${open[*]} " == *" $p "* ]] || api_uncordon "$p"; done
  [[ "$dry" == 1 ]] && { echo "dry-run: python3 -I n1-stats.py $out/bench.log" >&2; return 0; }
  if python3 -I "$HERE/n1-stats.py" "$out/bench.log" > "$out/verdict.txt" 2>&1; then
    result PASS n1 "$(grep -E 'median' "$out/verdict.txt" | tr '\n' ';')"
  else
    result FAIL n1 "$(grep -E 'median|no N1' "$out/verdict.txt" | tr '\n' ';')"
  fi
}

step_switch2() {
  gate
  local w new g c c0 t0 sp
  w="$(worker_on "$(machine 2)")"
  seed "$w" s2
  # The split worker is no target meanwhile (AerolVM cordon), so worker 2's
  # gVisor sandbox has one place to go: the other single worker. This is the
  # single-to-single move with memory (switch 1's seeds failed in run m1d-2).
  for sp in $(workers_in split); do api_cordon "$sp"; done
  new="$(switch_machine "$(machine 2)" switch2)" || { result FAIL switch2 "worker 2 did not come back"; return 0; }
  for sp in $(workers_in split); do api_uncordon "$sp"; done
  [[ "$(mode_of "$new")" == split ]] && result PASS switch2 "$w (single) decommissioned; $new serves in split" ||
    result FAIL switch2 "$new came back in $(mode_of "$new") mode"
  after_switch s2 "$w"
  read -r g _ c0 t0 < "$sd/seed-s2" || true
  c="$(count_of "$g" || true)"
  if [[ -n "$g" ]] && kept_counting "$c" "$c0" "$t0"; then
    result PASS single-single-gvisor-move "gVisor $g moved single to single with its memory: counter $c0 -> $c over $(( $(now) - t0 ))s, now on $(owner "$g") ($(mode_of "$(owner "$g")"))"
  else result FAIL single-single-gvisor-move "gVisor ${g:-none}: counter ${c0:-none} -> ${c:-none} on $(owner "$g")"; fi
  verify mixed2
}

step_moves() {
  gate
  local single src dst g c0 c1 t0 out="$sd/evidence/moves-split.txt"
  single="$(workers_in single | head -1)"
  [[ -n "$single" ]] && api_cordon "$single"
  src="$(workers_in split | head -1)"
  need moves "$src" || return 0
  for p in $(worker_pods); do [[ "$p" == "$src" ]] || api_cordon "$p"; done
  g="$(create "$(body gvisor "$BUSYBOX" split)")"
  for p in $(workers_in split); do [[ "$p" == "$src" ]] || api_uncordon "$p"; done
  start_counter "$g"; sh_in "$g" 'echo m1-moves > /root/marker' >/dev/null || true
  [[ "$dry" == 1 ]] || sleep 20
  c0="$(count_of "$g" || true)"; t0=$(now)
  echo "before: $g on $src, counter $c0" > "$out"
  switch_machine "$(machine_of "$src")" moves >/dev/null || true
  dst="$(owner "$g")"; c1="$(count_of "$g" || true)"
  echo "after: $g on ${dst:-none}, counter ${c1:-none}, marker $(sh_in "$g" 'cat /root/marker' | tr -d '\n')" >> "$out"
  [[ -n "$single" ]] && api_uncordon "$single"
  if [[ -n "$dst" && "$dst" != "$src" && "$(mode_of "$dst")" == split ]] && kept_counting "$c1" "$c0" "$t0"; then
    result PASS moves-split-split "gVisor $g moved $src -> $dst (both split) with its memory: counter $c0 -> $c1 over $(( $(now) - t0 ))s"
  else result FAIL moves-split-split "$(tr '\n' ';' < "$out")"; diag moves; fi
}

step_switch3() {
  gate
  local w new g r refusals
  w="$(workers_in single | head -1)"
  [[ -n "$w" ]] || { result SKIP switch3 "no single worker left"; return 0; }
  seed "$w" s3
  new="$(switch_machine "$(machine_of "$w")" switch3 cross_mode_probe)" || { result FAIL switch3 "worker did not come back"; return 0; }
  after_switch s3 "$w"
  read -r g r _ < "$sd/seed-s3" || true
  # The leader reports a refused move in its evacuate answer (failed:
  # {id: reason}); neither it nor the operator logs it.
  refusals="$(jq -r --arg g "$g" '.failed[$g] // empty' "$sd/evidence/cross-mode-evacuate.json" 2>/dev/null || true)"
  if [[ "$refusals" == *"restores gVisor checkpoints in privilege mode split, the source saves them in single"* ]]; then
    result PASS cross-mode-refusal "the leader refused to move gVisor $g from single $w to a split worker, before anything was saved: $refusals"
  else result FAIL cross-mode-refusal "evacuate answer: $(tr '\n' ' ' < "$sd/evidence/cross-mode-evacuate.json" 2>/dev/null | cut -c1-300)"; diag switch3; fi
  verify all-split
}

# cross_mode_probe <old worker>: once the operator has the worker
# decommissioning (cordoned in AerolVM), one evacuate pass of our own (the
# operator's call; each pass is idempotent) answers which moves it refused
# and why.
cross_mode_probe() {
  local w="$1" out
  wait_until 300 "$w decommissioning" node_state_is "$w" Decommissioning || true
  out="$(api POST "/v1/cluster/nodes/$w/evacuate" "{\"deadline_unix\": $(( $(now) + 900 ))}")"
  echo "evacuate $w -> $(code_of "$out")"
  body_of "$out" > "$sd/evidence/cross-mode-evacuate.json"
}
node_state_is() { [[ "$(kr -n "$ns" get aerolnode "$1" -o jsonpath='{.status.state}' 2>/dev/null)" == "$2" ]]; }

# --- S2, OV-E2 and the helper's hot swap -----------------------------------------------
store_count() { [[ "$dry" == 1 ]] && { echo 0; return 0; }; minio_mc ls "store/$MINIO_BUCKET/" 2>/dev/null | grep -c ' log-' || true; }
snapshot() { # snapshot <file>: per worker its restarts and helper; per sandbox its counter
  local f="$1" p id
  : > "$f"
  for p in $(worker_pods); do echo "worker $p $(restarts "$p")| helper $(helper "$p")" >> "$f"; done
  for id in $(cat "$sd/s2-ids" 2>/dev/null); do echo "sandbox $id on $(owner "$id") count $(count_of "$id")" >> "$f"; done
  echo "store files $(store_count)" >> "$f"
}
step_s2() {
  gate
  local out="$sd/evidence/s2" id i mid s0 s1 ok
  mkdir -p "$out"
  # shellcheck source=/dev/null
  source "$K8S/minio-store.sh"
  if [[ "$dry" == 1 ]]; then echo "dry-run: minio_store_up kubectl -n $ns (MinIO + mc pods); helm upgrade --set networkPolicy.extraEgressCIDRs={<MinIO IP>/32}" >&2
    MINIO_IP=192.0.2.9 MINIO_RCLONE_CONF=dry MINIO_BUCKET=sandbox-store
  else
    minio_store_up kubectl --kubeconfig "$sd/kubeconfig" -n "$ns" || { result FAIL ov-e2 "MinIO did not start"; return 0; }
    echo seed-ok | minio_mc pipe "store/$MINIO_BUCKET/seed.txt" >/dev/null
  fi
  hm upgrade "$release" "$(chart_dir)" -n "$ns" --reuse-values --set "networkPolicy.extraEgressCIDRs={$MINIO_IP/32}" >/dev/null
  # The mount: rclone (S3 remote) against MinIO, in a gVisor sandbox (every
  # worker is split by now); it writes a file a second into the store.
  mid="$(create "$(jq -cn --arg src "store:$MINIO_BUCKET" --arg conf "$MINIO_RCLONE_CONF" \
    '{runtime:"gvisor", image:"public.ecr.aws/docker/library/alpine:3.20",
      mounts:[{type:"rclone", source:$src, target:"/mnt/ext", credentials:{rclone_conf:$conf}}]}')")"
  if [[ -z "$mid" ]]; then result FAIL ov-e2 "the mount create was refused (creates.log)"; else
    [[ "$(sh_in "$mid" 'cat /mnt/ext/seed.txt' | tr -d '\n')" == seed-ok || "$dry" == 1 ]] &&
      result PASS ov-e2-reach "the sandbox $mid on $(owner "$mid") reads the store through the helper's rclone mount" ||
      result FAIL ov-e2-reach "sandbox $mid cannot read the store"
    sh_in "$mid" 'setsid nohup sh -c "i=0; while true; do i=\$((i+1)); echo \$i > /mnt/ext/log-\$i; sleep 1; done" </dev/null >/dev/null 2>&1 &' >/dev/null || true
  fi
  # Live sandboxes on the split workers: gVisor and runc, each a counter.
  : > "$sd/s2-ids"
  for i in 1 2 3; do
    for rtm in gvisor docker; do
      id="$(create "$(body "$rtm" "$ALPINE" split)")"
      [[ -n "$id" ]] && { start_counter "$id"; echo "$id" >> "$sd/s2-ids"; }
    done
  done
  [[ "$dry" == 1 ]] || sleep 30
  snapshot "$out/before.txt"; s0="$(store_count)"
  # S2: the rollout the operator runs for a version change swaps every
  # node's agent image in place, servers and gateways too.
  hm upgrade "$release" "$(chart_dir)" -n "$ns" --reuse-values --set "cluster.version=$T2" --set "image.tag=$T2" >/dev/null
  wait_until 2400 "every node reports $T2" all_at "$T2" || diag s2
  [[ "$dry" == 1 ]] || sleep 30
  snapshot "$out/after.txt"; s1="$(store_count)"
  ok=1
  for id in $(cat "$sd/s2-ids" 2>/dev/null); do answers "$id" || ok=0; done
  # Counters kept counting (none started again from 1): S2's "no sandbox
  # restarted". runtime and egress restart counts unchanged; agent +1.
  if [[ "$ok" == 1 ]] && python3 -I - "$out/before.txt" "$out/after.txt" <<'PY'
import re, sys
b, a = (open(f).read() for f in sys.argv[1:])
def counts(t): return {m[0]: int(m[1] or 0) for m in re.findall(r"sandbox (\S+) on \S* count (\d*)", t)}
def rs(t): return {m[0]: dict(re.findall(r"(\w+)=(\d+)", m[1])) for m in re.findall(r"worker (\S+) (.*?)\|", t)}
cb, ca = counts(b), counts(a)
bad = [i for i in cb if ca.get(i, 0) <= cb[i]]
rb, ra = rs(b), rs(a)
for w in rb:
    if w in ra and (ra[w].get("runtime") != rb[w].get("runtime") or ra[w].get("egress") != rb[w].get("egress")):
        bad.append("restarted:" + w)
print("not kept:", bad)
sys.exit(1 if bad else 0)
PY
  then result PASS s2 "rollout $T1 -> $T2 swapped every agent in place; every sandbox kept counting; runtime and egress containers did not restart"
  else result FAIL s2 "see $out/before.txt and after.txt"; diag s2; fi
  local p hp bad=0
  for p in $(workers_in split); do
    hp="$(helper "$p")"
    [[ "$hp" == *"aerolvm-rootd-$T2-"* ]] || { bad=1; echo "$p helper: ${hp:-none}" >> "$out/helpers.txt"; }
  done
  [[ "$bad" == 0 ]] && result PASS s2-helper-swap "every split worker now runs helper $T2 (signed hot swap), sandboxes kept" ||
    result FAIL s2-helper-swap "$(tr '\n' ';' < "$out/helpers.txt")"
  if [[ "${s1:-0}" -gt "${s0:-0}" ]] && answers "$mid"; then result PASS ov-e2-swap "the mount kept writing across the agent swap ($s0 -> $s1 files)"
  else result FAIL ov-e2-swap "store files $s0 -> $s1"; fi
  helper_restart "$(owner "$mid")" "$mid"
}
all_at() { # all_at <version>: every AerolNode reports it
  local v
  v="$(kr -n "$ns" get aerolnodes -o jsonpath='{range .items[*]}{.status.version}{"\n"}{end}' | sort -u)"
  [[ "$v" == "$1" ]]
}
# helper_restart <worker> <mount sandbox>: the helper killed; the supervisor
# empties its group (cgroup.kill on 6.12) and starts it again.
helper_restart() {
  local w="$1" mid="$2" h1 h2 p1 s0 s1 grp
  h1="$(helper "$w")"; p1="${h1%% *}"; s0="$(store_count)"
  rt "$w" kill "$p1" || true
  wait_until 90 "a new helper on $w" new_helper "$w" "$p1" || true
  h2="$(helper "$w")"
  [[ "$dry" == 1 ]] || sleep 15
  s1="$(store_count)"
  # The helper's group after the restart: only the new helper in it, and
  # the kernel's cgroup.kill there (5.14 and later; never run live before).
  if [[ "$dry" == 1 ]]; then grp="dry"; echo "dry-run: read the new helper's cgroup.procs and cgroup.kill on $w" >&2; else
  grp="$(kubectl --kubeconfig "$sd/kubeconfig" -n "$workers" exec "$w" -c runtime -- sh -c \
    'p=$(sed -n "s/^0:://p" /proc/'"${h2%% *}"'/cgroup); echo "group $p procs $(tr "\n" " " < /sys/fs/cgroup$p/cgroup.procs) kill-file $(test -e /sys/fs/cgroup$p/cgroup.kill && echo yes || echo no)"' 2>/dev/null || true)"
  fi
  echo "$h1 -> $h2; $grp; store $s0 -> $s1" > "$sd/evidence/helper-restart.txt"
  if [[ -n "$h2" && "${h2%% *}" != "$p1" ]] && answers "$mid" && [[ "${s1:-0}" -gt "${s0:-0}" || "$dry" == 1 ]]; then
    result PASS helper-restart "helper on $w restarted (${p1} -> ${h2%% *}); the mount kept writing ($s0 -> $s1); $grp"
  else result FAIL helper-restart "$(cat "$sd/evidence/helper-restart.txt")"; fi
  local id ok=1
  for id in $(cat "$sd/s2-ids" 2>/dev/null); do answers "$id" || ok=0; done
  [[ "$ok" == 1 ]] && result PASS ov-e2-helper-restart "every sandbox answers after the helper restart" ||
    result FAIL ov-e2-helper-restart "a sandbox stopped answering after the helper restart"
}
new_helper() { local h; h="$(helper "$1")"; [[ -n "$h" && "${h%% *}" != "$2" ]]; }

# --- variants: helpers the supervisor must refuse ----------------------------------------
step_variants() {
  gate
  local w reg v want since h0 h1 r0 log
  reg="$(tfout ecr_registry)"
  w="$(workers_in split | head -1)"
  need variants "$w" || return 0
  # The operator puts the release image back within seconds (swapAgent), so
  # each variant runs only briefly. An unsigned image never reaches the
  # supervisor: the agent's entrypoint stops at the missing signature
  # (exit 1) before staging anything, so its evidence is the agent's
  # previous log, not the runtime's (live run m1d-2).
  for v in unsigned:needs\ a\ signed\ root\ helper otherkey:refused.*bad_signature older:staged\ one\ is\ older; do
    want="${v#*:}"; v="${v%%:*}"
    since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; h0="$(helper "$w")"
    r0="$(kr -n "$workers" get pod "$w" -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')"
    k -n "$workers" set image "pod/$w" "agent=$reg/aerolvm:$T2-$v" >/dev/null
    wait_until 300 "agent of $w restarted on the $v image" agent_restarted "$w" "${r0:-0}" || true
    [[ "$dry" == 1 ]] || sleep 15
    log="$(kr -n "$workers" logs "$w" -c runtime --since-time="$since" 2>/dev/null | grep -E 'staged root helper|staged one' || true)"
    [[ "$v" == unsigned ]] && log="$(kr -n "$workers" logs "$w" -c agent --previous 2>/dev/null | grep 'needs a signed root helper' || true)"
    h1="$(helper "$w")"
    echo "$v: $log | helper $h0 -> $h1" >> "$sd/evidence/variants.txt"
    if grep -qE "$want" <<<"$log" && [[ "$h1" == "$h0" ]]; then result PASS "helper-$v" "refused ($want); the running helper ${h0%% *} kept"
    else result FAIL "helper-$v" "log: ${log:-none}; helper $h0 -> $h1"; fi
  done
  k -n "$workers" set image "pod/$w" "agent=$reg/aerolvm:$T2" >/dev/null
  r0="$(kr -n "$workers" get pod "$w" -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')"
  wait_until 300 "agent of $w back on $T2" agent_restarted "$w" "$(( ${r0:-1} - 1 ))" || true
}
agent_restarted() {
  local n r
  n="$(kr -n "$workers" get pod "$1" -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')"
  r="$(kr -n "$workers" get pod "$1" -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].ready}')"
  [[ "${n:-0}" -gt "$2" && "$r" == true ]]
}

# --- F10 ----------------------------------------------------------------------------
step_f10() {
  gate
  local w out="$sd/evidence/f10" ids=() id i r0 h0 u0 dead=0 alive=0 killed
  mkdir -p "$out"
  w="$(workers_in split | tail -1)"
  need f10 "$w" || return 0
  r0="$(restarts "$w")"; h0="$(helper "$w")"; u0="$(uid_of "$w")"
  for p in $(worker_pods); do [[ "$p" == "$w" ]] || api_cordon "$p"; done
  for i in $(seq 1 "${M1_F10_SANDBOXES:-5}"); do
    id="$(create "{\"runtime\":\"gvisor\",\"image\":\"$ALPINE\",\"cpu\":0.5,\"memory_mb\":4096}")"
    [[ -n "$id" ]] && ids+=("$id")
  done
  for p in $(worker_pods); do [[ "$p" == "$w" ]] || api_uncordon "$p"; done
  say "f10: ${#ids[@]} sandboxes on $w; each holds ${M1_F10_FILL_MB:-3072} MB of memory at once"
  # Anonymous memory, not /dev/shm: a gVisor sandbox's /dev/shm is 64 MB,
  # so a dd there never pressed on memory (live run m1d-2). busybox tail -c
  # keeps the bytes in its buffer, and sleep never reads them, so each
  # sandbox holds the fill for a minute.
  local fill=$(( ${M1_F10_FILL_MB:-3072} * 1048576 ))
  for id in "${ids[@]}"; do
    ( sh_in "$id" "head -c $fill /dev/zero | tail -c $fill | sleep 60; echo held" > "$out/fill-$id.txt" 2>&1 || true ) &
  done
  wait
  [[ "$dry" == 1 ]] || sleep 20
  for id in "${ids[@]}"; do if answers "$id"; then alive=$((alive + 1)); else dead=$((dead + 1)); fi; done
  killed="$(node_sh "$(machine_of "$w")" 'dmesg | grep -iE "Killed process|oom-kill" | tail -40')"
  echo "$killed" > "$out/dmesg.txt"
  echo "before: $r0 | $h0 | uid $u0" > "$out/machinery.txt"
  echo "after:  $(restarts "$w") | $(helper "$w") | uid $(uid_of "$w")" >> "$out/machinery.txt"
  local machinery_ok=0
  if [[ "$(restarts "$w")" == "$r0" && "$(helper "$w")" == "$h0" && "$(uid_of "$w")" == "$u0" ]] &&
     ! grep -qE 'Killed process [0-9]+ \((containerd|sandboxd|aerolvm-rootd|aerolvm-superv|toolboxd-host)' "$out/dmesg.txt"; then machinery_ok=1; fi
  id="$(only_on "$w" create "$(body gvisor "$ALPINE")")"
  if [[ "$dry" == 1 ]] || [[ "$dead" -ge 1 && "$machinery_ok" == 1 && -n "$id" ]]; then
    result PASS f10 "$dead of ${#ids[@]} sandboxes killed whole, $alive kept; agent, runtime, egress and helper untouched; a new create works"
  elif [[ "$dead" == 0 ]]; then result FAIL f10 "the sandboxes' cap was not reached (raise M1_F10_FILL_MB or M1_F10_SANDBOXES)"
  else result FAIL f10 "machinery hit: $(tr '\n' ';' < "$out/machinery.txt"); see $out/dmesg.txt"; diag f10; fi
  for id in "${ids[@]}"; do api DELETE "/v1/sandboxes/$id" >/dev/null || true; done
}

# --- F8 -----------------------------------------------------------------------------
step_f8() {
  gate
  local w m uid u t0 out="$sd/evidence/f8.txt" newuid check
  w="$(workers_in split | head -1)"
  need f8 "$w" || return 0
  m="$(machine_of "$w")"; uid="$(uid_of "$w")"; u="${uid//-/_}"
  [[ -n "$uid" && -n "$m" ]] || { result FAIL f8 "no pod uid or machine for $w"; return 0; }
  only_on "$w" create "$(body gvisor "$ALPINE")" >/dev/null
  only_on "$w" create "$(body docker "$ALPINE")" >/dev/null
  # The delete guard (C26) refuses a plain delete; the drill means it.
  k -n "$workers" annotate pod "$w" aerolvm.io/force-delete=true --overwrite >/dev/null
  t0=$(now)
  if k -n "$workers" delete pod "$w" --wait=true --timeout=180s >/dev/null; then
    say "f8: $w deleted in $(( $(now) - t0 ))s with sandboxes running"
  else result FAIL f8 "the pod did not go within 180 s (stuck Terminating?)"; diag f8; return 0; fi
  [[ "$dry" == 1 ]] || sleep 20
  newuid="$(kr -n "$workers" get pods -l app.kubernetes.io/component=worker --field-selector "spec.nodeName=$m" -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true)"
  # The kubelet's own pod namespaces are /run/netns/cni-*. Anything else
  # there, any mount naming the old pod or the helper (other than the new
  # pod's), any cgroup or process of the old pod, is left behind.
  check="m=\$(grep -e aerolvm-rootd -e /run/netns/ -e '$uid' /proc/1/mountinfo | grep -v /run/netns/cni- | grep -v '${newuid:-none}' | wc -l);
n=\$(ls /run/netns 2>/dev/null | grep -vc '^cni-');
d=\$(ls -d /var/lib/kubelet/pods/$uid 2>/dev/null | wc -l);
c=\$(find /sys/fs/cgroup -name '*$u*' 2>/dev/null | wc -l);
p=\$(grep -l '$u' /proc/[0-9]*/cgroup 2>/dev/null | wc -l);
echo \"F8 mounts=\$m netns=\$n poddir=\$d cgroups=\$c procs=\$p\""
  node_sh "$m" "$check" > "$out"
  if [[ "$dry" == 1 ]] || grep -q 'F8 mounts=0 netns=0 poddir=0 cgroups=0 procs=0' "$out"; then
    result PASS f8 "deleting split worker $w with sandboxes running left nothing on $m ($(cat "$out" 2>/dev/null))"
  else result FAIL f8 "left on $m: $(tr '\n' ' ' < "$out")"; fi
  wait_until 900 "a worker on $m Serving again" new_on "$m" "$w" || diag f8
}

# verifynow: aerolvm k8s verify on its own, as M1_VERIFY_LABEL (a resumed run
# takes the verify its stopped step did not reach).
step_verifynow() { gate; verify "${M1_VERIFY_LABEL:-now}"; }

step_final() {
  gate
  verify final
  kr -n "$ns" get aerolcluster,aerolnodes -o wide > "$sd/evidence/final-nodes.txt" 2>&1 || true
  [[ "$dry" == 1 ]] || { echo "--- results"; cat "$sd/m1.txt"; } | tee "$sd/evidence/summary.txt"
}

step_down() {
  same_account
  gw_keeper_stop
  # The chart goes only from the run's own cluster: a kubeconfig that names
  # another context is never used (cluster.sh down still runs; it checks the
  # account and works from the run's Terraform state).
  if [[ "$dry" == 1 ]] || ctx_ok; then
    hm uninstall "$release" -n "$ns" --wait --timeout 10m >/dev/null 2>&1 || true
    # The servers' volumes (claims the operator made): deleted while the
    # CSI driver still runs, so they go now, not at the reaper.
    k -n "$ns" delete pvc --all --wait=true --timeout=5m >/dev/null 2>&1 || true
  fi
  # The commit's source copy (.state/<name>/src-*) stays with the run's
  # evidence; remove the folder by hand once the leak check is clean.
  x "$K8S/cluster.sh" down "$name"
  [[ "$dry" == 1 ]] || date +%s > "$sd/cost-end"
  x "$HERE/leak-check.sh" "$name" "${M1_VM_NAME:-$name-vm}" | tee "$sd/leaks.txt" || say "down: something is left; see $sd/leaks.txt"
  cost_check down || true
}

# --- cost and results -------------------------------------------------------------
# cost_check <step>: the run's spend so far and its projection (cost.py
# --running), logged after every step. Past M1_COST_LIMIT ($6.15, the
# plan's worst case) it returns 4 and the run stops and tears down.
vm_sd="$K8S/.state/${M1_VM_NAME:-$name-vm}"
cost_check() {
  [[ "$dry" == 1 ]] && { echo "dry-run: (cost check after $1)" >&2; return 0; }
  echo "$1" >> "$sd/done-steps"
  local out rc=0
  out="$(python3 -I "$HERE/cost.py" --running --limit "${M1_COST_LIMIT:-6.15}" --vm-hours "${M1_VM_HOURS:-1.5}" \
    --cell-start "$(cat "$sd/cost-start" 2>/dev/null || echo 0)" --cell-end "$(cat "$sd/cost-end" 2>/dev/null || echo 0)" \
    --done "$(paste -sd, "$sd/done-steps")" \
    --vm-start "$(cat "$vm_sd/started-at" 2>/dev/null || echo 0)" --vm-end "$(cat "$vm_sd/ended-at" 2>/dev/null || echo 0)")" || rc=$?
  say "after $1: $out"
  echo "$(date -u +%FT%TZ) after $1: $out" >> "$sd/cost.log"
  return "$rc"
}
stop_run() { # stop_run <why>: evidence, then teardown, then out
  say "STOP: $1"
  result FAIL run-stopped "$1"
  diag stop
  step_down || true
  torn=1
  exit 5
}

# --- running steps ------------------------------------------------------------------
core=(up setup build install)
checks=(kernel switch1 shape n1 switch2 moves switch3 s2 variants f10 f8 final)
run_check() {
  local s="$1" rc=0
  ( set -e; "step_$s" ) || rc=$?
  # Exit 2 is the gate's refusal: nothing more is read or changed.
  if [[ "$rc" == 2 ]]; then result FAIL "$s" "refused by the gate (see above)"
  elif [[ "$rc" != 0 ]]; then result FAIL "$s" "the step exited $rc"; diag "$s"; fi
  return 0
}
steps=("$@")
# up runs the estimate first (and stops past the ceiling).
[[ "${steps[*]}" == all ]] && steps=("${core[@]}" "${checks[@]}" down)
torn=0
on_exit() {
  local rc=$?
  gw_keeper_stop
  # Only a run that made something, and was not refused, is torn down.
  if [[ "$rc" != 0 && ( "${1:-}" == all || "${M1_TEARDOWN_ON_EXIT:-0}" == 1 ) && "${M1_KEEP:-0}" != 1 && "$torn" == 0 && "$dry" != 1 &&
        "$refused" == 0 && -f "$sd/terraform.tfstate" ]]; then
    say "the run stopped (exit $rc): tearing down (M1_KEEP=1 keeps it)"
    diag exit || true
    step_down || true
  fi
}
trap 'on_exit "$*"' EXIT
for s in "${steps[@]}"; do
  case "$s" in
    estimate|up|setup|build|install) "step_$s" ;;
    down) step_down; torn=1 ;;
    # The API's port-forward keeper, from this (the main) shell: each check
    # runs in a subshell, which must never own the forward (m1-lib.sh). It
    # starts only once the gate passes: a kubeconfig the gate refuses may
    # name another cluster. run_check then shows the refusal.
    kernel|switch1|shape|n1|switch2|moves|switch3|s2|variants|f10|f8|final|verifynow)
      if ( gate ) 2>/dev/null; then gw_keeper_start; fi
      run_check "$s" ;;
    *) echo "m1-eks.sh: unknown step $s" >&2; exit 2 ;;
  esac
  if [[ "$s" != down && "$s" != estimate ]]; then
    cost_check "$s" || [[ "$dry" == 1 ]] || stop_run "the projected cost passed \$${M1_COST_LIMIT:-6.15} after $s"
  fi
  # A blocker: with no split worker after the first switch, nothing after
  # it can prove anything: evidence, teardown, report.
  if [[ "$s" == switch1 && "$dry" != 1 && -z "$(workers_in split)" ]]; then
    stop_run "no worker came back in split after the first switch"
  fi
done

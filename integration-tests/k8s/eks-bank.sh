#!/usr/bin/env bash
# eks-bank.sh: the bank run on EKS. The image-pull and SLO-breach drills
# (issue #1343) and enterprise mode on Kubernetes (issue #1349), on a real
# three-zone cell that installs charts/aerolvm/values-bank-eks.yaml as a bank
# would, then 60 workers for an hour.
#
#   eks-bank.sh <name> estimate             # the cost table; makes nothing
#   eks-bank.sh <name> all                  # every step below, then down
#   eks-bank.sh <name> <step> [step...]
#   DRY_RUN=1 eks-bank.sh <name> all        # print every AWS, Terraform,
#                                           # kubectl and Helm call; make nothing
#
# Run it from a checkout of the commit under test (merged main): the images,
# the chart and the aerolvm CLI all come from that commit (cell.sh's
# git-archive build, or AEROL_BUILD_REF), built inside the cluster. Nothing
# large leaves this machine: the source goes to S3 (~12 MB), the drill
# images are pushed from a pod in the cluster, and every load generator
# runs in a pod.
#
# Steps, in the order `all` runs them:
#   estimate   the planned and the worst-case cost, step by step. Refuses
#              (exit 3) when the worst case passes EKS_BANK_CEILING ($45).
#   up         estimate, then cluster.sh up: EKS over three zones, 6 system
#              nodes (m7i.xlarge), no worker node group (Karpenter makes
#              every worker), IRSA, the audit buckets, the load balancer
#              controller's role, ECR repositories, and the teardown timer
#              (a Lambda AWS calls at the TTL, EKS_BANK_TTL, 6h).
#   build      the commit's images, the edge image too, built in the cluster.
#   install    cert-manager, the run's private CA, a gp3 class whose volumes
#              carry the run's tags, the AWS Load Balancer Controller,
#              Karpenter's NodePool, kube-prometheus-stack, then the chart:
#              values-bank-eks.yaml with drills-eks/values-run.yaml over it.
#              Waits for the cell and its 6 workers.
#   enterprise every node in enterprise mode with no restarts; the witness
#              heads and export objects in S3 through IRSA; a locked head
#              cannot be deleted; one operator API token.
#   nlb        the gateways' internal NLB: internal, every target healthy,
#              private addresses only; through it, from a pod, the API over
#              the run's CA answers, the admin token is refused, an API token
#              works. Makes the run's admin API token ($sd/api-token).
#   gvisor     a sandbox runs under gVisor on Amazon Linux 2023 (its worker
#              from the placement route, /v1/cluster/placements/{id});
#              runc refused.
#   verify     aerolvm k8s verify on the live enterprise install.
#   drills     drills-eks.sh, once for each of setup static pull-storm
#              slo-breach large-layers ecr-push (each a check of its own;
#              after a failed setup the rest are recorded as skipped), or
#              only those EKS_BANK_DRILLS names.
#   gateways11 11 gateways (the shard-aware opt-in is on every node), then
#              drills-eks.sh shard-routes, then back to 3. shard-routes is
#              part of this step, not an EKS_BANK_DRILLS name: it runs
#              whenever gateways11 does.
#   scale      fills the cell past its workers' free CPU (fillers sized from
#              the members and the create policy) until the operator adds
#              a worker, then 60 workers; ecr-storm and thresholds at 60
#              (or those of them EKS_BANK_DRILLS names; the other is a SKIP
#              line); back to 6. A peak drill the time box cuts off, or
#              that never starts, is a FAIL line. Time-boxed (EKS_BANK_SCALE_MINUTES, 60) with
#              three guards: the NodePool's CPU limit, an EXIT trap that
#              scales back, and an AWS schedule that runs the teardown
#              Lambda's scale-cap phase if this machine is gone.
#   down       the chart (its load balancer and volumes first), the scale-cap
#              schedule, then cell.sh down (cluster.sh down: Terraform
#              destroy, the GOVERNANCE-locked witness bucket emptied with the
#              bypass). Then lists anything left tagged with the run.
#
# up, build and install are what every later step needs: one that fails
# ends the run (and `all` tears it down). The steps after them are checks:
# one that fails is recorded "FAIL <step> exited N", and the run goes on to
# the next one, then down; `all` then exits 1 (run_check).
#
# The gate: every step after up talks only to the kubeconfig cluster.sh
# wrote for <name>, and only if its context is that EKS cluster, the run
# was made with --bank-drills, and this machine's AWS credentials are that
# cluster's account (drills-eks.sh holds the same gate). Never KUBECONFIG,
# KUBECTL_CONTEXT or ~/.kube/config.
#
# Settings: DRY_RUN (0 or 1, nothing else). EKS_BANK_CEILING ($45),
# EKS_BANK_TTL (6h), EKS_BANK_SYSTEM (6), EKS_BANK_BASE_WORKERS (6),
# EKS_BANK_PEAK_WORKERS (60), EKS_BANK_SCALE_MINUTES (60),
# EKS_BANK_BACK_MINUTES (20), EKS_BANK_GATEWAYS (11), EKS_BANK_PRICE_*.
# EKS_BANK_DRILLS: the drills to run, names separated by commas, spaces or
# newlines; unset or empty: all of them. The drills step's: setup static
# pull-storm slo-breach large-layers ecr-push; the scale step's peak:
# ecr-storm thresholds. setup always runs, and ecr-storm brings ecr-push
# (its images, pushed at 6 workers, not at the peak). estimate prices only
# these. A value with no names in it, or a name that is not a drill,
# refuses the run (exit 2), before any AWS call; it is read only when the
# steps include up, estimate, drills, scale or all, so a value left over in
# the shell never stops down.
# EKS_BANK_KEEP=1: `all` leaves the run up when a step fails (by default it
# tears it down). EKS_BANK_ACCEPT_ACCOUNT_COSTS=1: go on although the
# account adds costs of its own (up names them). EKS_BANK_CHART_DIR: a chart
# folder to check and install instead of the build commit's.
#
# The run's Terraform state is in .state/<name>/ beside this script
# (git-ignored), in this checkout. Do not remove the checkout or its
# ignored files (a worktree cleanup, git clean -x) while a run is up: down
# needs that state. If it is lost, reap.sh still finds every part of the run
# by its tags once its TTL has passed.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
name="${1:?usage: eks-bank.sh <name> <step> [step...] (estimate up build install enterprise nlb gvisor verify drills gateways11 scale down all)}"
shift
[[ $# -gt 0 ]] || { echo "eks-bank.sh: name the steps (or all)" >&2; exit 2; }
HELM="${HELM:-helm}"
# helm_fetch: every chart this run fetches comes through it, with no registry
# credentials and a time limit (HELM_FETCH_SECONDS).
# shellcheck source=helm-fetch.sh
source "$HERE/helm-fetch.sh"
# pf_start / pf_stop: every port-forward the run makes is kubectl itself,
# waited for until it forwards, on a local port nothing else answers on.
# shellcheck source=port-forward.sh
source "$HERE/port-forward.sh"
# 0 or 1 only: any other spelling ("true", "yes") would start a live run.
case "${DRY_RUN:-0}" in
  0|1) dry="${DRY_RUN:-0}" ;;
  *) echo "eks-bank.sh: DRY_RUN must be 0 or 1, not \"$DRY_RUN\"; nothing ran" >&2; exit 2 ;;
esac

# A refusal never tears anything down (on_exit): it may be the wrong
# credentials, under which Terraform would forget the run's resources.
refused=0
refuse() { echo "eks-bank.sh: refusing to run: $*" >&2; refused=1; exit 2; }
[[ "$name" =~ ^[a-z][a-z0-9-]{2,30}$ ]] || refuse "\"$name\" is not a cluster.sh run name"

# --- the run's shape (each one an input of the estimate) -----------------------
ceiling="${EKS_BANK_CEILING:-45}"
ttl="${EKS_BANK_TTL:-6h}"
system_nodes="${EKS_BANK_SYSTEM:-6}"
base_workers="${EKS_BANK_BASE_WORKERS:-6}"
peak_workers="${EKS_BANK_PEAK_WORKERS:-60}"
scale_minutes="${EKS_BANK_SCALE_MINUTES:-60}"
back_minutes="${EKS_BANK_BACK_MINUTES:-20}"
gateways_peak="${EKS_BANK_GATEWAYS:-11}"
# The drills each step runs (parse_drills): the drills step's, in this
# order, and the scale step's peak drills. Without EKS_BANK_DRILLS, all.
step_drills=(setup static pull-storm slo-breach large-layers ecr-push)
peak_drills=(ecr-storm thresholds)
all_drills=("${step_drills[@]}" "${peak_drills[@]}")
run_drills_list=("${step_drills[@]}")
run_peak_list=("${peak_drills[@]}")
# parse_drills: EKS_BANK_DRILLS into run_drills_list and run_peak_list. The
# drills run in the order above whatever order they are named in. setup is
# always one of them, first: every other drill needs its registry,
# Prometheus, receiver and client pod, and a run's cell is new. ecr-storm
# brings ecr-push: without its images, ecr-storm pushed 200 of them itself
# at the peak, and the time box ended it mid-push with no result. Unset or
# empty: all of them. No names, or a name that is not a drill: refused.
parse_drills() {
  [[ -n "${EKS_BANK_DRILLS:-}" ]] || return 0
  local asked=() named=" " d
  IFS=$', \t\n' read -r -d '' -a asked <<<"$EKS_BANK_DRILLS" || true
  for d in ${asked[@]+"${asked[@]}"}; do
    [[ -n "$d" ]] || continue
    [[ " ${all_drills[*]} " == *" $d "* ]] ||
      refuse "EKS_BANK_DRILLS: \"$d\" is not a drill (${all_drills[*]})"
    named+="$d "
  done
  [[ "$named" != " " ]] || refuse "EKS_BANK_DRILLS has no drill names in it (${all_drills[*]}); unset it to run them all"
  [[ "$named" != *" ecr-storm "* ]] || named+="ecr-push "
  run_drills_list=()
  for d in "${step_drills[@]}"; do
    if [[ "$d" == setup || "$named" == *" $d "* ]]; then run_drills_list+=("$d"); fi
  done
  run_peak_list=()
  for d in "${peak_drills[@]}"; do
    if [[ "$named" == *" $d "* ]]; then run_peak_list+=("$d"); fi
  done
}
# Each drill's hours for the estimate: the fifth run's times (setup 4.5 min,
# static 1.5, pull-storm 35, slo-breach 49, large-layers 3.5, ecr-push 51),
# each rounded up to 0.05 h with its drills-eks.sh start. All six: 2.6 h
# (that run's drills step took 2.4).
drill_hours() {
  case "$1" in
    setup) echo 0.1 ;; static) echo 0.05 ;; pull-storm) echo 0.6 ;;
    slo-breach) echo 0.85 ;; large-layers) echo 0.1 ;; ecr-push) echo 0.9 ;;
  esac
}
# The local ports of the run's port-forwards: server-0's admin port (the
# admin token's calls), a gateway's API port (the API token's), and verify's.
admin_lport=19219
gw_lport=19212
verify_lport=19220
ns=aerolvm-system
workers=aerolvm-workers
release=aerolvm
cname=aerolvm
# The AWS Load Balancer Controller, checked by the digest its chart index
# publishes (lb-controller-iam-policy.json is the same release's policy).
LBC_CHART_VERSION=3.6.2
LBC_CHART_SHA256=9255bf39873b6cb31106dbe61dc87c3617bff4197783b5b94381811a13f99c3c
# terraform/lb-controller-iam-policy.json, as the controller publishes it
# for this release (docs/install/iam_policy.json at v3.6.2).
LBC_POLICY_SHA256=16f232c9d9f79366fe949c4550ad517a202380058a9e48d45a4e215044a20a6a
CERT_MANAGER_VERSION=v1.21.3
CERT_MANAGER_SHA256=c04a51295adda2b1a775146751f973e787190778c7f35180861d9678876e5c74

sd="$HERE/.state/$name"
if [[ "$dry" == 1 ]]; then
  sd="${EKS_BANK_DRY_DIR:-$(mktemp -d)}"
fi
mkdir -p "$sd"
# on_exit's mark that a teardown follows (check_exit reads it): never one an
# earlier run left.
rm -f "$sd/.teardown-next"
# Where this run's lines begin in bank.txt and in the drills' drills.txt (an
# earlier run's FAIL lines are not this run's answer).
bank_mark=0
[[ ! -f "$sd/bank.txt" ]] || bank_mark="$(wc -l < "$sd/bank.txt" | tr -d ' ')"
drills_mark=0
[[ ! -f "$sd/drills/drills.txt" ]] || drills_mark="$(wc -l < "$sd/drills/drills.txt" | tr -d ' ')"
log="$sd/bank.log"
say() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$log" >&2; }
result() {
  if [[ "$dry" == 1 ]]; then
    # A SKIP is decided before anything runs, so a dry run can show it.
    if [[ "$1" == SKIP ]]; then echo "dry-run: SKIP $2 $3" >&2; else echo "dry-run: (no result in a dry run) $2" >&2; fi
    return 0
  fi
  echo "$1 $2 $3" | tee -a "$sd/bank.txt" "$log"
}
now() { date +%s; }

# x <cmd...>: run it, or in a dry run print it (and the manifest it would
# read from stdin) and run nothing. Every call that reaches AWS or the
# cluster goes through x.
x() {
  if [[ "$dry" == 1 ]]; then
    printf 'dry-run:' >&2; printf ' %q' "$@" >&2; printf '\n' >&2
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
# kr <args>: a kubectl read whose answer the script uses; empty in a dry run.
kr() { [[ "$dry" == 1 ]] && return 0; kubectl --kubeconfig "$sd/kubeconfig" "$@"; }
tfout() {
  if [[ "$dry" == 1 ]]; then
    case "$1" in
      zones) echo '["us-east-1a","us-east-1b","us-east-1c"]' ;;
      region) echo us-east-1 ;;
      ecr_registry) echo "111122223333.dkr.ecr.us-east-1.amazonaws.com/$name" ;;
      *) echo "dry-$1" ;;
    esac
    return 0
  fi
  # Strings raw, lists (zones) as JSON.
  TF_DATA_DIR="$sd/.terraform" terraform -chdir="$HERE/terraform" output -state="$sd/terraform.tfstate" -json "$1" |
    jq -r 'if type == "string" then . else tojson end'
}

# --- the gate ---------------------------------------------------------------------
gate() {
  [[ "$dry" == 1 ]] && return 0
  [[ -f "$sd/kubeconfig" && -f "$sd/run.tfvars.json" ]] ||
    refuse "no cluster.sh state for $name in $sd (only a cluster cluster.sh made)"
  python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("name") == sys.argv[2] and d.get("bank_drills") is True else 1)' \
    "$sd/run.tfvars.json" "$name" || refuse "$name was not made with cluster.sh --bank-drills"
  local ctx
  ctx="$(KUBECONFIG="$sd/kubeconfig" kubectl config current-context 2>/dev/null || true)"
  [[ "$ctx" =~ ^arn:aws:eks:[a-z0-9-]+:[0-9]{12}:cluster/${name}$ ]] ||
    refuse "the kubeconfig cluster.sh wrote for $name names context \"$ctx\", not that EKS cluster"
  # And this machine's AWS credentials are that cluster's account: every aws
  # call the steps make (S3, ELB, EC2, ECR) lands in it.
  local acct
  acct="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
  [[ "$(cut -d: -f5 <<<"$ctx")" == "$acct" ]] ||
    refuse "this machine's AWS credentials are for account \"$acct\", the cluster is in $(cut -d: -f5 <<<"$ctx")"
  gated=1
}
# same_account: down without a kubeconfig (a run that died early) checks
# this machine's account against the one cluster.sh up recorded, before any
# AWS call.
same_account() {
  [[ "$dry" == 1 ]] && return 0
  local want got
  want="$(jq -r '.aws_account // ""' "$sd/run.tfvars.json" 2>/dev/null || true)"
  [[ -n "$want" ]] || return 0
  got="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
  [[ "$got" == "$want" ]] || refuse "this machine's AWS credentials are for account \"$got\"; $name was made in $want"
}

# --- estimate -----------------------------------------------------------------
# On-demand prices in us-east-1 (USD, AWS's price list as of 2026-11; each
# can be overridden): m7i.xlarge, the EKS control plane, a public IPv4
# address, an NLB (one LCU), gp3 per GB-month. The allowance covers ECR and
# S3 storage, CloudWatch logs, the Lambda, and cross-zone traffic (the 3 GiB
# layer drill moves about 18 GB across zones).
estimate() {
  local d dh=0
  for d in "${run_drills_list[@]}"; do dh="$(awk "BEGIN {print $dh + $(drill_hours "$d")}")"; done
  EKS_BANK_STEPS="up=0.4 build=0.25 install=0.3 checks=0.25 drills=$dh gateways11=0.25 scale=$(awk "BEGIN {print ($scale_minutes + $back_minutes) / 60}") down=0.3" \
  EKS_BANK_DRILLS_PRICED="${run_drills_list[*]}" \
  EKS_BANK_ESTIMATE_JSON="$sd/estimate.json" \
  python3 -I - "$ceiling" "$ttl" "$system_nodes" "$base_workers" "$peak_workers" "$scale_minutes" "$back_minutes" <<'PY' | tee "$sd/estimate.txt"
import os, sys
ceiling, ttl, system, base, peak, box, back = sys.argv[1:]
ceiling, system, base, peak, box, back = float(ceiling), int(system), int(base), int(peak), float(box), float(back)
ttl_h = float(ttl[:-1]) / (60 if ttl.endswith("m") else 1)
p = lambda k, d: float(os.environ.get("EKS_BANK_PRICE_" + k, d))
vm, eks, ip, nlb, gp3 = p("M7I_XLARGE", 0.2016), p("EKS", 0.10), p("IPV4", 0.005), p("NLB", 0.0285), p("GP3_GB_MONTH", 0.08) / 730
allowance = p("ALLOWANCE", 3.0)
# Disks: system 50 GiB, workers 60 GiB, 3 servers 10 GiB, the drill registry 100 GiB.
disk_gb = system * 50 + base * 60 + 3 * 10 + 100
base_h = eks + (system + base) * (vm + ip) + nlb + disk_gb * gp3
worker_h = vm + ip + 60 * gp3
extra_h = (peak - base) * worker_h
# The drills fill every worker (slo-breach), and the operator buys up to the
# NodePool's limit outside the scale step: 2 machines over the base.
drill_extra_h = 2 * worker_h
steps = [kv.split("=") for kv in os.environ["EKS_BANK_STEPS"].split()]
total_h = sum(float(h) for _, h in steps)
print(f"{'step':<12}{'hours':>7}{'USD':>9}   (base cell: ${base_h:.2f}/h = EKS, {system} system + {base} worker m7i.xlarge, NLB, {disk_gb} GB gp3)")
planned = 0.0
for step, h in steps:
    h = float(h)
    c = base_h * h
    if step == "scale":
        # Workers above the base: the climb and the way back average half.
        c += extra_h * (box / 60 + 0.5 * back / 60)
    if step == "drills":
        c += drill_extra_h * h
    planned += c
    print(f"{step:<12}{h:>7.2f}{c:>9.2f}" + (f"   ({os.environ['EKS_BANK_DRILLS_PRICED']})" if step == "drills" else ""))
planned += allowance
# Worst case: nothing torn down until the teardown timer (compute at the
# TTL, the control plane 30-60 min later), and the 60 workers held until
# the scale-cap schedule fires (box + back + 15 min).
worst = (base_h + drill_extra_h) * ttl_h + eks * 1.0 + extra_h * (box + back + 15) / 60 + allowance
with open(os.environ["EKS_BANK_ESTIMATE_JSON"], "w") as fh:
    fh.write('{"planned": %.2f, "worst": %.2f, "ceiling": %.2f}\n' % (planned, worst, ceiling))
print(f"{'allowance':<12}{'':>7}{allowance:>9.2f}")
print(f"planned: ${planned:.2f} over {total_h:.1f} h; worst case (teardown timer at {ttl_h:g} h): ${worst:.2f}; ceiling ${ceiling:.2f}")
if total_h > ttl_h:
    print(f"REFUSED: the plan takes {total_h:.1f} h, past the {ttl_h:g} h teardown timer; raise EKS_BANK_TTL")
    sys.exit(3)
if worst > ceiling:
    print(f"REFUSED: the worst case ${worst:.2f} passes the ceiling ${ceiling:.2f} (EKS_BANK_CEILING)")
    sys.exit(3)
PY
}

# --- the chart -------------------------------------------------------------------
# chart_dir: the chart the run installs, the build commit's (or
# EKS_BANK_CHART_DIR, a chart folder to use instead).
chart_dir() {
  if [[ -n "${EKS_BANK_CHART_DIR:-}" ]]; then echo "$EKS_BANK_CHART_DIR"; else echo "$(src_tree)/charts/aerolvm"; fi
}
# render_values <out> <registry> <tag> <zones> <witness> <export> <region> <audit role>:
# drills-eks/values-run.yaml with the run's values in.
render_values() {
  sed -e "s|@@REGISTRY@@|$2|" -e "s|@@TAG@@|$3|g" -e "s|@@ZONES@@|$4|" \
    -e "s|@@DOMAIN@@|bank.$name.internal|" -e "s|@@WITNESS@@|$5|" -e "s|@@EXPORT@@|$6|" -e "s|@@REGION@@|$7|g" \
    -e "s|@@AUDIT_ROLE@@|$8|" -e "s|@@ECR_HOST@@|${2%%/*}|" \
    -e "s|@@BASE_WORKERS@@|$base_workers|" -e "s|@@PEAK_WORKERS@@|$peak_workers|" \
    "$HERE/drills-eks/values-run.yaml" > "$1"
}
# enterprise_guard: the chart, rendered as the install will render it (with
# stand-ins for what Terraform has not made yet), gives every node template
# enterprise mode and the audit witness and export. Run before Terraform: a
# commit without enterprise mode would spend the budget on nothing.
enterprise_guard() {
  local chart vals
  chart="$(chart_dir)"
  vals="$sd/values-guard.yaml"
  render_values "$vals" "guard.invalid/$name" v0.0.0-guard '"us-east-1a", "us-east-1b", "us-east-1c"' \
    guard-witness guard-export us-east-1 arn:aws:iam::000000000000:role/guard
  if ! "$HELM" template "$release" "$chart" -n "$ns" -f "$chart/values-bank-eks.yaml" -f "$vals" > "$sd/guard-render.yaml" 2> "$sd/guard-render.err"; then
    say "up: the chart at $chart does not render the bank values: $(head -3 "$sd/guard-render.err")"
    return 1
  fi
  if ! python3 -I "$HERE/drills-eks/chart_guard.py" "$sd/guard-render.yaml" SB_ENTERPRISE_MODE=true \
      SB_AUDIT_WITNESS_S3_BUCKET=guard-witness SB_AUDIT_EXPORT_BACKEND=s3 SB_AUDIT_EXPORT_S3_BUCKET=guard-export \
      > "$sd/guard.txt"; then
    say "up: the chart at $chart does not run enterprise mode with the audit store on every node: $(head -4 "$sd/guard.txt" | tr '\n' ';')"
    return 1
  fi
}

# account_costs: what this AWS account adds to the run on its own, read
# with read-only calls. Each refuses the run unless
# EKS_BANK_ACCEPT_ACCOUNT_COSTS=1; a check that cannot be read refuses too.
#   Inspector's enhanced ECR scanning: about $0.09 an image pushed (the
#     cell's 4 images and the ECR drill's DRILL_ECR_IMAGES + 1, ~$18).
#   AWS Config recording: about $0.003 a resource change; this run's
#     machines and their disks and interfaces, ~$4.
#   GuardDuty runtime monitoring: about $2 of vCPU-hours, and with its
#     agent managed, a VPC endpoint that keeps the VPC from being deleted.
account_costs() {
  if [[ "$dry" == 1 ]]; then
    echo "dry-run: read Inspector's ECR scanning, AWS Config recording and GuardDuty runtime monitoring (read-only)" >&2
    return 0
  fi
  local region=us-east-1 found=() extra=0 v
  v="$(aws inspector2 batch-get-account-status --region "$region" --query 'accounts[0].resourceState.ecr.status' --output text 2>/dev/null)" || v=unreadable
  if [[ "$v" != DISABLED ]]; then
    found+=("Inspector enhanced ECR scanning ($v): about \$$(awk "BEGIN {printf \"%.0f\", (5 + ${DRILL_ECR_IMAGES:-200}) * 0.09}")")
    extra=$(awk "BEGIN {print $extra + (5 + ${DRILL_ECR_IMAGES:-200}) * 0.09}")
  fi
  v="$(aws configservice describe-configuration-recorder-status --region "$region" --query 'ConfigurationRecordersStatus[?recording] | length(@)' --output text 2>/dev/null)" || v=unreadable
  if [[ "$v" != 0 ]]; then
    found+=("AWS Config recording ($v recorder(s) on): about \$4")
    extra=$(awk "BEGIN {print $extra + 4}")
  fi
  local det on=""
  if det="$(aws guardduty list-detectors --region "$region" --query 'DetectorIds' --output text 2>/dev/null)"; then
    local got
    for v in $det; do
      [[ "$v" == None ]] && continue
      # A detector that cannot be read counts as on.
      if ! got="$(aws guardduty get-detector --region "$region" --detector-id "$v" --output json 2>/dev/null)"; then
        on=unreadable
        continue
      fi
      jq -e '[.Features[]? | select((.Name == "RUNTIME_MONITORING" or .Name == "EKS_RUNTIME_MONITORING") and .Status == "ENABLED")] | length > 0' \
        <<<"$got" >/dev/null && on="${on:-1}"
    done
  else
    on=unreadable
  fi
  if [[ -n "$on" ]]; then
    found+=("GuardDuty runtime monitoring (${on/1/on}): about \$2, and its VPC endpoint can keep the VPC from being deleted")
    extra=$(awk "BEGIN {print $extra + 2}")
  fi
  [[ ${#found[@]} -eq 0 ]] && return 0
  printf 'up: this account adds to the run: %s\n' "${found[@]}" | tee -a "$log" >&2
  if [[ "${EKS_BANK_ACCEPT_ACCOUNT_COSTS:-0}" != 1 ]]; then
    say "up: refused; turn those off for the run, or set EKS_BANK_ACCEPT_ACCOUNT_COSTS=1 to accept about \$$extra more"
    return 3
  fi
  if ! python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d["worst"] + float(sys.argv[2]) <= d["ceiling"] else 1)' "$sd/estimate.json" "$extra"; then
    say "up: refused; the worst case plus about \$$extra the account adds passes the ceiling"
    return 3
  fi
  say "up: accepted about \$$extra the account adds (EKS_BANK_ACCEPT_ACCOUNT_COSTS=1)"
}

# --- up / build -------------------------------------------------------------------
step_up() {
  estimate || { say "up: refused by the estimate; nothing made"; return 3; }
  if ! enterprise_guard; then
    [[ "$dry" == 1 ]] || { say "up: refused; nothing made"; return 3; }
    echo "dry-run: (the guard above refuses a live run)" >&2
  fi
  # A name whose state still holds a run, or whose cluster still exists,
  # is not this run's to make: down that one first, or pick another name.
  if [[ -f "$sd/terraform.tfstate" ]] && jq -e '(.resources // []) | length > 0' "$sd/terraform.tfstate" >/dev/null 2>&1; then
    say "up: refused; $sd/terraform.tfstate still holds a run's resources: ./eks-bank.sh $name down first, or pick another name"
    return 3
  fi
  if [[ "$dry" == 1 ]]; then
    echo "dry-run: read whether an EKS cluster named $name exists (read-only)" >&2
  elif aws eks describe-cluster --region us-east-1 --name "$name" >/dev/null 2>&1; then
    say "up: refused; an EKS cluster named $name already exists in this account"
    return 3
  fi
  account_costs || return 3
  # Terraform gives the controller this policy: only the published one.
  echo "$LBC_POLICY_SHA256  $HERE/terraform/lb-controller-iam-policy.json" | shasum -a 256 -c - >/dev/null ||
    { say "up: terraform/lb-controller-iam-policy.json is not the controller's published v$LBC_CHART_VERSION policy"; return 1; }
  # From here a failure tears down what this process made (on_exit).
  made_here=1
  x "$HERE/cluster.sh" up "$name" --ttl "$ttl" --zones 3 --system "$system_nodes" --system-type m7i.xlarge \
    --workers 0 --type m7i.xlarge --karpenter --ebs-csi --network-policy \
    --ecr aerolvm,aerolvm-runtime,aerolvm-operator,aerolvm-edge,drill --bank-drills --teardown
}

step_build() {
  # cell.sh build: the commit's source to S3, Go, xcaddy and BuildKit in a
  # Job on the system nodes, images to the run's ECR repositories.
  AEROL_BUILD_EDGE=1 x "$HERE/cell.sh" "$name" build
}

# The image tag cell.sh builds (v0.0.0-cell.<sha>), and the commit.
build_sha() { git -C "$ROOT" rev-parse "${AEROL_BUILD_REF:-HEAD}^{commit}"; }
# src_tree: that commit's files (lib.sh's git-archive copy in the state
# folder): the chart and the CLI come from it, never the working tree.
src_tree() { (cd "$HERE" && sd="$sd" bash -c 'source ./lib.sh; source_tree "$0"' "$(build_sha)"); }
image_tag() { echo "v0.0.0-cell.$(build_sha | cut -c1-8)"; }

# --- install ----------------------------------------------------------------------
wait_until() { # wait_until <seconds> <what> <cmd...>
  local secs="$1" what="$2"; shift 2
  [[ "$dry" == 1 ]] && { echo "dry-run: wait up to ${secs}s for $what" >&2; return 0; }
  for _ in $(seq 1 $(( secs / 10 ))); do "$@" >/dev/null 2>&1 && return 0; sleep 10; done
  say "timed out after ${secs}s waiting for $what"
  return 1
}
serving() { # serving <role>: how many AerolNodes of that role serve
  kr -n "$ns" get aerolnodes -o json | python3 -I -c 'import json,sys; print(sum(1 for n in json.load(sys.stdin)["items"] if n["spec"].get("role") == sys.argv[1] and n.get("status", {}).get("state") == "Serving"))' "$1"
}
at_least() { [[ "$(serving "$1")" -ge "$2" ]]; }
cell_ready() { [[ "$(kr -n "$ns" get aerolcluster "$cname" -o jsonpath='{.status.phase}')" == Ready ]]; }

nodepool() { # nodepool <cpu limit>
  sed -e "s|@@NAME@@|$name|g" -e "s|@@ROLE@@|$(tfout node_role_name)|" -e "s|@@TTL@@|$(jq -r .ttl "$sd/run.tfvars.json" 2>/dev/null || echo dry)|" \
    -e "s|@@ZONES@@|$(tfout zones | jq -r 'join(", ")')|" -e "s|@@LIMIT_CPU@@|$1|" "$HERE/drills-eks/karpenter.yaml" | k apply -f - >/dev/null
}

step_install() {
  local t0 region zones registry tag chart vpc ca
  t0=$(now)
  region="$(tfout region)"; zones="$(tfout zones | jq -r 'map("\"" + . + "\"") | join(", ")')"
  registry="$(tfout ecr_registry)"; tag="$(image_tag)"; vpc="$(tfout vpc_id)"
  chart="$(chart_dir)"
  if ! grep -q 'registryCA:' "$chart/values.yaml"; then
    say "install: the chart at $chart has no worker.registryCA; run from merged main"
    [[ "$dry" == 1 ]] || return 1
  fi

  say "install: cert-manager $CERT_MANAGER_VERSION, the run's CA, gp3"
  x curl -fsSL -o "$sd/cert-manager.yaml" \
    "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml"
  [[ "$dry" == 1 ]] || echo "$CERT_MANAGER_SHA256  $sd/cert-manager.yaml" | shasum -a 256 -c - >/dev/null
  k apply -f "$sd/cert-manager.yaml" >/dev/null
  k -n cert-manager wait --for=condition=Available deployment --all --timeout=5m >/dev/null
  wait_until 120 "cert-manager's webhook" k apply -f "$HERE/drills-eks/ca.yaml"
  k -n cert-manager wait certificate/aerolvm-drills-ca --for=condition=Ready --timeout=2m >/dev/null
  # The volumes the CSI driver makes (servers, the drill registry) carry the
  # run's tags, so the teardown and reap.sh find one a run left.
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
  tagSpecification_3: "aerol:ttl=$(jq -r .ttl "$sd/run.tfvars.json" 2>/dev/null || echo dry)"
YAML

  say "install: the AWS Load Balancer Controller $LBC_CHART_VERSION (its role through EKS Pod Identity)"
  x helm_fetch "$HELM" "$sd" "the AWS Load Balancer Controller's chart $LBC_CHART_VERSION" \
    aws-load-balancer-controller --repo https://aws.github.io/eks-charts --version "$LBC_CHART_VERSION"
  [[ "$dry" == 1 ]] || echo "$LBC_CHART_SHA256  $sd/aws-load-balancer-controller-$LBC_CHART_VERSION.tgz" | shasum -a 256 -c - >/dev/null
  # Pods cannot reach instance metadata (hop limit 1): region and VPC are
  # given. Every AWS object it makes carries the run's tags.
  hm upgrade --install aws-load-balancer-controller "$sd/aws-load-balancer-controller-$LBC_CHART_VERSION.tgz" -n kube-system \
    --set clusterName="$name" --set region="$region" --set vpcId="$vpc" \
    --set serviceAccount.create=true --set serviceAccount.name=aws-load-balancer-controller \
    --set-string "defaultTags.aerol:purpose=k8s-phase0" --set-string "defaultTags.aerol:run=$name" \
    --set-string "defaultTags.aerol:ttl=$(jq -r .ttl "$sd/run.tfvars.json" 2>/dev/null || echo dry)" \
    --wait --timeout 5m >/dev/null

  say "install: Karpenter's worker NodePool, at most $(( base_workers + 2 )) machines for now"
  nodepool $(( 4 * (base_workers + 2) ))

  say "install: kube-prometheus-stack (Alertmanager to the drills' receiver comes with drills-eks.sh setup)"
  k create namespace monitoring --dry-run=client -o yaml | k apply -f - >/dev/null
  local kps="${DRILL_KPS_VERSION:-92.17.0}"
  x helm_fetch "$HELM" "$sd" "kube-prometheus-stack's chart $kps" \
    kube-prometheus-stack --repo https://prometheus-community.github.io/helm-charts --version "$kps"
  hm upgrade --install kube-prometheus-stack "$sd/kube-prometheus-stack-$kps.tgz" \
    -n monitoring -f "$HERE/drills-local/kps-values.yaml" --wait --timeout 10m >/dev/null

  say "install: the namespaces, and the CA every worker trusts for the drill registry"
  k create namespace "$ns" --dry-run=client -o yaml | k apply -f - >/dev/null
  k label namespace "$ns" pod-security.kubernetes.io/enforce=restricted --overwrite >/dev/null
  # The chart makes the worker namespace; made first so the CA ConfigMap is
  # there before a worker pod is, and labelled for Helm to adopt.
  k create namespace "$workers" --dry-run=client -o yaml | k apply -f - >/dev/null
  k label namespace "$workers" app.kubernetes.io/managed-by=Helm --overwrite >/dev/null
  k annotate namespace "$workers" meta.helm.sh/release-name="$release" meta.helm.sh/release-namespace="$ns" --overwrite >/dev/null
  ca="$(kr -n cert-manager get secret aerolvm-drills-ca -o jsonpath='{.data.ca\.crt}' | base64 -d)"
  k -n "$workers" create configmap drills-registry-ca --from-literal=ca.crt="$ca" --dry-run=client -o yaml | k apply -f - >/dev/null

  say "install: the chart, values-bank-eks.yaml with the run's values over it"
  render_values "$sd/values-run.yaml" "$registry" "$tag" "$zones" "$(tfout witness_bucket)" "$(tfout export_bucket)" \
    "$region" "$(tfout audit_role_arn)"
  # The preset's <...> must all be filled: a render that still holds one is
  # refused before anything is installed.
  if [[ "$dry" != 1 ]]; then
    "$HELM" template "$release" "$chart" -n "$ns" -f "$chart/values-bank-eks.yaml" \
      -f "$sd/values-run.yaml" > "$sd/rendered.yaml"
    if grep -nE '"<[^>]+>"|: <[a-z]' "$sd/rendered.yaml" | grep -v '^[0-9]*: *#' > "$sd/unfilled.txt"; then
      say "install: the render still holds the preset's placeholders: $(head -3 "$sd/unfilled.txt")"; return 1
    fi
  fi
  hm upgrade --install "$release" "$chart" -n "$ns" \
    -f "$chart/values-bank-eks.yaml" -f "$sd/values-run.yaml" >/dev/null
  wait_until 900 "the AerolCluster Ready" cell_ready || return 1
  wait_until 1200 "$base_workers workers Serving" at_least worker "$base_workers" || return 1
  say "install: done in $(( $(now) - t0 ))s"
  kr -n "$ns" get aerolcluster,aerolnodes > "$sd/install-nodes.txt" 2>&1 || true
}

# --- the admin credential -----------------------------------------------------------
# admin_call <method> <path> [json]: one call with the admin token, through a
# port-forward to server-0's admin port: in enterprise mode the only place
# it works. Prints the HTTP code, then the body. A port-forward that does
# not open answers 000 with the reason as the body.
admin_call() {
  [[ "$dry" == 1 ]] && { echo "dry-run: admin token $1 $2 (port-forward to $cname-server-0:21219)" >&2; echo 200; echo '{}'; return 0; }
  local pat pf out
  pat="$(kr -n "$ns" get secret "$cname-admin" -o jsonpath='{.data.token}' | base64 -d | tr -d '\n')"
  if ! pf_start pf "$admin_lport" --kubeconfig "$sd/kubeconfig" -n "$ns" port-forward "pod/$cname-server-0" "$admin_lport:21219" 2>/dev/null; then
    echo 000; jq -cn --arg e "$pf_error" '{error: $e}'; return 0
  fi
  out="$(curl -sS -m 60 -w '\n%{http_code}' -X "$1" -H "Authorization: Bearer $pat" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "http://127.0.0.1:$admin_lport$2" || true)"
  pf_stop "$pf"
  tail -1 <<<"$out"; sed '$d' <<<"$out"
}
api_token() {
  [[ -s "$sd/api-token" ]] && return 0
  local out
  out="$(admin_call POST /v1/tokens "{\"name\": \"eks-bank-$(date +%s)\", \"role\": \"admin\", \"team\": \"*\", \"expires_in\": \"24h\"}")"
  [[ "$dry" == 1 ]] && { ( umask 077; echo dry > "$sd/api-token" ); return 0; }
  [[ "$(head -1 <<<"$out")" == 201 ]] || { say "making the run's API token: $out"; return 1; }
  ( umask 077; sed 1d <<<"$out" | jq -r .token | tr -d '\n' > "$sd/api-token" )
}

# --- enterprise -------------------------------------------------------------------
node_pods() {
  kr -n "$ns" get pods -l app.kubernetes.io/name=aerolvm -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name} {.metadata.labels.app\.kubernetes\.io/component}{"\n"}{end}' | grep -v operator || true
  kr -n "$workers" get pods -l app.kubernetes.io/component=worker -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name} worker{"\n"}{end}' || true
}
step_enterprise() {
  local out="$sd/evidence/enterprise" bad=0 n=0 pns pod role region witness exportb key vid
  mkdir -p "$out"
  [[ "$dry" == 1 ]] && { echo "dry-run: check every node pod, the S3 witness and export, the operator's tokens" >&2; return 0; }
  region="$(tfout region)"; witness="$(tfout witness_bucket)"; exportb="$(tfout export_bucket)"
  : > "$out/nodes.txt"
  while read -r pns pod role; do
    [[ -n "$pod" ]] || continue
    n=$(( n + 1 ))
    local ent restarts clash irsa others
    ent="$(kr -n "$pns" get pod "$pod" -o jsonpath='{.spec.containers[?(@.name=="agent")].env[?(@.name=="SB_ENTERPRISE_MODE")].value}')"
    restarts="$(kr -n "$pns" get pod "$pod" -o jsonpath='{.status.containerStatuses[?(@.name=="agent")].restartCount}')"
    clash="$(kr -n "$pns" logs "$pod" -c agent 2>/dev/null | grep -c 'address already in use' || true)"
    # IRSA in the agent container only (eks.amazonaws.com/skip-containers).
    irsa="$(kr -n "$pns" get pod "$pod" -o jsonpath='{.spec.containers[?(@.name=="agent")].env[?(@.name=="AWS_ROLE_ARN")].value}')"
    others="$(kr -n "$pns" get pod "$pod" -o json | jq -r '[.spec.containers[], .spec.initContainers[]? | select(.name != "agent") | select(any(.env[]?; .name == "AWS_ROLE_ARN")) | .name] | join(",")')"
    echo "$role $pod: enterprise=$ent restarts=$restarts address-in-use=$clash irsa=${irsa:-none} irsa-elsewhere=${others:-none}" >> "$out/nodes.txt"
    kr -n "$pns" logs "$pod" -c agent 2>/dev/null | grep -iE 'enterprise|witness|audit export|topology|egress floor|admin token listener' | cut -c1-300 | head -20 > "$out/boot-$pod.txt" || true
    [[ "$ent" == true && "$restarts" == 0 && "$clash" == 0 && -n "$irsa" && -z "$others" ]] || bad=$(( bad + 1 ))
  done < <(node_pods)
  aws s3api list-object-versions --region "$region" --bucket "$witness" --max-items 2000 --output json > "$out/witness-versions.json"
  aws s3api get-object-lock-configuration --region "$region" --bucket "$witness" > "$out/witness-lock.json"
  key="$(jq -r '[.Versions[]? | select(.Key | test("canary") | not)][0].Key // ""' "$out/witness-versions.json")"
  vid="$(jq -r --arg k "$key" '[.Versions[]? | select(.Key == $k)][0].VersionId // ""' "$out/witness-versions.json")"
  local retention="" del=""
  if [[ -n "$key" ]]; then
    retention="$(aws s3api get-object-retention --region "$region" --bucket "$witness" --key "$key" --version-id "$vid" --output json 2>&1 || true)"
    # The lock holds even for this run's admin, without the bypass.
    del="$(aws s3api delete-object --region "$region" --bucket "$witness" --key "$key" --version-id "$vid" 2>&1 || true)"
  fi
  echo "retention of $key: $retention" > "$out/witness-lock-check.txt"
  echo "delete of that version without the governance bypass: $del" >> "$out/witness-lock-check.txt"
  aws s3 ls --region "$region" --recursive "s3://$exportb/" > "$out/export-objects.txt" || true
  local heads exports tokens
  heads="$(jq '[.Versions[]?] | length' "$out/witness-versions.json")"
  exports="$(wc -l < "$out/export-objects.txt" | tr -d ' ')"
  admin_call GET /v1/tokens | sed 1d | jq -r '.tokens[] | "\(.id) \(.name) \(.role) \(if .expired then "expired" else "live" end)"' > "$out/tokens.txt" || true
  tokens="$(grep -c '^[^ ]* aerolvm-operator-[^ ]* .* live$' "$out/tokens.txt" || true)"
  if [[ "$bad" == 0 && "$n" -ge $(( 6 + base_workers )) && "$heads" -gt 0 && "$exports" -gt 0 && "$del" == *AccessDenied* && "$retention" == *GOVERNANCE* && "$tokens" == 1 ]]; then
    result PASS enterprise "$n node pods in enterprise mode, none restarted, IRSA in the agent only; $heads witness versions (GOVERNANCE-locked, a delete refused), $exports export objects; one live operator API token"
  else
    result FAIL enterprise "$bad of $n node pods wrong ($out/nodes.txt); witness versions $heads; export objects $exports; delete: ${del:0:120}; operator tokens live: $tokens"
  fi
}

# --- nlb ----------------------------------------------------------------------------
step_nlb() {
  local out="$sd/evidence/nlb" host region arn scheme lbtype health pat tok verdict
  mkdir -p "$out"
  api_token
  [[ "$dry" == 1 ]] && { echo "dry-run: check the gateways' internal NLB from a pod in the cluster" >&2; return 0; }
  region="$(tfout region)"
  wait_until 600 "the gateways' load balancer address" \
    bash -c "[[ -n \"\$(kubectl --kubeconfig '$sd/kubeconfig' -n $ns get svc $release-gateway -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')\" ]]" || return 1
  host="$(kr -n "$ns" get svc "$release-gateway" -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')"
  aws elbv2 describe-load-balancers --region "$region" --output json |
    jq --arg h "$host" '.LoadBalancers[] | select(.DNSName == $h)' > "$out/lb.json"
  arn="$(jq -r '.LoadBalancerArn // ""' "$out/lb.json")"; scheme="$(jq -r '.Scheme // ""' "$out/lb.json")"; lbtype="$(jq -r '.Type // ""' "$out/lb.json")"
  # No load balancer with the Service's name: a FAIL, not target-group
  # calls with an empty ARN. Every target group the controller made is
  # checked, whatever its port (443 and 2220 since the gateways stopped
  # exposing 80).
  if [[ -z "$arn" ]]; then
    result FAIL nlb "no load balancer in $region has the gateway Service's name $host"
    return 0
  fi
  wait_until 600 "every NLB target healthy" bash -c "
    for tg in \$(aws elbv2 describe-target-groups --region $region --load-balancer-arn $arn --query 'TargetGroups[].TargetGroupArn' --output text); do
      aws elbv2 describe-target-health --region $region --target-group-arn \$tg --query 'TargetHealthDescriptions[].TargetHealth.State' --output text | tr '\t' '\n' | grep -qv '^healthy$' && exit 1
    done; exit 0" || true
  for tg in $(aws elbv2 describe-target-groups --region "$region" --load-balancer-arn "$arn" --query 'TargetGroups[].TargetGroupArn' --output text); do
    aws elbv2 describe-target-health --region "$region" --target-group-arn "$tg" --output json
  done > "$out/targets.json"
  health="$(jq -rs '[.[].TargetHealthDescriptions[].TargetHealth.State] | group_by(.) | map("\(.[0])=\(length)") | join(" ")' "$out/targets.json")"
  # From a pod in the VPC: the NLB's addresses, then HTTPS to each with the
  # API host as SNI, checked against the run's CA.
  pat="$(kr -n "$ns" get secret "$cname-admin" -o jsonpath='{.data.token}' | base64 -d | tr -d '\n')"
  tok="$(cat "$sd/api-token")"
  k create namespace drills --dry-run=client -o yaml | k apply -f - >/dev/null
  k -n drills create configmap drills-registry-ca --from-literal=ca.crt="$(kr -n cert-manager get secret aerolvm-drills-ca -o jsonpath='{.data.ca\.crt}' | base64 -d)" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  k -n drills delete pod nlb-probe --ignore-not-found --wait=true >/dev/null
  k -n drills run nlb-probe --image=public.ecr.aws/docker/library/python:3.12-slim --restart=Never \
    --overrides='{"spec":{"volumes":[{"name":"ca","configMap":{"name":"drills-registry-ca"}}],"containers":[{"name":"nlb-probe","image":"public.ecr.aws/docker/library/python:3.12-slim","command":["sleep","900"],"volumeMounts":[{"name":"ca","mountPath":"/ca"}]}]}}' >/dev/null
  k -n drills wait pod/nlb-probe --for=condition=Ready --timeout=3m >/dev/null
  verdict="$(k -n drills exec -i nlb-probe -- python -I - "$host" "bank.$name.internal" "$pat" "$tok" <<'PY'
import http.client, ipaddress, json, socket, ssl, sys
host, api, pat, tok = sys.argv[1:]
ips = sorted({a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET)})
ctx = ssl.create_default_context(cafile="/ca/ca.crt")
def get(ip, path, bearer=None):
    s = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=20), server_hostname=api)
    c = http.client.HTTPConnection(api)
    c.sock = s
    c.request("GET", path, headers={"Authorization": "Bearer " + bearer} if bearer else {})
    r = c.getresponse()
    body = r.read(300).decode(errors="replace")
    return r.status, body
res = {"addresses": ips, "private": all(ipaddress.ip_address(i).is_private for i in ips), "per_address": {}}
for ip in ips:
    res["per_address"][ip] = {
        "health": get(ip, "/health")[0],
        "whoami_admin_token": get(ip, "/v1/whoami", pat)[0],
        "whoami_api_token": get(ip, "/v1/whoami", tok)[0],
        "list_api_token": get(ip, "/v1/sandboxes", tok)[0],
    }
print(json.dumps(res))
PY
)"
  k -n drills delete pod nlb-probe --wait=false >/dev/null
  echo "$verdict" > "$out/probe.json"
  if [[ "$scheme" == internal && "$lbtype" == network && "$health" != *unhealthy* && "$health" == healthy=* ]] &&
     jq -e '.private and (.addresses | length > 0) and ([.per_address[] | .health == 200 and .whoami_admin_token == 401 and .whoami_api_token == 200 and .list_api_token == 200] | all)' "$out/probe.json" >/dev/null; then
    result PASS nlb "an internal network load balancer ($health), private addresses $(jq -c .addresses "$out/probe.json") only; through each, over the run's CA: /health 200, the admin token 401, an API token 200"
  else
    result FAIL nlb "scheme $scheme, type $lbtype, targets $health; probe $(cat "$out/probe.json")"
  fi
}

# --- gvisor -----------------------------------------------------------------------
# gw_call <method> <path> [json]: one call with the run's API token, through
# a port-forward to a gateway pod's API port. Answers as admin_call does.
gw_call() {
  [[ "$dry" == 1 ]] && { echo "dry-run: API token $1 $2 (port-forward to a gateway)" >&2; echo 200; echo '{}'; return 0; }
  local gw pf out
  gw="$(kr -n "$ns" get pods -l app.kubernetes.io/component=gateway -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  # No gateway pod: an answer the caller records, never a port-forward to
  # "pod/".
  [[ -n "$gw" ]] || { echo 000; echo '{"error": "no gateway pod to call through"}'; return 0; }
  if ! pf_start pf "$gw_lport" --kubeconfig "$sd/kubeconfig" -n "$ns" port-forward "pod/$gw" "$gw_lport:21212" 2>/dev/null; then
    echo 000; jq -cn --arg e "$pf_error" '{error: $e}'; return 0
  fi
  out="$(curl -sS -m 300 -w '\n%{http_code}' -X "$1" -H "Authorization: Bearer $(cat "$sd/api-token")" \
    -H 'Content-Type: application/json' ${3:+-d "$3"} "http://127.0.0.1:$gw_lport$2" || true)"
  pf_stop "$pf"
  tail -1 <<<"$out"; sed '$d' <<<"$out"
}
# sandbox_machine <sandbox id> <out dir>: the worker pod and machine a
# sandbox runs on, into <out>/placement.json and <out>/machine.txt. The v1
# sandbox answer names no node: its owner is the placement record's
# (/v1/cluster/placements/{id}, owner.node_id). On Kubernetes a node's id is
# its AerolNode's name, which is also its worker pod's name (the operator
# sets SB_NODE_ID to it). Prints the worker pod's name; returns 1, with the
# reason in machine.txt, when any name along the way is empty: kubectl is
# never asked for a resource with no name.
sandbox_machine() {
  local id="$1" out="$2" placed wpod node
  placed="$(admin_call GET "/v1/cluster/placements/$id")"
  sed 1d <<<"$placed" > "$out/placement.json"
  wpod="$(jq -r '.owner.node_id // ""' "$out/placement.json" 2>/dev/null || true)"
  if [[ -z "$wpod" ]]; then
    echo "no owner node: the placement route answered $(head -1 <<<"$placed"): $(sed 1d <<<"$placed" | cut -c1-200)" > "$out/machine.txt"
    return 1
  fi
  node="$(kr -n "$workers" get pod "$wpod" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)"
  if [[ -z "$node" ]]; then
    echo "worker pod $wpod (the owner node) has no machine in $workers" > "$out/machine.txt"
    return 1
  fi
  kr get node "$node" -o jsonpath='{.status.nodeInfo.osImage} | kernel {.status.nodeInfo.kernelVersion} | {.status.nodeInfo.containerRuntimeVersion}' \
    > "$out/machine.txt" 2>&1 || true
  echo "$wpod"
}
step_gvisor() {
  local out="$sd/evidence/gvisor" made id wpod="" runc
  mkdir -p "$out"
  api_token
  [[ "$dry" == 1 ]] && { echo "dry-run: a gVisor sandbox on an AL2023 worker (its owner from /v1/cluster/placements/{id}); runc refused" >&2; return 0; }
  made="$(gw_call POST /v1/sandboxes '{"image": "public.ecr.aws/docker/library/alpine:3.20", "runtime": "gvisor", "cpu": 0.5, "memory_mb": 512, "tags": {"drill-run": "gvisor"}}')"
  echo "$made" > "$out/create.txt"
  id="$(sed 1d <<<"$made" | jq -r '.id // ""' 2>/dev/null || true)"
  [[ -n "$id" ]] || { result FAIL gvisor "create answered $(head -1 <<<"$made"): $(sed 1d <<<"$made" | cut -c1-200)"; return 0; }
  gw_call POST "/v1/sandboxes/$id/toolbox/process/execute" '{"command": "sh -c \"dmesg | head -3; uname -r\""}' > "$out/exec.txt"
  # The exec answered 200 and its own output names gVisor (an error body
  # that quotes the command must not pass). Read whole, then searched: no
  # assignment takes a pipeline that a reader stopping early can end.
  local exec_code stdout started
  exec_code="$(head -1 "$out/exec.txt")"
  stdout="$(sed 1d "$out/exec.txt" | jq -r '.stdout // ""' 2>/dev/null || true)"
  started="$(grep 'Starting gVisor' <<<"$stdout" || true)"
  started="$(head -1 <<<"$started")"
  wpod="$(sandbox_machine "$id" "$out" || true)"
  gw_call DELETE "/v1/sandboxes/$id" > /dev/null || true
  runc="$(gw_call POST /v1/sandboxes '{"image": "public.ecr.aws/docker/library/alpine:3.20", "runtime": "runc"}')"
  runc="$(head -1 <<<"$runc")"
  echo "a runc create: $runc" >> "$out/exec.txt"
  if [[ "$exec_code" == 200 && -n "$started" && -n "$wpod" ]] && grep -q 'Amazon Linux 2023' "$out/machine.txt" && [[ "$runc" =~ ^(400|403|422)$ ]]; then
    result PASS gvisor "sandbox $id ran under gVisor ($started) on worker $wpod, a machine running $(cat "$out/machine.txt"); a runc create answered $runc"
  else
    # One line in bank.txt: the exec's answer and the machine with their
    # newlines folded.
    result FAIL gvisor "exec: $(tr '\n' ' ' < "$out/exec.txt" | cut -c1-300); machine: $(tr '\n' ' ' < "$out/machine.txt"); runc create: $runc"
  fi
}

# --- verify -------------------------------------------------------------------------
step_verify() {
  local out="$sd/evidence/verify" src cli pat pf rc=0
  mkdir -p "$out"
  # Its probe sandbox from Amazon's mirror: the run's create policy refuses
  # the default (alpine:3.20 is docker.io).
  local probe=public.ecr.aws/docker/library/alpine:3.20
  [[ "$dry" == 1 ]] && { echo "dry-run: aerolvm k8s verify through server-0's admin port, --probe-image $probe" >&2; return 0; }
  src="$(src_tree)"
  cli="$sd/aerolvm"
  (cd "$src" && go build -o "$cli" ./cmd/aerolvm)
  pat="$(kr -n "$ns" get secret "$cname-admin" -o jsonpath='{.data.token}' | base64 -d | tr -d '\n')"
  if ! pf_start pf "$verify_lport" --kubeconfig "$sd/kubeconfig" -n "$ns" port-forward "pod/$cname-server-0" "$verify_lport:21219" 2>/dev/null; then
    result FAIL verify "no port-forward to $cname-server-0's admin port: $pf_error"
    return 0
  fi
  KUBECONFIG="$sd/kubeconfig" SB_API_URL="http://127.0.0.1:$verify_lport" SB_PAT_TOKEN="$pat" "$cli" k8s verify \
    --namespace "$ns" --worker-namespace "$workers" --release "$release" --cluster "$cname" \
    --skip-signatures --probe-runtimes gvisor --probe-image "$probe" \
    > "$out/verify.txt" 2>&1 || rc=$?
  pf_stop "$pf"
  if [[ "$rc" == 0 ]]; then
    result PASS verify "aerolvm k8s verify passed on the live enterprise install (signatures skipped: dev images) ($out/verify.txt)"
  else
    result FAIL verify "aerolvm k8s verify exited $rc: $(grep -iE 'fail|error' "$out/verify.txt" | head -5 | tr '\n' ' ')"
  fi
}

# --- drills -------------------------------------------------------------------------
drills() {
  api_token
  DRILL_TOKEN_FILE="$sd/api-token" DRILL_AWS_REGION="$(tfout region)" DRILL_ECR_REPO="$(tfout ecr_registry)/drill" \
    DRILL_CA_ISSUER=aerolvm-drills-ca AEROL_NS="$ns" AEROL_WORKER_NS="$workers" AEROL_CLUSTER_NAME="$cname" \
    AEROL_HELM_RELEASE="$release" HELM="$HELM" x "$HERE/drills-eks.sh" "$name" "$sd/drills" "$@"
}

# --- gateways11 ---------------------------------------------------------------------
step_gateways11() {
  local out="$sd/evidence/gateways11" chart t0
  mkdir -p "$out"
  chart="$(chart_dir)"
  # Without the opt-in the chart refuses past 10 gateways, before anything
  # reaches the cluster.
  if [[ "$dry" != 1 ]]; then
    "$HELM" template "$release" "$chart" -n "$ns" -f "$chart/values-bank-eks.yaml" \
      -f "$sd/values-run.yaml" --set "cluster.gateways.minReplicas=$gateways_peak" \
      --set-string worker.extraEnv.SB_CLUSTER_SHARD_AWARE_INGRESS=false > /dev/null 2> "$out/refused.txt" || true
  fi
  t0=$(now)
  say "gateways11: $gateways_peak gateways, enterprise mode, the shard-aware opt-in"
  # From here, an end of the step for any reason puts the gateways back to
  # 3 (run_check's exit handler runs check_undo).
  check_undo=gateways_back
  hm upgrade "$release" "$chart" -n "$ns" --reuse-values --set "cluster.gateways.minReplicas=$gateways_peak" >/dev/null
  wait_until 900 "$gateways_peak gateways Serving" at_least gateway "$gateways_peak" || { result FAIL gateways11 "$(serving gateway) of $gateways_peak gateways serve after $(( $(now) - t0 ))s"; }
  kr -n "$ns" get pods -l app.kubernetes.io/component=gateway -o wide > "$out/gateways.txt" 2>&1 || true
  [[ "$dry" == 1 ]] || say "gateways11: $(serving gateway) gateways serve, $(( $(now) - t0 ))s; the chart without the opt-in: $(grep -o 'refuses to start past 10[^.]*' "$out/refused.txt" | head -1)"
  local rc=0
  drills shard-routes || rc=$?
  [[ "$rc" == 0 ]] || result FAIL shard-routes "drills-eks.sh shard-routes exited $rc"
  gateways_back
  check_undo=""
}
# gateways_back: the gateways back to 3 (the end of gateways11, or its exit
# handler).
gateways_back() {
  hm upgrade "$release" "$(chart_dir)" -n "$ns" --reuse-values --set cluster.gateways.minReplicas=3 >/dev/null || return 1
  wait_until 900 "the gateways back to 3" bash -c "[[ \$(kubectl --kubeconfig '$sd/kubeconfig' -n $ns get pods -l app.kubernetes.io/component=gateway --no-headers | wc -l) -le 3 ]]" || true
}

# --- scale --------------------------------------------------------------------------
workers_now() { # live workers, pending ones, Karpenter's machines
  [[ "$dry" == 1 ]] && { echo "0 0 0"; return 0; }
  # Read three times before giving up: one failed API read in an hour of
  # polling must not end the scale step.
  local w p m _
  for _ in 1 2 3; do
    if w="$(serving worker)" &&
       p="$(kr -n "$ns" get aerolnodes -o json | jq '[.items[] | select(.spec.role == "worker" and .status.state != "Serving" and .metadata.deletionTimestamp == null)] | length')" &&
       m="$(kr get nodeclaims -o json | jq '[.items[] | select(.metadata.labels["karpenter.sh/nodepool"] == "gvisor-general")] | length')" &&
       [[ "$w" =~ ^[0-9]+$ && "$p" =~ ^[0-9]+$ && "$m" =~ ^[0-9]+$ ]]; then
      echo "$w $p $m"
      return 0
    fi
    sleep 5
  done
  say "scale: the cluster did not answer the worker count three times"
  return 1
}
# read_workers: workers_now into the caller's w, p and m; 1 when the
# cluster did not give the counts (read from "$(workers_now)" directly, a
# failure left them empty, and an empty m passed "m <= base"). The polling
# loops wait and read again (`read_workers || { sleep 15; continue; }`):
# a minute of API errors must not end the most expensive step. The reads a
# result is written from are plain calls, so there a failure ends the step
# (set -e).
read_workers() {
  local counts
  counts="$(workers_now)" || return 1
  read -r w p m <<<"$counts"
}
timeline() { echo "$(date -u +%H:%M:%S) $1 workers/pending/machines $(workers_now)" >> "$sd/evidence/scale/timeline.txt"; }
set_min_workers() {
  k -n "$ns" patch aerolcluster "$cname" --type json \
    -p "[{\"op\": \"replace\", \"path\": \"/spec/workerPools/0/minWorkers\", \"value\": $1}]" >/dev/null
}
# kill_tree <pid>: a process and everything under it, deepest first, so a
# drills-eks.sh in it runs its EXIT trap (callers stopped, faults cleared,
# port-forwards ended) as soon as its foreground child is gone.
kill_tree() {
  local kid
  for kid in $(pgrep -P "$1" 2>/dev/null || true); do kill_tree "$kid"; done
  kill -TERM "$1" 2>/dev/null || true
}
drill_pid=""
in_scale=""
# stop_scale_drills: the peak drills (ecr-storm, thresholds) stopped, the
# whole tree, so each drills-eks.sh runs its own cleanup.
stop_scale_drills() {
  if [[ -n "$drill_pid" ]] && kill -0 "$drill_pid" 2>/dev/null; then
    kill_tree "$drill_pid"
    wait "$drill_pid" 2>/dev/null || true
  fi
  drill_pid=""
}
scale_back() {
  # The scale step's normal end, and its exit handler's (check_exit): the
  # peak drills stopped, the floor back to the base, the fill sandboxes
  # gone, the NodePool's limit back down. Marked done only at its end: a
  # TERM that lands while the normal end runs it (the peak drills, once
  # killed, end the step's wait for them) must leave the exit handler the
  # rest to do. Each part can run twice.
  [[ "${scaled_back:-0}" == 1 ]] && return 0
  stop_scale_drills
  say "scale: back to $base_workers workers"
  set_min_workers "$base_workers" || true
  drills unfill || true
  nodepool $(( 4 * (base_workers + 2) )) || true
  scaled_back=1
}
cap_schedule() { # cap_schedule <UTC time>: AWS ends Karpenter's machines then
  x aws scheduler create-schedule --region "$(tfout region)" --name "$name-scale-cap" \
    --schedule-expression "at($1)" --schedule-expression-timezone UTC --flexible-time-window Mode=OFF \
    --action-after-completion DELETE \
    --target "{\"Arn\": \"$(tfout teardown_lambda_arn)\", \"RoleArn\": \"$(tfout scheduler_role_arn)\", \"Input\": \"{\\\"phase\\\": \\\"scale-cap\\\"}\"}" >/dev/null
}
step_scale() {
  local out="$sd/evidence/scale" t0 deadline cap_at rounds=0 last_fill=0 w p m left
  mkdir -p "$out"
  # The teardown timer must not land inside the box: refuse unless the TTL
  # leaves the box, the way back and half an hour.
  if [[ "$dry" != 1 ]]; then
    left=$(( ( $(python3 -I -c 'import datetime,json,sys; t=json.load(open(sys.argv[1]))["ttl"]; print(int(datetime.datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()))' "$sd/run.tfvars.json") - $(now) ) / 60 ))
    if (( left < scale_minutes + back_minutes + 30 )); then
      say "scale: refused; $left min left before the teardown timer, the step needs $(( scale_minutes + back_minutes + 30 ))"
      return 1
    fi
  fi
  api_token
  t0=$(now)
  deadline=$(( t0 + scale_minutes * 60 ))
  # The hard guard first: if this machine dies, AWS ends every Karpenter
  # machine of the run at the end of the box, the way back and 15 minutes.
  cap_at="$(python3 -I -c 'import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=int(sys.argv[1]))).strftime("%Y-%m-%dT%H:%M:%S"))' $(( scale_minutes + back_minutes + 15 )))"
  cap_schedule "$cap_at"
  # From here an exit, Ctrl-C included, scales back (on_exit).
  in_scale=1
  scaled_back=0
  say "scale: time box $scale_minutes min; AWS's scale-cap at $cap_at UTC"
  nodepool $(( 4 * (peak_workers + 2) ))

  # 1. The cell fills past what its workers hold, so the operator must add
  #    one (EKS_BANK_FILL_TARGET, the base and one more). Each round is
  #    sized from the members and the create policy (fill_plan): fillers
  #    of the policy's largest CPU, as many as every worker's free CPU
  #    takes, and one more. The fifth run's rounds of 8 1-CPU fillers made
  #    80 CPUs in 15 min, short of six workers of 18: no 7th served.
  local target="${EKS_BANK_FILL_TARGET:-$(( base_workers + 1 ))}" fill_until=$(( t0 + 15 * 60 )) plan fcpu fcount filled=""
  timeline start
  while [[ "$dry" != 1 && $(now) -lt $fill_until ]]; do
    read_workers || { sleep 15; continue; }
    [[ "$w" -ge "$target" ]] && break
    if [[ "$p" == 0 && $(( $(now) - last_fill )) -ge 90 ]]; then
      rounds=$(( rounds + 1 )); last_fill=$(now)
      local frc=0
      if plan="$(fill_plan "$out")"; then
        read -r fcpu fcount <<<"$plan"
        filled="${filled:+$filled, }$fcount of $fcpu CPU"
        DRILL_FILL_COUNT="$fcount" DRILL_FILL_CPU="$fcpu" drills fill || frc=$?
        [[ "$frc" == 0 ]] || say "scale: fill round $rounds: drills-eks.sh fill exited $frc"
      else
        say "scale: fill round $rounds: no fill plan (the members were not read)"
      fi
      timeline "fill round $rounds"
    fi
    sleep 15
    timeline poll
  done
  read_workers
  result "$([[ "$dry" == 1 || "$w" -ge "$target" ]] && echo PASS || echo FAIL)" scale-full \
    "$rounds fill rounds (${filled:-none}, sized from the members' free CPU and the create policy): the operator added workers and Karpenter bought machines until $w workers served ($m machines; $target wanted) in $(( $(now) - t0 ))s ($out/timeline.txt)"

  # 2. To the peak: the floor to 60.
  local tp
  tp=$(now)
  set_min_workers "$peak_workers"
  wait_until $(( deadline - $(now) > 1200 ? 1200 : deadline - $(now) )) "$peak_workers workers Serving" at_least worker "$peak_workers" || true
  read_workers
  timeline peak
  result "$([[ "$dry" == 1 || "$w" -ge "$peak_workers" ]] && echo PASS || echo FAIL)" scale-peak \
    "minWorkers $peak_workers: $w workers serving on $m machines $(( $(now) - tp ))s later"

  # 3. At the peak, until the box ends: the ECR storm and the thresholds,
  #    those of them run_peak_list holds (EKS_BANK_DRILLS); one it leaves
  #    out is a SKIP line.
  local d peak="$out/peak"
  for d in "${peak_drills[@]}"; do
    [[ " ${run_peak_list[*]-} " == *" $d "* ]] || result SKIP "$d" "not in EKS_BANK_DRILLS"
  done
  if [[ "$dry" == 1 ]]; then
    for d in ${run_peak_list[@]+"${run_peak_list[@]}"}; do drills "$d"; done
  else
    # One run of drills-eks.sh each, so one that fails does not skip the
    # next; a run that fails is recorded here (its own PASS or FAIL lines
    # go to drills/drills.txt). Each marks its start and its end, so one
    # the time box cuts off, or never starts, gets a FAIL line too
    # (peak_unfinished): the fifth-run fix's re-run plan would have lost
    # both without a word.
    mkdir -p "$peak"
    rm -f "$peak"/*.started "$peak"/*.ended
    (
      for d in ${run_peak_list[@]+"${run_peak_list[@]}"}; do
        now > "$peak/$d.started"
        rc=0
        drills "$d" || rc=$?
        : > "$peak/$d.ended"
        [[ "$rc" == 0 ]] || result FAIL "$d" "drills-eks.sh $d exited $rc"
      done
    ) &
    drill_pid=$!
    while kill -0 "$drill_pid" 2>/dev/null; do
      if [[ $(now) -ge $deadline ]]; then
        say "scale: the time box ended; stopping the drills at the peak"
        kill_tree "$drill_pid"
        break
      fi
      sleep 15
    done
    wait "$drill_pid" 2>/dev/null || true
    drill_pid=""
    peak_unfinished "$peak"
  fi

  # 4. Back: the floor to the base, the fill gone; the operator decommissions
  #    and Karpenter ends the empty machines. Then the rest are ended.
  local tb
  tb=$(now)
  scale_back
  while [[ "$dry" != 1 && $(( $(now) - tb )) -lt $(( back_minutes * 60 )) ]]; do
    timeline back
    read_workers || { sleep 30; continue; }
    [[ "$m" -le "$base_workers" ]] && break
    sleep 30
  done
  read_workers
  result "$([[ "$dry" == 1 || "$m" -le "$base_workers" ]] && echo PASS || echo INCOMPLETE)" scale-back \
    "$(( ($(now) - tb) / 60 )) min after the floor went back to $base_workers: $w workers, $m machines"
  if [[ "$dry" != 1 && "$m" -gt "$base_workers" ]]; then
    end_extra_machines
  fi
  x aws scheduler delete-schedule --region "$(tfout region)" --name "$name-scale-cap" >/dev/null 2>&1 || true
  in_scale=""
}
# fill_plan <out dir>: the next scale fill round, "<cpu> <count>":
# drills-local/fillplan.py over the members (gw_call) and the create policy
# (the <cluster>-create-policy ConfigMap), both kept in <out>, with one
# filler past what the workers' free CPU takes. 1 when the members were not
# read.
fill_plan() {
  local out="$1" members
  members="$(gw_call GET /v1/cluster/members)"
  [[ "$(head -1 <<<"$members")" == 200 ]] || return 1
  sed 1d <<<"$members" > "$out/members.json"
  kr -n "$ns" get configmap "$cname-create-policy" -o jsonpath='{.data.policy\.yaml}' > "$out/create-policy.yaml" 2>/dev/null ||
    : > "$out/create-policy.yaml"
  python3 -I "$HERE/drills-local/fillplan.py" "$out/members.json" "$out/create-policy.yaml" --past 1 > "$out/fill-plan.json" || return 1
  jq -r '"\(.cpu) \(.count)"' "$out/fill-plan.json"
}
# peak_unfinished <dir>: a FAIL line for each peak drill that did not end:
# cut off by the time box (it started) or not started at all.
peak_unfinished() {
  local d
  for d in ${run_peak_list[@]+"${run_peak_list[@]}"}; do
    [[ ! -f "$1/$d.ended" ]] || continue
    if [[ -f "$1/$d.started" ]]; then
      result FAIL "$d" "cut off by the time box after $(( $(now) - $(cat "$1/$d.started") ))s"
    else
      result FAIL "$d" "not started: the time box ended first"
    fi
  done
}
# end_extra_machines: past the way back, the machines above the base are
# ended directly: every Karpenter machine of this run but those under the
# base's oldest serving workers.
end_extra_machines() {
  local keep ids
  keep="$(kr -n "$ns" get aerolnodes -o json | jq -r --argjson n "$base_workers" \
    '[.items[] | select(.spec.role == "worker" and .status.state == "Serving")] | sort_by(.metadata.creationTimestamp) | .[:$n][] | .status.nodeName' | sort -u)"
  ids="$(kr get nodes -l aerolvm.io/pool=gvisor-general -o json | jq -r --arg keep "$keep" \
    '.items[] | select(.metadata.name as $n | ($keep | split("\n") | index($n)) | not) | .spec.providerID | split("/") | last')"
  if [[ -n "$ids" ]]; then
    # shellcheck disable=SC2086
    x aws ec2 terminate-instances --region "$(tfout region)" --instance-ids $ids >/dev/null
    result INFO scale-forced "ended $(wc -w <<<"$ids" | tr -d ' ') machines above the base directly"
  fi
}

# --- down ---------------------------------------------------------------------------
# left_after_down <region>: everything still there that carries the run's
# name or tags; non-zero when anything is left, or a listing failed.
left_after_down() {
  local region="$1" acct left=0 what got
  acct="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo unknown)"
  while IFS='|' read -r what cmd; do
    if got="$(bash -c "$cmd" 2>&1)"; then
      got="$(tr -s '\t\n ' ' ' <<<"$got" | sed -e 's/^ //' -e 's/ $//' -e 's/^None$//')"
    else
      got="could not list: ${got:0:160}"
    fi
    echo "$what: ${got:-none}"
    [[ -z "$got" ]] || left=1
  done <<LIST
instances (Karpenter's and the node groups')|aws ec2 describe-instances --region $region --filters Name=instance-state-name,Values=pending,running,stopping,stopped --query "Reservations[].Instances[?Tags[?(Key=='aerol:run' && Value=='$name') || (Key=='eks:cluster-name' && Value=='$name')]].InstanceId" --output text
volumes|aws ec2 describe-volumes --region $region --filters Name=tag:aerol:run,Values=$name --query 'Volumes[].VolumeId' --output text
load balancers|for a in \$(aws elbv2 describe-load-balancers --region $region --query 'LoadBalancers[].LoadBalancerArn' --output text); do aws elbv2 describe-tags --region $region --resource-arns \$a --query "TagDescriptions[?Tags[?(Key=='elbv2.k8s.aws/cluster' || Key=='aerol:run') && Value=='$name']].ResourceArn" --output text; done
cluster|aws eks list-clusters --region $region --query "clusters[?@ == '$name']" --output text
VPC|aws ec2 describe-vpcs --region $region --filters Name=tag:aerol:run,Values=$name --query 'Vpcs[].VpcId' --output text
buckets|for b in $name-witness-$acct $name-export-$acct; do aws s3api head-bucket --bucket \$b >/dev/null 2>&1 && echo \$b; done; true
ECR repositories|aws ecr describe-repositories --region $region --query "repositories[?starts_with(repositoryName, '$name/')].repositoryName" --output text
schedules|aws scheduler list-schedules --region $region --name-prefix $name- --query 'Schedules[].Name' --output text
teardown Lambda|aws lambda list-functions --region $region --query "Functions[?FunctionName == '$name-teardown'].FunctionName" --output text
IAM roles|aws iam list-roles --query "Roles[?starts_with(RoleName, '$name-')].RoleName" --output text
LIST
  return "$left"
}

step_down() {
  local region
  # Before any AWS call: this machine's account is the run's.
  same_account
  region="$(tfout region 2>/dev/null || echo "${AWS_REGION:-us-east-1}")"
  x aws scheduler delete-schedule --region "$region" --name "$name-scale-cap" >/dev/null || true
  if [[ -f "$sd/kubeconfig" || "$dry" == 1 ]]; then
    # The chart first: its gateway Service is the NLB (the load balancer
    # controller deletes it), its servers' volumes are EBS. Then the drill
    # registry's volume, then the controller itself.
    hm uninstall "$release" -n "$ns" --wait --timeout 10m >/dev/null || true
    k delete namespace drills --wait=true --timeout=10m >/dev/null || true
    k -n "$ns" delete pvc --all --wait=true --timeout=10m >/dev/null || true
    wait_until 600 "the gateways' load balancer gone" bash -c \
      "[[ -z \$(aws elbv2 describe-load-balancers --region $region --query 'LoadBalancers[].LoadBalancerArn' --output text | tr '\t' '\n' | while read -r a; do [[ -n \$a ]] && aws elbv2 describe-tags --region $region --resource-arns \$a --query \"TagDescriptions[0].Tags[?Key=='elbv2.k8s.aws/cluster'].Value | [0]\" --output text; done | grep -x '$name') ]]" || true
    wait_until 600 "the run's volumes released" bash -c "[[ -z \$(kubectl --kubeconfig '$sd/kubeconfig' get pv --no-headers 2>/dev/null) ]]" || true
    hm uninstall aws-load-balancer-controller -n kube-system >/dev/null || true
  fi
  # A volume the CSI driver could not delete in time (about $10 a month for
  # the drill registry's): every unattached one with this run's name and
  # TTL (an older run's of the same name are reap.sh's to judge).
  local vol ttl_tag
  ttl_tag="$(jq -r '.ttl // ""' "$sd/run.tfvars.json" 2>/dev/null || true)"
  for vol in $([[ "$dry" == 1 || -z "$ttl_tag" ]] || aws ec2 describe-volumes --region "$region" \
      --filters "Name=tag:aerol:run,Values=$name" "Name=tag:aerol:ttl,Values=$ttl_tag" Name=tag:aerol:purpose,Values=k8s-phase0 \
      Name=status,Values=available --query 'Volumes[].VolumeId' --output text 2>/dev/null || true); do
    x aws ec2 delete-volume --region "$region" --volume-id "$vol" >/dev/null || true
  done
  x "$HERE/cell.sh" "$name" down
  downed=1
  [[ "$dry" == 1 ]] && return 0
  if left_after_down "$region" | tee "$sd/left-after-down.txt"; then
    say "down: nothing of $name is left"
  else
    say "down: something of $name is left ($sd/left-after-down.txt); run ./eks-bank.sh $name down again, or reap.sh once its TTL has passed"
    return 1
  fi
}

# --- checks -------------------------------------------------------------------------
# run_check <step> <cmd...>: one check of the run. A check that fails is
# recorded "FAIL <step> exited N" and the run goes on; up, build and install
# are not checks (everything after needs them).
#
# The check runs in a subshell with set -e on, started plainly: bash ignores
# set -e in anything run under if, while, ||, && or !, subshells and
# functions included, so a check must never be called from one (it would
# carry on past a failed command). The subshell runs in the background and
# is waited for: bash runs this script's trap for a signal only when a
# foreground command ends, but `wait` returns at once, and on_exit then
# stops the check (stop_check) before it tears anything down.
#
# What a check leaves for later steps lives in files under $sd (the API
# token, the values, the results), never in shell variables, which the
# subshell keeps to itself. Its own unfinished business (the scale step's
# floor, gateways11's 11 gateways) is undone by check_exit, the subshell's
# EXIT trap. The status is in check_rc; run_check itself always returns 0.
check_pid=""
check_rc=0
check_undo=""
failed_checks=()
run_check() {
  local step="$1"; shift
  rm -f "$sd/.check-exit"
  set +e
  (
    set -e
    trap check_exit EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    "$@"
  ) &
  check_pid=$!
  wait "$check_pid"
  check_rc=$?
  check_pid=""
  set -e
  if [[ "$check_rc" != 0 ]]; then
    result FAIL "$step" "exited $check_rc"
    failed_checks+=("$step")
  fi
  return 0
}
# check_exit: the check subshell's EXIT trap, which stops and undoes what
# the check left: the scale step's floor (in_scale), gateways11's 11
# gateways (check_undo). INT and TERM are caught and dropped from here so
# the undo finishes; caught, not ignored, because an ignored signal is
# inherited: a drills-eks.sh the undo starts could then never be stopped
# (its port-forward loop outlived the run). When on_exit tears the run down
# next ($sd/.teardown-next), only the peak drills are stopped: the rest goes
# with the cluster, and a long undo would only delay the teardown. Its first
# act is the mark $sd/.check-exit: stop_check leaves an undo that has begun
# to finish (killing its tree then would kill the undo's own children).
check_exit() {
  local rc=$?
  trap : INT TERM
  : > "$sd/.check-exit"
  if [[ -f "$sd/.teardown-next" ]]; then
    stop_scale_drills
  else
    if [[ -n "$in_scale" ]]; then scale_back || true; fi
    if [[ -n "$check_undo" ]]; then "$check_undo" || true; fi
  fi
  exit "$rc"
}
# stop_check: on_exit's first act while a check runs. TERM to the check
# alone; its trap runs check_exit, whose first act is the mark
# $sd/.check-exit. With the mark there the undo has begun, and it is left to
# finish: a Ctrl-C reaches the check and this shell together, so the check
# may already be undoing, and kill_tree then killed the undo's own children
# (gateways_back's Helm, the floor's kubectl patch). No mark within 5 s: the
# check is held by a foreground child (a drill, a wait), whose end bash
# waits for before it runs a trap; the whole tree goes (kill_tree), and the
# undo starts after. Either way its exit handler finishes before anything
# is torn down.
stop_check() {
  [[ -n "$check_pid" ]] || return 0
  if kill -0 "$check_pid" 2>/dev/null; then
    kill -TERM "$check_pid" 2>/dev/null || true
    local _
    for _ in $(seq 1 50); do
      if [[ -f "$sd/.check-exit" ]] || ! kill -0 "$check_pid" 2>/dev/null; then break; fi
      sleep 0.1
    done
    if [[ ! -f "$sd/.check-exit" ]] && kill -0 "$check_pid" 2>/dev/null; then
      kill_tree "$check_pid"
    fi
    wait "$check_pid" 2>/dev/null || true
  fi
  check_pid=""
}
# run_drills: drills-eks.sh once per drill (run_drills_list: EKS_BANK_DRILLS,
# or all six), each a check of its own, so one that fails does not skip the
# rest. All of them need setup: after a failed setup the rest are recorded
# as skipped.
run_drills() {
  local d skip=""
  for d in "${run_drills_list[@]}"; do
    if [[ -n "$skip" ]]; then
      result FAIL "drills-$d" "skipped: drills-eks.sh setup exited $skip"
      failed_checks+=("drills-$d")
      continue
    fi
    run_check "drills-$d" drills "$d"
    if [[ "$d" == setup && "$check_rc" != 0 ]]; then skip="$check_rc"; fi
  done
  return 0
}

# --- main ---------------------------------------------------------------------------
# on_exit: whatever ends the script, a failed step or Ctrl-C, stops a check
# in progress (which puts back what it changed) and, for `all`, tears the
# run down (unless EKS_BANK_KEEP=1), so a failure never leaves the cell
# running until the teardown timer.
run_all=0
downed=0
# Set when this process called cluster.sh up, or passed the gate: only then
# is a Terraform state in .state/<name> this run's to tear down (a state an
# earlier run left is not).
made_here=0
gated=0
on_exit() {
  local rc=$? teardown=0 down_pid
  # From here no INT or TERM stops this script: a second Ctrl-C used to end
  # the run before down. Its children inherit INT and TERM ignored, but a
  # program may turn them back on: Terraform does, so a second Ctrl-C could
  # still stop its destroy. The teardown therefore runs as a job of its own
  # (below). Everything the teardown starts ends by itself; nothing in it
  # loops.
  trap - EXIT
  trap '' INT TERM
  if [[ "$rc" != 0 && "$run_all" == 1 && "$refused" != 1 && "$downed" != 1 && "${EKS_BANK_KEEP:-0}" != 1 && -f "$sd/terraform.tfstate" ]] &&
     [[ "$made_here" == 1 || "$gated" == 1 ]]; then
    teardown=1
    : > "$sd/.teardown-next"
  fi
  stop_check
  if [[ "$teardown" == 1 ]]; then
    say "all: stopped with exit $rc; tearing $name down (EKS_BANK_KEEP=1 keeps it)"
    # A job of its own (set -m): its own process group, so a Ctrl-C at the
    # terminal, which goes to this script's group, reaches no part of the
    # teardown, Terraform included. Its stdin is /dev/null: a job outside
    # the terminal's group that read the terminal would be stopped for
    # good. Best effort, under ||: down goes on past a part that fails,
    # and says what is left.
    set -m
    { step_down || exit 1; } < /dev/null &
    down_pid=$!
    set +m
    wait "$down_pid" || say "all: down did not finish; run ./eks-bank.sh $name down, or reap.sh"
  fi
  rm -f "$sd/.teardown-next"
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT TERM
steps=("$@")
if [[ "$1" == all ]]; then
  run_all=1
  steps=(up build install enterprise nlb gvisor verify drills gateways11 scale down)
fi
# EKS_BANK_DRILLS matters to these steps only (up runs estimate): a value
# left in the shell never stops down, or a run of the other steps.
if [[ " ${steps[*]} " =~ \ (up|estimate|drills|scale)\  ]]; then parse_drills; fi
for step in "${steps[@]}"; do
  case "$step" in
    up|estimate) ;;
    # A run that died before its kubeconfig: cluster.sh down needs only its
    # Terraform state.
    down) [[ -f "$sd/kubeconfig" ]] && gate ;;
    *) gate ;;
  esac
  say "--- $step"
  case "$step" in
    estimate) estimate ;;
    gate) echo "gate: ok" ;;
    up) step_up ;;
    build) step_build ;;
    install) step_install ;;
    enterprise) run_check enterprise step_enterprise ;;
    nlb) run_check nlb step_nlb ;;
    gvisor) run_check gvisor step_gvisor ;;
    verify) run_check verify step_verify ;;
    drills) run_drills ;;
    gateways11) run_check gateways11 step_gateways11 ;;
    scale) run_check scale step_scale ;;
    down) step_down ;;
    *) echo "eks-bank.sh: unknown step $step" >&2; exit 2 ;;
  esac
done
# Every step ran. Any FAIL this run wrote makes its answer 1 (down, if asked
# for, has run): a check that exited non-zero, a FAIL a check recorded
# itself before returning 0 (enterprise, nlb, verify, scale-full, ...), and
# a FAIL a drill wrote in drills.txt (slo-alerts, shard-routes, ...: the
# fifth run's closing line named only gvisor and scale-full).
fails="$( { [[ ! -f "$sd/bank.txt" ]] || tail -n +$(( bank_mark + 1 )) "$sd/bank.txt" | awk '$1 == "FAIL" {print $2}'
  [[ ! -f "$sd/drills/drills.txt" ]] || tail -n +$(( drills_mark + 1 )) "$sd/drills/drills.txt" | awk '$1 == "FAIL" {print $2}'
  printf '%s\n' ${failed_checks[@]+"${failed_checks[@]}"}; } | sed '/^$/d' | sort -u | tr '\n' ' ')"
if [[ -n "$fails" ]]; then
  say "eks-bank.sh: checks that failed: ${fails% } ($sd/bank.txt, $sd/drills/drills.txt)"
  exit 1
fi

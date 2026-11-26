#!/usr/bin/env bash
# spa.sh: the SP-A rerun (plans/security-gaps-m1-m4.md §4.2): AerolVM's own
# KVM Firecracker paths on plain EC2, nested virtualization against metal,
# with the warm VMM pool measured and a snapshot move added.
#
#   spa.sh --dry-run                          print the cost and every AWS call; make none
#   spa.sh --i-have-owner-approval            run it (real AWS money: the owner says yes first)
#   options: --legs a,b  --run <name>  --ceiling <dollars, default 10>
#
# Legs (each is one machine; all run at once, each terminates itself):
#   bench-m8i         m8i.xlarge, nested virtualization, Ubuntu 24.04:
#                     install from the commit, then cold, template,
#                     pause/resume (busy and idle guests; a failed start is
#                     tried 3 more times) and warm-pool creates
#   bench-c5metal     c5.metal, the same bench on bare metal
#   move-m8i          m8i.4xlarge, nested: fckind's move proof (kind, cluster
#                     mode, a Firecracker VM moved with its memory)
#   bench-m8i-redial  opt-in: bench-m8i with spa-redial.patch applied to
#                     that machine's build only (the proposed handshake
#                     redial, plans §4.2 "nested resume"); it changes no code
#                     in the repo. Run it only with the owner's yes for it.
#   move-c5metal      opt-in: the move proof on c5.metal
# Default legs: bench-m8i,bench-c5metal,move-m8i.
#
# Settings: AEROL_BUILD_REF (default HEAD), AEROL_PYTHON (a python whose
# boto3 can send CpuOptions.NestedVirtualization; the AWS CLI 2.27 cannot),
# M2_SPA_SAMPLES (20), M2_SPA_CYCLES (40), M2_SPA_IDLE_CYCLES (20),
# M2_PRICE_<TYPE> (cost.py).
#
# Results: integration-tests/k8s/.state/<run>/ (report.txt, <leg>.txt, and
# <leg>-results.tgz from each bench leg). Go (plan §4.2): warm create p50
# under 100 ms, every pause/resume cycle intact, the move passes.
# Exit: 0 go; 5 the run finished and the verdict is no-go; 3 past the
# ceiling; 4 not approved; 130/143/129 Ctrl-C/TERM/hangup; 1 something left.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

usage() { sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; }

run="m2-spa-$(date -u +%m%d%H%M)"
ceiling=10
m2_parse_flags "$@"
legs="${legs_arg:-bench-m8i,bench-c5metal,move-m8i}"
samples="${M2_SPA_SAMPLES:-20}" cycles="${M2_SPA_CYCLES:-40}" idle_cycles="${M2_SPA_IDLE_CYCLES:-20}"
for n in "$samples" "$cycles" "$idle_cycles"; do
  [[ "$n" =~ ^[0-9]+$ ]] || { echo "M2_SPA_SAMPLES, M2_SPA_CYCLES and M2_SPA_IDLE_CYCLES must be whole numbers" >&2; exit 2; }
done

UBUNTU=/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id
AL2023=/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64
# leg_spec <leg>: L_TYPE L_AMI L_ROOT L_DISK L_NESTED L_KIND L_TTL L_PLAN L_PATCH
leg_spec() {
  case "$1" in
    bench-m8i) L_TYPE=m8i.xlarge L_AMI=$UBUNTU L_ROOT=/dev/sda1 L_DISK=40 L_NESTED=1 L_KIND=bench L_TTL=60 L_PLAN=25 L_PATCH=none ;;
    bench-m8i-redial) L_TYPE=m8i.xlarge L_AMI=$UBUNTU L_ROOT=/dev/sda1 L_DISK=40 L_NESTED=1 L_KIND=bench L_TTL=60 L_PLAN=25 L_PATCH=redial ;;
    bench-c5metal) L_TYPE=c5.metal L_AMI=$UBUNTU L_ROOT=/dev/sda1 L_DISK=40 L_NESTED=0 L_KIND=bench L_TTL=60 L_PLAN=30 L_PATCH=none ;;
    # fckind's user data powers off after 100 minutes on its own.
    move-m8i) L_TYPE=m8i.4xlarge L_AMI=$AL2023 L_ROOT=/dev/xvda L_DISK=60 L_NESTED=1 L_KIND=move L_TTL=100 L_PLAN=60 L_PATCH=none ;;
    move-c5metal) L_TYPE=c5.metal L_AMI=$AL2023 L_ROOT=/dev/xvda L_DISK=60 L_NESTED=0 L_KIND=move L_TTL=100 L_PLAN=60 L_PATCH=none ;;
    *) return 1 ;;
  esac
}
IFS=, read -r -a want <<<"$legs"
[[ ${#want[@]} -gt 0 ]] || { echo "no legs" >&2; exit 2; }
cost_args=()
max_ttl=0
for l in "${want[@]}"; do
  leg_spec "$l" || { echo "unknown leg \"$l\" (bench-m8i, bench-c5metal, move-m8i, bench-m8i-redial, move-c5metal)" >&2; exit 2; }
  [[ " ${cost_args[*]-} " != *" --leg $l:"* ]] || { echo "leg \"$l\" is named twice" >&2; exit 2; }
  cost_args+=(--leg "$l:$L_TYPE:$L_PLAN:$L_TTL:$L_DISK")
  ((L_TTL > max_ttl)) && max_ttl=$L_TTL
done

sha="$(git -C "$REPO" rev-parse "${AEROL_BUILD_REF:-HEAD}^{commit}")"
sd="$M2_STATE/$run"
mkdir -p "$sd"
report="$sd/report.txt"
: >"$report"
say "SP-A rerun $run: legs $legs; source ${sha:0:12}; samples $samples, cycles $cycles busy + $idle_cycles idle"
m2_gate "${cost_args[@]}"

# From here on AWS is called (or, dry, printed).
if [[ "$dry" != 1 ]] && grep -q -e m8i <<<"$legs"; then
  "$M2_PY" -I "$here/launch.py" check || exit 2
fi
trap m2_finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
m2_bucket="aerol-itest-artifacts-$(m2_account)"
m2_stage_src "$sha"
src_sum="$M2_SUM"
src_url="$(m2_get_url "$M2_KEY")"
m2_stage_kit kit "$here" spa-bench.py spa-redial.patch
kit_sum="$M2_SUM"
kit_url="$(m2_get_url "$M2_KEY")"
m2_sg_create

for l in "${want[@]}"; do
  leg_spec "$l"
  ud="$sd/userdata-$l.sh"
  if [[ "$L_KIND" == bench ]]; then
    results_url="$(m2_put_url "spike-m2/$run/$l-results.tgz")"
    m2_render "$here/spa-userdata.sh" "$ud" SRC_URL="$src_url" SRC_SHA="$src_sum" KIT_URL="$kit_url" KIT_SHA="$kit_sum" \
      RESULTS_URL="$results_url" TTL_MIN="$L_TTL" SAMPLES="$samples" CYCLES="$cycles" IDLE_CYCLES="$idle_cycles" \
      PATCH="$L_PATCH" LEG="$l"
    m2_launch "$l" "$L_TYPE" "$L_AMI" "$ud" "$L_ROOT" "$L_DISK" "$L_NESTED" 0 "$L_TTL" SPA
  else
    m2_render "$K8S/fckind/userdata.sh" "$ud" SRC_URL="$src_url" SRC_SHA="$src_sum" PROOF=move
    m2_launch "$l" "$L_TYPE" "$L_AMI" "$ud" "$L_ROOT" "$L_DISK" "$L_NESTED" 0 "$L_TTL" FCK
  fi
done

m2_follow $((max_ttl + 5))

# The bench legs' full logs and JSON (kept in S3 as evidence).
for l in "${want[@]}"; do
  leg_spec "$l"
  [[ "$L_KIND" == bench ]] || continue
  x aws s3 cp --only-show-errors --region "$M2_REGION" "s3://$m2_bucket/spike-m2/$run/$l-results.tgz" "$sd/$l-results.tgz" ||
    say "$l: no results in S3"
done
if [[ "$dry" != 1 ]]; then
  vrc=0
  python3 -I "$here/verdict.py" "$sd" >"$sd/verdict.txt" 2>&1 || vrc=$?
  while IFS= read -r line; do m2_out "$line"; done <"$sd/verdict.txt"
  # m2_finish reports this code (5: the run finished, the verdict is no-go).
  [[ "$vrc" == 0 ]] || exit 5
fi

#!/usr/bin/env bash
# spb.sh: spike SP-B steps 1-4 (plans/security-gaps-m1-m4.md §4.2) on one
# m7i.xlarge launched with Nitro Enclaves on: Firecracker v1.18 in direct
# mode under AerolVM's jailer argv, an EFI bzImage guest kernel, toolboxd
# answering on vsock port 1024 (step 1); TAP networking under nft rules
# (step 2); confidential mode and an attestation document from /dev/nsm
# checked up to the AWS root (step 3); 50 creates at once against the
# 5-per-vCPU cap (step 4); and a parked VM's claim time (eng review R19).
#
#   spb.sh --dry-run                          print the cost and every AWS call; make none
#   spb.sh --i-have-owner-approval            run it (real AWS money: the owner says yes first)
#   options: --run <name>  --ceiling <dollars, default 3>
#
# No SSH and no inbound rule. The machine's first boot (spb-userdata.sh)
# fetches the commit's source and this kit from S3, checks both, reserves
# the Nitro memory pool (kernel argument) and reboots; the second boot
# (spb-run.sh, a systemd unit) builds the tools (spb-setup.sh), runs the
# steps (spb.py) and PUTs its results to S3. SPB lines come back on the
# serial console. It powers itself off when done or at its deadline,
# across the reboot, and powering off terminates it; this script
# terminates it on any exit and runs the leak check.
#
# Settings: AEROL_BUILD_REF (default HEAD), AEROL_PYTHON (for boto3),
# M2_SPB_TYPE (m7i.xlarge), M2_SPB_POOL (6G@0: 20 VMs of 256 MiB fit after
# the slot donations), M2_SPB_STEPS ("step1 step2 step3a step3b step4
# parked"; step5, step6 and probe-* are there too), M2_PRICE_<TYPE>.
# Results: integration-tests/k8s/.state/<run>/ (report.txt, spb.txt,
# spb-results.tgz). Go (plan §4.2): steps 1-4 pass and a cold create is
# under 2 s end to end.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

usage() { sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; }

run="m2-spb-$(date -u +%m%d%H%M)"
ceiling=3
m2_parse_flags "$@"
[[ -z "$legs_arg" ]] || { echo "spb.sh has one leg; --legs is for spa.sh" >&2; exit 2; }
itype="${M2_SPB_TYPE:-m7i.xlarge}"
pool="${M2_SPB_POOL:-6G@0}"
steps="${M2_SPB_STEPS:-step1 step2 step3a step3b step4 parked}"
[[ "$pool" =~ ^[0-9]+[GM](@[0-9]+)?(,[0-9]+[GM](@[0-9]+)?)*$ ]] || { echo "M2_SPB_POOL looks wrong: $pool" >&2; exit 2; }
for s in $steps; do
  case "$s" in step1 | step2 | step3a | step3b | step4 | step5 | step6 | parked | probe-pci-off | probe-dirty-pages | probe-min-mem | probe-pause) ;;
    *) echo "unknown step \"$s\" in M2_SPB_STEPS" >&2; exit 2 ;;
  esac
done
ttl=120 plan=45 disk=30

sha="$(git -C "$REPO" rev-parse "${AEROL_BUILD_REF:-HEAD}^{commit}")"
sd="$M2_STATE/$run"
mkdir -p "$sd"
report="$sd/report.txt"
: >"$report"
say "SP-B $run: $itype with Nitro Enclaves, pool $pool, steps: $steps; source ${sha:0:12}"
m2_gate --leg "spb:$itype:$plan:$ttl:$disk"

trap m2_finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
m2_bucket="aerol-itest-artifacts-$(m2_account)"
m2_stage_src "$sha"
src_sum="$M2_SUM"
src_url="$(m2_get_url "$M2_KEY")"
m2_stage_kit kit "$here" spb-run.sh spb-setup.sh spb.py spb_attest.py nsm-attest.go
kit_sum="$M2_SUM"
kit_url="$(m2_get_url "$M2_KEY")"
results_url="$(m2_put_url "spike-m2/$run/spb-results.tgz")"
m2_sg_create
ud="$sd/userdata-spb.sh"
m2_render "$here/spb-userdata.sh" "$ud" SRC_URL="$src_url" SRC_SHA="$src_sum" KIT_URL="$kit_url" KIT_SHA="$kit_sum" \
  RESULTS_URL="$results_url" TTL_MIN="$ttl" POOL="$pool" STEPS="$steps"
m2_launch spb "$itype" /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.18-x86_64 "$ud" /dev/xvda "$disk" 0 1 "$ttl" SPB

m2_follow $((ttl + 5))
x aws s3 cp --only-show-errors --region "$M2_REGION" "s3://$m2_bucket/spike-m2/$run/spb-results.tgz" "$sd/spb-results.tgz" ||
  say "no results in S3"
if [[ "$dry" != 1 ]]; then
  grep -h '^SPB VERDICT' "$sd/spb.txt" 2>/dev/null | tee -a "$report" >&2 || say "no verdict lines: the run did not finish"
fi

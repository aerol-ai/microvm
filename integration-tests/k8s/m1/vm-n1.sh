#!/usr/bin/env bash
# vm-n1.sh: part B of the M1 drill: N1's WASM warm-create question on one
# EC2 machine (the chart refuses WASM in a split worker pod, so EKS cannot
# answer it). One m7i.xlarge, Ubuntu 24.04, us-east-1, default VPC, in a
# security group of its own with no inbound rule, no SSH: results come back
# on the serial console.
#
#   vm-n1.sh <vm name>              # e.g. m1d-1-vm
#   DRY_RUN=1 vm-n1.sh <vm name>    # print every AWS call; make nothing
#
# It spends real AWS money (README.md beside it): the owner says yes first.
#
# The commit's source (AEROL_BUILD_REF, default HEAD of this checkout) and
# this folder's vm-bench.py go to the artifact bucket (~12 MB, once); the machine
# fetches them by presigned link (3 h). It runs vm-userdata.sh: install in
# single, bench, split, bench, single, bench, split, bench. It terminates
# itself when done or at its TTL (M1_VM_TTL_MIN, 170), and this script
# terminates it on any exit (M1_VM_KEEP=1 leaves it to its TTL). It carries
# the tags scripts/integration-reap.sh looks for (itest, ttl 3 h), so
# `make integration-reap` ends it too if all else fails.
#
# Cost guard: before anything is made, cost.py --vm-only prices the worst
# case (the machine runs until it powers itself off, plus 10 minutes) and
# refuses past M1_VM_CEILING ($2), or a type it has no price for unless
# M1_PRICE_VM gives one.
# Settings: M1_VM_TYPE (m7i.xlarge), M1_VM_TTL_MIN (170), M1_VM_CEILING (2),
# M1_VM_ROUNDS (15), M1_VM_BUSY (8). Runs on macOS's bash 3.2 too.
# The report: integration-tests/k8s/.state/<vm name>/vm-report.txt; the
# verdict: n1-stats.py on it.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$K8S/../.." && pwd)"
vm="${1:?usage: vm-n1.sh <vm name>}"
[[ "$vm" =~ ^[a-z][a-z0-9-]{2,40}$ ]] || { echo "vm-n1.sh: bad name" >&2; exit 2; }
case "${DRY_RUN:-0}" in 0|1) dry="${DRY_RUN:-0}" ;; *) echo "DRY_RUN must be 0 or 1" >&2; exit 2 ;; esac
region=us-east-1
itype="${M1_VM_TYPE:-m7i.xlarge}"
ttl_min="${M1_VM_TTL_MIN:-170}"
sha="$(git -C "$REPO" rev-parse "${AEROL_BUILD_REF:-HEAD}^{commit}")"
sd="$K8S/.state/$vm"
mkdir -p "$sd"
report="$sd/vm-report.txt"
: > "$report"
say() { echo "[$(date -u +%T)] $*" | tee -a "$report" >&2; }
[[ "$ttl_min" =~ ^[0-9]+$ ]] || { echo "vm-n1.sh: M1_VM_TTL_MIN must be whole minutes" >&2; exit 2; }
# The cost guard, before any upload or launch (exit 3 past the ceiling).
python3 -I "$HERE/cost.py" --vm-only --vm-type "$itype" --vm-ttl-min "$ttl_min" --ceiling "${M1_VM_CEILING:-2}" \
  --hourly-out "$sd/hourly" | tee -a "$report"
x() {
  if [[ "$dry" == 1 ]]; then printf 'dry-run:' >&2; printf ' %q' "$@" >&2; printf '\n' >&2; return 0; fi
  "$@"
}

if [[ "$dry" == 1 ]]; then acct=111122223333; else acct="$(aws sts get-caller-identity --query Account --output text)"; fi
bucket="aerol-itest-artifacts-$acct"
prefix="m1-vm/${sha:0:12}"
# The source, once per commit; the kit (vm-bench.py), per run.
if [[ "$dry" == 1 ]]; then
  echo "dry-run: git archive --format=tar.gz $sha > $sd/src.tgz; aws s3 cp $sd/src.tgz s3://$bucket/$prefix/src.tgz (if absent)" >&2
else
  if ! aws s3 ls "s3://$bucket/$prefix/src.tgz" >/dev/null 2>&1; then
    git -C "$REPO" archive --format=tar.gz -o "$sd/src.tgz" "$sha"
    aws s3 cp --only-show-errors --region "$region" "$sd/src.tgz" "s3://$bucket/$prefix/src.tgz"
  fi
fi
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$sd/kit.tgz" -C "$HERE" vm-bench.py
x aws s3 cp --only-show-errors --region "$region" "$sd/kit.tgz" "s3://$bucket/$prefix/kit-$vm.tgz"
if [[ "$dry" == 1 ]]; then
  src_url="https://$bucket.s3.amazonaws.com/$prefix/src.tgz?X-Amz-Signature=dry"; kit_url="https://$bucket.s3.amazonaws.com/$prefix/kit-$vm.tgz?X-Amz-Signature=dry"
else
  src_url="$(aws s3 presign "s3://$bucket/$prefix/src.tgz" --expires-in 10800 --region "$region")"
  kit_url="$(aws s3 presign "s3://$bucket/$prefix/kit-$vm.tgz" --expires-in 10800 --region "$region")"
fi
# Not sed: a presigned link is full of "&", which sed reads as the match.
SRC="$src_url" KIT="$kit_url" TTL="$ttl_min" R="${M1_VM_ROUNDS:-15}" B="${M1_VM_BUSY:-8}" python3 -I -c '
import os, sys
t = open(sys.argv[1]).read()
for k, v in (("@SRC_URL@", "SRC"), ("@KIT_URL@", "KIT"), ("@TTL_MIN@", "TTL"), ("@ROUNDS@", "R"), ("@BUSY@", "B")):
    t = t.replace(k, os.environ[v])
sys.stdout.write(t)' "$HERE/vm-userdata.sh" > "$sd/userdata.sh"
say "source ${sha:0:12} staged; launching $itype ($vm)"

if [[ "$dry" == 1 ]]; then ami=ami-dry; ttl=2099-01-01T00:00:00Z; else
  ami="$(aws ssm get-parameter --region "$region" --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value --output text)"
  ttl="$(date -u -v+3H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+3 hours' +%Y-%m-%dT%H:%M:%SZ)"
fi
tags="{Key=Name,Value=$vm},{Key=aerol:run,Value=$vm},{Key=aerol:purpose,Value=m1-vm},{Key=aerol:ttl,Value=$ttl},{Key=aerol:owner,Value=itest},{Key=itest,Value=true},{Key=ttl,Value=3}"
id="" sg=""
# finish_vm (on any exit): the machine terminated, then its security group
# deleted once the machine is gone (a group in use cannot be deleted).
# Both carry the run's tags, so leak-check.sh lists either if it is left.
finish_vm() {
  [[ -z "$id" ]] || x aws ec2 terminate-instances --region "$region" --instance-ids "$id" >/dev/null || true
  [[ "$dry" == 1 || -z "$id" ]] || date +%s > "$sd/ended-at"
  if [[ -n "$sg" ]]; then
    [[ -z "$id" ]] || x aws ec2 wait instance-terminated --region "$region" --instance-ids "$id" || true
    x aws ec2 delete-security-group --region "$region" --group-id "$sg" ||
      say "security group $sg is left: aws ec2 delete-security-group --region $region --group-id $sg"
  fi
}
keep_vm() {
  [[ "$dry" == 1 || -z "$id" ]] || date +%s > "$sd/ended-at"
  [[ -z "$sg" ]] || say "M1_VM_KEEP=1: once $id has ended, delete its group: aws ec2 delete-security-group --region $region --group-id $sg"
}
if [[ "${M1_VM_KEEP:-0}" == 1 ]]; then trap keep_vm EXIT; else trap finish_vm EXIT; fi
# The VM's own security group in the default VPC: a new group has no
# inbound rule and lets everything out (the downloads), so nothing can
# reach the machine.
if [[ "$dry" == 1 ]]; then
  vpc=vpc-dry
  x aws ec2 create-security-group --region "$region" --group-name "$vm" --vpc-id "$vpc" \
    --description "M1 drill VM $vm: no inbound rule" --tag-specifications "ResourceType=security-group,Tags=[$tags]"
  sg=sg-dry
else
  vpc="$(aws ec2 describe-vpcs --region "$region" --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)"
  [[ "$vpc" == vpc-* ]] || { say "no default VPC in $region (got \"$vpc\")"; exit 1; }
  sg="$(aws ec2 create-security-group --region "$region" --group-name "$vm" --vpc-id "$vpc" \
    --description "M1 drill VM $vm: no inbound rule" --tag-specifications "ResourceType=security-group,Tags=[$tags]" \
    --query GroupId --output text)"
fi
if [[ "$dry" == 1 ]]; then
  x aws ec2 run-instances --region "$region" --image-id "$ami" --instance-type "$itype" --count 1 \
    --security-group-ids "$sg" \
    --instance-initiated-shutdown-behavior terminate --user-data "file://$sd/userdata.sh" \
    --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=40,VolumeType=gp3,DeleteOnTermination=true}' \
    --tag-specifications "ResourceType=instance,Tags=[$tags]" "ResourceType=volume,Tags=[$tags]"
  id=i-dry
else
  id="$(aws ec2 run-instances --region "$region" --image-id "$ami" --instance-type "$itype" --count 1 \
    --security-group-ids "$sg" \
    --instance-initiated-shutdown-behavior terminate --user-data "file://$sd/userdata.sh" \
    --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=40,VolumeType=gp3,DeleteOnTermination=true}' \
    --tag-specifications "ResourceType=instance,Tags=[$tags]" "ResourceType=volume,Tags=[$tags]" \
    --query 'Instances[0].InstanceId' --output text)"
fi
# The running cost (m1-eks.sh cost_check) counts the VM from here to its end.
[[ "$dry" == 1 ]] || { date +%s > "$sd/started-at"; echo "$id" > "$sd/instance-id"; }
say "instance $id in security group $sg"
if [[ "$dry" == 1 ]]; then
  echo "dry-run: follow aws ec2 get-console-output --instance-id $id --latest every 20 s until 'VMN1 DONE' (at most $ttl_min min)" >&2
  echo "dry-run: python3 -I $HERE/n1-stats.py $report > $sd/vm-verdict.txt" >&2
  exit 0
fi

# Each VMN1 and N1 line as it comes, until DONE or the machine is gone. The
# console keeps its last 64 KB: follow the last line printed, by its text.
start=$(date +%s) last="" done=""
while (( $(date +%s) - start < ttl_min * 60 )); do
  out="$(aws ec2 get-console-output --region "$region" --instance-id "$id" --latest --query Output --output text 2>/dev/null || true)"
  lines=()
  while IFS= read -r l; do lines+=("$l"); done < <(grep -oE '(VMN1|N1) .*' <<<"$out" | sed 's/\r$//' || true)
  from=0
  if [[ -n "$last" ]]; then
    for (( i = ${#lines[@]} - 1; i >= 0; i-- )); do
      [[ "${lines[$i]}" == "$last" ]] && { from=$((i + 1)); break; }
    done
  fi
  for (( i = from; i < ${#lines[@]}; i++ )); do echo "${lines[$i]}" | tee -a "$report"; done
  (( ${#lines[@]} > 0 )) && last="${lines[${#lines[@]} - 1]}"
  grep -q 'VMN1 DONE' <<<"$out" && { done=1; break; }
  state="$(aws ec2 describe-instances --region "$region" --instance-ids "$id" --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || true)"
  [[ "$state" == shutting-down || "$state" == terminated ]] && { say "the instance is $state"; break; }
  sleep 20
done
[[ -n "$done" ]] || say "no DONE line"
python3 -I "$HERE/n1-stats.py" "$report" > "$sd/vm-verdict.txt" 2>&1 || true
say "--- done in $(( ($(date +%s) - start) / 60 )) min; verdict:"; cat "$sd/vm-verdict.txt" | tee -a "$report"

#!/usr/bin/env bash
# integration-reap.sh — the cost safety net.
#
# Terminates any EC2 instance tagged itest=true whose age exceeds its ttl tag
# (hours, default 4). Runs independently of run.sh, so a hard kill / runner OOM
# / power loss that skips run.sh's trap teardown can't leak the expensive metal
# firecracker node ($4/hr) indefinitely. Wire into cron or CI.
#
# Usage:
#   scripts/integration-reap.sh [--region us-east-1] [--dry-run]
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --region) shift; REGION="${1:?}";;
    --region=*) REGION="${arg#*=}";;
    --dry-run) DRY_RUN=1;;
  esac
done

DEFAULT_TTL_HOURS=4
now_epoch=$(date +%s)

# Pull running/pending itest instances with their launch time + ttl tag.
instances=$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:itest,Values=true" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query 'Reservations[].Instances[].{Id:InstanceId,Launch:LaunchTime,Ttl:Tags[?Key==`ttl`]|[0].Value}' \
  --output json)

echo "$instances" | jq -c '.[]' | while read -r row; do
  id=$(echo "$row" | jq -r '.Id')
  launch=$(echo "$row" | jq -r '.Launch')
  ttl=$(echo "$row" | jq -r '.Ttl // empty')
  ttl_hours="${ttl:-$DEFAULT_TTL_HOURS}"

  launch_epoch=$(date -d "$launch" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "${launch%%.*}" +%s 2>/dev/null || echo 0)
  age_hours=$(( (now_epoch - launch_epoch) / 3600 ))

  if (( age_hours >= ttl_hours )); then
    if [[ "$DRY_RUN" == "1" ]]; then
      echo "[dry-run] would terminate ${id} (age ${age_hours}h >= ttl ${ttl_hours}h)"
    else
      echo "terminating ${id} (age ${age_hours}h >= ttl ${ttl_hours}h)"
      aws ec2 terminate-instances --region "$REGION" --instance-ids "$id" >/dev/null
    fi
  else
    echo "keeping ${id} (age ${age_hours}h < ttl ${ttl_hours}h)"
  fi
done

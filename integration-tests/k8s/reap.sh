#!/usr/bin/env bash
# reap.sh: delete Phase 0 EKS clusters whose aerol:ttl has passed.
#
#   reap.sh            # delete what is past its TTL
#   DRY_RUN=1 reap.sh  # only say what would go
#
# scripts/integration-reap.sh terminates EC2 instances only. An EKS cluster
# keeps billing for its control plane, and a managed node group recreates any
# instance that reaper kills, so the cluster itself has to go. Node groups
# first (EKS refuses to delete a cluster that still has them), then the
# cluster. The VPC, subnets and IAM roles cost nothing and are only reported;
# `cluster.sh down <name>` removes them with the run's own Terraform state.
set -euo pipefail

region="${AWS_REGION:-$(aws configure get region 2>/dev/null || echo us-east-1)}"
dry="${DRY_RUN:-0}"
now="$(date -u +%s)"

epoch_of() {
  date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$1" +%s 2>/dev/null || date -u -d "$1" +%s
}

for c in $(aws eks list-clusters --region "$region" --query 'clusters[]' --output text); do
  tags="$(aws eks describe-cluster --region "$region" --name "$c" --query 'cluster.tags' --output json)"
  purpose="$(jq -r '."aerol:purpose" // ""' <<<"$tags")"
  ttl="$(jq -r '."aerol:ttl" // ""' <<<"$tags")"
  [[ "$purpose" == "k8s-phase0" ]] || continue
  if [[ -z "$ttl" ]]; then
    echo "skip $c: no aerol:ttl tag, so not ours to judge"
    continue
  fi
  if ! exp="$(epoch_of "$ttl")"; then
    echo "skip $c: aerol:ttl '$ttl' does not parse"
    continue
  fi
  if (( exp > now )); then
    echo "keep $c: ttl $ttl"
    continue
  fi
  echo "reap $c: ttl $ttl passed"
  [[ "$dry" == 1 ]] && continue
  ngs="$(aws eks list-nodegroups --region "$region" --cluster-name "$c" --query 'nodegroups[]' --output text)"
  for ng in $ngs; do
    aws eks delete-nodegroup --region "$region" --cluster-name "$c" --nodegroup-name "$ng" >/dev/null
  done
  for ng in $ngs; do
    aws eks wait nodegroup-deleted --region "$region" --cluster-name "$c" --nodegroup-name "$ng"
  done
  aws eks delete-cluster --region "$region" --name "$c" >/dev/null
  echo "deleted $c"
done

aws ec2 describe-vpcs --region "$region" \
  --filters Name=tag:aerol:purpose,Values=k8s-phase0 \
  --query 'Vpcs[].[VpcId, Tags[?Key==`aerol:run`]|[0].Value]' --output text |
  while read -r vpc run; do
    [[ -n "$vpc" ]] && echo "left over (no cost): VPC $vpc from run $run; remove with: cluster.sh down $run"
  done

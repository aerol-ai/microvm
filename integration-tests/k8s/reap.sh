#!/usr/bin/env bash
# reap.sh: remove what Phase 0 EKS runs (cluster.sh, cell.sh, eks-bank.sh)
# left behind, each thing once its own aerol:ttl has passed.
#
#   reap.sh            # remove what is past its TTL
#   DRY_RUN=1 reap.sh  # only say what would go (DRY_RUN is 0 or 1, nothing else)
#
# scripts/integration-reap.sh terminates EC2 instances only. An EKS cluster
# keeps billing for its control plane, and a managed node group recreates any
# instance that reaper kills, so the cluster itself has to go. A run whose
# cluster is already gone (the teardown Lambda deleted it, or a down that
# stopped halfway) still leaves things that bill or block: Karpenter's
# machines, the load balancer controller's NLB, volumes, ECR images, a
# scale-cap schedule, the audit buckets, and the VPC, IAM roles, OIDC
# provider and Lambda that `cluster.sh down` would have destroyed.
#
# Every thing is judged on its own tags, never on another's: it is removed
# only when it carries aerol:purpose=k8s-phase0 (this harness's; other
# harnesses tag aerol:run too) and its own aerol:ttl has passed. A run name
# can be used again: an older run's leftover past its TTL says nothing about
# a live run of the same name, whose things carry their own, later TTL. A
# thing of this harness with no TTL that parses is reported and kept.
#   machines                         terminated
#   load balancers                   deleted (the controller's tags)
#   clusters                         their node groups (each on its own tags),
#                                    then the cluster once none is left
#   the teardown Lambdas, their log groups, ECR repositories (with their
#   images), OIDC providers, IAM roles (their policies and instance
#   profiles first), unattached volumes      deleted
#   the audit buckets                emptied with the governance bypass (the
#                                    witness is GOVERNANCE-locked for this),
#                                    then deleted
#   VPCs                             their endpoints, interfaces, gateways,
#                                    subnets, route tables and security
#                                    groups, then themselves, once no cluster
#                                    uses them
# EventBridge schedules carry no tags: a one-time teardown or scale-cap
# schedule (<run>-teardown-*, <run>-scale-cap) whose own at() time is more
# than an hour past has fired and does nothing more; that one is deleted.
# A failure is reported and the reap goes on: one stuck thing never keeps
# the rest running.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# empty_versioned_bucket: run.sh's, tested in safety/empty_bucket_test.go.
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

case "${DRY_RUN:-0}" in
  0|1) dry="${DRY_RUN:-0}" ;;
  *) echo "reap.sh: DRY_RUN must be 0 or 1, not \"$DRY_RUN\"; nothing ran" >&2; exit 2 ;;
esac
region="${AWS_REGION:-$(aws configure get region 2>/dev/null || echo us-east-1)}"
now="$(date -u +%s)"

epoch_of() {
  date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$1" +%s 2>/dev/null || date -u -d "$1" +%s
}
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# act <what> <cmd...>: delete something, or say it would. A failure is
# reported and the reap goes on.
act() {
  local what="$1"; shift
  if [[ "$dry" == 1 ]]; then
    echo "would remove $what"
    return 0
  fi
  if "$@" >/dev/null 2>"$tmp/err"; then
    echo "removed $what"
  else
    echo "could not remove $what: $(tr '\n' ' ' < "$tmp/err" | cut -c1-200)" >&2
  fi
}
# q <aws args...>: a read; empty when it fails (reported).
q() {
  local out
  if out="$(aws --region "$region" "$@" 2>"$tmp/qerr")"; then
    [[ "$out" == None ]] || printf '%s\n' "$out"
  else
    echo "reap: $1 $2 failed: $(tr '\n' ' ' < "$tmp/qerr" | cut -c1-200)" >&2
  fi
}

# expired <kind> <id> <tags>: the thing is this harness's and its own
# aerol:ttl has passed. <tags> is its tags as [{Key, Value}] or {key: value}.
# Sets run to its aerol:run. One of this harness's with no TTL that parses
# is reported and kept; a live one is kept.
run=""
expired() {
  local kind="$1" id="$2" line purpose ttl exp
  line="$(jq -r 'if type == "array" then (map({(.Key): .Value}) | add // {}) else (. // {}) end
    | "\(.["aerol:purpose"] // "-")\t\(.["aerol:run"] // "-")\t\(.["aerol:ttl"] // "-")"' <<<"${3:-null}" 2>/dev/null || printf -- '-\t-\t-')"
  IFS=$'\t' read -r purpose run ttl <<<"$line"
  [[ "$purpose" == k8s-phase0 ]] || return 1
  if [[ "$ttl" == - ]] || ! exp="$(epoch_of "$ttl" 2>/dev/null)"; then
    echo "keep $kind $id of run $run: it has no aerol:ttl that parses ('$ttl'); remove it by hand once its run is over"
    return 1
  fi
  if (( exp > now )); then
    echo "keep $kind $id of run $run: ttl $ttl"
    return 1
  fi
  return 0
}

reap_vpc() { # reap_vpc <vpc>
  local vpc="$1" id sgs
  for id in $(q ec2 describe-vpc-endpoints --filters "Name=vpc-id,Values=$vpc" --query 'VpcEndpoints[].VpcEndpointId' --output text); do
    act "VPC endpoint $id of $vpc" aws --region "$region" ec2 delete-vpc-endpoints --vpc-endpoint-ids "$id"
  done
  for id in $(q ec2 describe-network-interfaces --filters "Name=vpc-id,Values=$vpc" Name=status,Values=available --query 'NetworkInterfaces[].NetworkInterfaceId' --output text); do
    act "network interface $id of $vpc" aws --region "$region" ec2 delete-network-interface --network-interface-id "$id"
  done
  for id in $(q ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$vpc" --query 'InternetGateways[].InternetGatewayId' --output text); do
    act "internet gateway $id from $vpc" aws --region "$region" ec2 detach-internet-gateway --internet-gateway-id "$id" --vpc-id "$vpc"
    act "internet gateway $id" aws --region "$region" ec2 delete-internet-gateway --internet-gateway-id "$id"
  done
  for id in $(q ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc" --query 'Subnets[].SubnetId' --output text); do
    act "subnet $id of $vpc" aws --region "$region" ec2 delete-subnet --subnet-id "$id"
  done
  for id in $(q ec2 describe-route-tables --filters "Name=vpc-id,Values=$vpc" --query 'RouteTables[?!(Associations[?Main])].RouteTableId' --output text); do
    act "route table $id of $vpc" aws --region "$region" ec2 delete-route-table --route-table-id "$id"
  done
  # Security groups can name each other in their rules: every rule first.
  sgs="$(q ec2 describe-security-groups --filters "Name=vpc-id,Values=$vpc" --query "SecurityGroups[?GroupName != 'default'].GroupId" --output text)"
  if [[ "$dry" != 1 ]]; then
    for id in $sgs; do
      local perms
      perms="$(aws --region "$region" ec2 describe-security-groups --group-ids "$id" --query 'SecurityGroups[0].IpPermissions' --output json 2>/dev/null || echo '[]')"
      jq -e 'length > 0' <<<"$perms" >/dev/null 2>&1 &&
        { aws --region "$region" ec2 revoke-security-group-ingress --group-id "$id" --ip-permissions "$perms" >/dev/null 2>&1 || true; }
    done
  fi
  for id in $sgs; do
    act "security group $id of $vpc" aws --region "$region" ec2 delete-security-group --group-id "$id"
  done
  act "VPC $vpc" aws --region "$region" ec2 delete-vpc --vpc-id "$vpc"
}

reap_role() { # reap_role <role>
  local role="$1" p
  for p in $(q iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyArn' --output text); do
    act "role $role's policy $p" aws iam detach-role-policy --role-name "$role" --policy-arn "$p"
  done
  for p in $(q iam list-role-policies --role-name "$role" --query 'PolicyNames[]' --output text); do
    act "role $role's inline policy $p" aws iam delete-role-policy --role-name "$role" --policy-name "$p"
  done
  # Karpenter's instance profiles hold the node role.
  for p in $(q iam list-instance-profiles-for-role --role-name "$role" --query 'InstanceProfiles[].InstanceProfileName' --output text); do
    act "role $role from instance profile $p" aws iam remove-role-from-instance-profile --instance-profile-name "$p" --role-name "$role"
    act "instance profile $p" aws iam delete-instance-profile --instance-profile-name "$p"
  done
  act "IAM role $role" aws iam delete-role --role-name "$role"
}

# --- machines ------------------------------------------------------------------------
ids=""
while read -r item; do
  [[ -n "$item" ]] || continue
  # An answer of another shape is skipped, never a reason to stop.
  id="$(jq -r '.id? // empty' <<<"$item" 2>/dev/null || true)"
  [[ -n "$id" ]] || continue
  if expired machine "$id" "$(jq -c '.tags? // []' <<<"$item" 2>/dev/null || echo '[]')"; then ids="$ids $id"; fi
done < <(q ec2 describe-instances --filters Name=tag:aerol:purpose,Values=k8s-phase0 Name=instance-state-name,Values=pending,running,stopping,stopped \
  --query 'Reservations[].Instances[].{id: InstanceId, tags: Tags}' --output json | jq -c '.[]?')
# shellcheck disable=SC2086
[[ -z "$ids" ]] || act "machines$ids" aws --region "$region" ec2 terminate-instances --instance-ids $ids

# --- load balancers ----------------------------------------------------------------
lbs="$(q elbv2 describe-load-balancers --query 'LoadBalancers[].LoadBalancerArn' --output text | tr '\t' '\n' | sed '/^$/d')"
if [[ -n "$lbs" ]]; then
  while read -r batch; do
    # shellcheck disable=SC2086
    q elbv2 describe-tags --resource-arns $batch --query TagDescriptions --output json
  done < <(xargs -n 20 <<<"$lbs") | jq -c '.[]?' | while read -r d; do
    arn="$(jq -r .ResourceArn <<<"$d")"
    if expired "load balancer" "$arn" "$(jq -c .Tags <<<"$d")"; then
      act "load balancer $arn" aws --region "$region" elbv2 delete-load-balancer --load-balancer-arn "$arn"
    fi
  done
fi

# --- clusters, their node groups first ------------------------------------------------
clusters_left="$tmp/clusters"
: > "$clusters_left"
for c in $(q eks list-clusters --query 'clusters[]' --output text); do
  info="$(q eks describe-cluster --name "$c" --query '{tags: cluster.tags, vpc: cluster.resourcesVpcConfig.vpcId}' --output json)"
  [[ -n "$info" ]] || info='{}'
  echo "$c $(jq -r '.vpc // "-"' <<<"$info")" >> "$clusters_left"
  expired cluster "$c" "$(jq -c '.tags' <<<"$info")" || continue
  ngs_left=""
  for ng in $(q eks list-nodegroups --cluster-name "$c" --query 'nodegroups[]' --output text); do
    if expired "node group" "$c/$ng" "$(q eks describe-nodegroup --cluster-name "$c" --nodegroup-name "$ng" --query nodegroup.tags --output json)"; then
      act "node group $c/$ng" aws --region "$region" eks delete-nodegroup --cluster-name "$c" --nodegroup-name "$ng"
      if [[ "$dry" != 1 ]] && ! aws --region "$region" eks wait nodegroup-deleted --cluster-name "$c" --nodegroup-name "$ng" 2>/dev/null; then
        echo "reap: node group $c/$ng is not deleted yet; a later reap deletes the cluster" >&2
        ngs_left=1
      fi
    else
      ngs_left=1
    fi
  done
  if [[ -n "$ngs_left" ]]; then
    echo "keep cluster $c until its node groups are gone"
  else
    act "cluster $c" aws --region "$region" eks delete-cluster --name "$c"
  fi
done

# --- the teardown Lambdas and their log groups -------------------------------------
for arn in $(q lambda list-functions --query 'Functions[?ends_with(FunctionName, `-teardown`)].FunctionArn' --output text); do
  if expired "teardown Lambda" "${arn##*:}" "$(q lambda list-tags --resource "$arn" --query Tags --output json)"; then
    act "teardown Lambda ${arn##*:}" aws --region "$region" lambda delete-function --function-name "${arn##*:}"
  fi
done
for lg in $(q logs describe-log-groups --log-group-name-prefix /aws/lambda/ --query 'logGroups[?ends_with(logGroupName, `-teardown`)].logGroupName' --output text); do
  if expired "log group" "$lg" "$(q logs list-tags-log-group --log-group-name "$lg" --query tags --output json)"; then
    act "log group $lg" aws --region "$region" logs delete-log-group --log-group-name "$lg"
  fi
done

# --- ECR repositories, OIDC providers, IAM roles, volumes --------------------------
for arn in $(q ecr describe-repositories --query 'repositories[].repositoryArn' --output text); do
  if expired "ECR repository" "${arn##*:repository/}" "$(q ecr list-tags-for-resource --resource-arn "$arn" --query tags --output json)"; then
    act "ECR repository ${arn##*:repository/} and its images" aws --region "$region" ecr delete-repository --repository-name "${arn##*:repository/}" --force
  fi
done
for arn in $(q iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn' --output text); do
  if expired "OIDC provider" "$arn" "$(q iam list-open-id-connect-provider-tags --open-id-connect-provider-arn "$arn" --query Tags --output json)"; then
    act "OIDC provider $arn" aws iam delete-open-id-connect-provider --open-id-connect-provider-arn "$arn"
  fi
done
# Only the names Terraform gives roles (<run>-<role>); each judged on its tags.
roles="$(q iam list-roles --query 'Roles[?ends_with(RoleName, `-cluster`) || ends_with(RoleName, `-node`) || ends_with(RoleName, `-karpenter`) || ends_with(RoleName, `-ebs-csi`) || ends_with(RoleName, `-audit`) || ends_with(RoleName, `-lb-controller`) || ends_with(RoleName, `-teardown`) || ends_with(RoleName, `-scheduler`)].RoleName' --output text)"
for role in $roles; do
  if expired "IAM role" "$role" "$(q iam list-role-tags --role-name "$role" --query Tags --output json)"; then reap_role "$role"; fi
done
while read -r item; do
  [[ -n "$item" ]] || continue
  # An answer of another shape is skipped, never a reason to stop.
  id="$(jq -r '.id? // empty' <<<"$item" 2>/dev/null || true)"
  [[ -n "$id" ]] || continue
  if expired volume "$id" "$(jq -c '.tags? // []' <<<"$item" 2>/dev/null || echo '[]')"; then act "volume $id" aws --region "$region" ec2 delete-volume --volume-id "$id"; fi
done < <(q ec2 describe-volumes --filters Name=tag:aerol:purpose,Values=k8s-phase0 Name=status,Values=available \
  --query 'Volumes[].{id: VolumeId, tags: Tags}' --output json | jq -c '.[]?')

# --- the audit buckets -------------------------------------------------------------
for b in $(q s3api list-buckets --query 'Buckets[].Name' --output text); do
  [[ "$b" == *-witness-* || "$b" == *-export-* ]] || continue
  expired bucket "$b" "$(aws s3api get-bucket-tagging --bucket "$b" --query TagSet --output json 2>/dev/null || echo '[]')" || continue
  if [[ "$dry" == 1 ]]; then
    echo "would empty (governance bypass) and remove bucket $b"
    continue
  fi
  bregion="$(aws s3api get-bucket-location --bucket "$b" --query LocationConstraint --output text 2>/dev/null || echo "$region")"
  [[ -z "$bregion" || "$bregion" == None ]] && bregion=us-east-1
  if empty_versioned_bucket "$b" aws --region "$bregion"; then
    act "bucket $b" aws --region "$bregion" s3api delete-bucket --bucket "$b"
  else
    echo "could not empty bucket $b; a later reap tries again" >&2
  fi
done

# --- spent teardown and scale-cap schedules ------------------------------------------
for s in $(q scheduler list-schedules --query 'Schedules[].Name' --output text); do
  [[ "$s" =~ ^([a-z][a-z0-9-]*)-(scale-cap|teardown-(compute|cluster|cluster-2))$ ]] || continue
  owner="${BASH_REMATCH[1]}"
  info="$(q scheduler get-schedule --name "$s" --query '{at: ScheduleExpression, target: Target.Arn}' --output json)"
  # The name alone could be another project's: its target must be this
  # harness's teardown Lambda for that run, <run>-teardown.
  if ! [[ "$(jq -r '.target // ""' <<<"${info:-null}" 2>/dev/null || true)" =~ ^arn:aws:lambda:[a-z0-9-]+:[0-9]{12}:function:${owner}-teardown$ ]]; then
    echo "keep schedule $s: its target is not the teardown Lambda $owner-teardown"
    continue
  fi
  at="$(jq -r '.at // ""' <<<"$info" | sed -n 's/^at(\(.*\))$/\1/p')"
  if [[ -z "$at" ]] || ! exp="$(epoch_of "${at}Z" 2>/dev/null)"; then
    echo "keep schedule $s: no at() time that parses"
    continue
  fi
  # Not yet fired, or within the hour after: it is a run's live timer.
  if (( exp + 3600 > now )); then
    echo "keep schedule $s: fires $at UTC"
    continue
  fi
  act "spent schedule $s (fired $at UTC)" aws --region "$region" scheduler delete-schedule --name "$s"
done

# --- VPCs, once no cluster uses them ----------------------------------------------
while read -r item; do
  [[ -n "$item" ]] || continue
  # An answer of another shape is skipped, never a reason to stop.
  vpc="$(jq -r '.id? // empty' <<<"$item" 2>/dev/null || true)"
  [[ -n "$vpc" ]] || continue
  expired VPC "$vpc" "$(jq -c '.tags? // []' <<<"$item" 2>/dev/null || echo '[]')" || continue
  if awk -v v="$vpc" '$2 == v {f=1} END {exit !f}' "$clusters_left"; then
    echo "keep VPC $vpc until the cluster in it is deleted; a later reap removes it"
    continue
  fi
  reap_vpc "$vpc"
done < <(q ec2 describe-vpcs --filters Name=tag:aerol:purpose,Values=k8s-phase0 --query 'Vpcs[].{id: VpcId, tags: Tags}' --output json | jq -c '.[]?')

#!/usr/bin/env bash
# leak-check.sh: lists what is left of an M1 drill run in AWS. Read-only:
# describe, list and get calls only; it deletes nothing.
#
#   leak-check.sh <run name> [vm name]     # exit 1 if anything is left
#   DRY_RUN=1 leak-check.sh <run name>     # print the calls, make none
#
# <run name> is m1-eks.sh's (the EKS part); [vm name] is vm-n1.sh's
# (default <run name>-vm). Besides the run's own tags (aerol:run), it looks
# by the names and tags Kubernetes and EKS put on what they make, because
# those carry no aerol:* tag: the VPC CNI's network interfaces, the EBS CSI
# driver's volumes (24 such volumes were found by hand on 2026-11-19), EKS's
# cluster security group and its log group. To delete what it finds:
# integration-tests/k8s/cluster.sh down <name> again, then
# integration-tests/k8s/reap.sh once the TTL has passed (DRY_RUN=1 first);
# a VM left running: aws ec2 terminate-instances, or `make integration-reap`
# after its 3 h ttl tag.
set -uo pipefail
name="${1:?usage: leak-check.sh <run name> [vm name]}"
vm="${2:-$name-vm}"
region=us-east-1
case "${DRY_RUN:-0}" in 0|1) dry="${DRY_RUN:-0}" ;; *) echo "DRY_RUN must be 0 or 1" >&2; exit 2 ;; esac
[[ "$name" =~ ^[a-z][a-z0-9-]{2,30}$ ]] || { echo "leak-check: bad run name" >&2; exit 2; }

left=0
check() { # check <what> <shell>
  local got
  if [[ "$dry" == 1 ]]; then echo "dry-run: $1: $2"; return 0; fi
  if got="$(bash -c "$2" 2>&1)"; then
    got="$(tr -s '\t\n ' ' ' <<<"$got" | sed -e 's/^ //' -e 's/ $//' -e 's/^None$//')"
  else
    got="could not list: ${got:0:160}"
  fi
  echo "$1: ${got:-none}"
  [[ -z "$got" ]] || left=1
}
r="--region $region"
acct="$( [[ "$dry" == 1 ]] && echo 111122223333 || aws sts get-caller-identity --query Account --output text 2>/dev/null)"

check "EKS cluster" "aws eks list-clusters $r --query \"clusters[?@ == '$name']\" --output text"
check "instances (run, cluster, VM)" "aws ec2 describe-instances $r --filters Name=instance-state-name,Values=pending,running,stopping,stopped --query \"Reservations[].Instances[?Tags[?(Key=='aerol:run' && (Value=='$name' || Value=='$vm')) || (Key=='eks:cluster-name' && Value=='$name') || (Key=='Name' && Value=='$vm')]].InstanceId\" --output text"
check "volumes (run tag)" "aws ec2 describe-volumes $r --filters Name=tag:aerol:run,Values=$name,$vm --query 'Volumes[].VolumeId' --output text"
check "volumes (Kubernetes cluster tag)" "aws ec2 describe-volumes $r --filters Name=tag-key,Values=kubernetes.io/cluster/$name --query 'Volumes[].VolumeId' --output text"
check "network interfaces (VPC CNI)" "aws ec2 describe-network-interfaces $r --filters Name=tag:cluster.k8s.amazonaws.com/name,Values=$name --query 'NetworkInterfaces[].NetworkInterfaceId' --output text"
check "security groups" "aws ec2 describe-security-groups $r --filters Name=tag:aws:eks:cluster-name,Values=$name --query 'SecurityGroups[].GroupId' --output text; aws ec2 describe-security-groups $r --filters Name=tag:aerol:run,Values=$name,$vm --query 'SecurityGroups[].GroupId' --output text"
check "VPC" "aws ec2 describe-vpcs $r --filters Name=tag:aerol:run,Values=$name --query 'Vpcs[].VpcId' --output text"
check "load balancers" "for a in \$(aws elbv2 describe-load-balancers $r --query 'LoadBalancers[].LoadBalancerArn' --output text); do aws elbv2 describe-tags $r --resource-arns \$a --query \"TagDescriptions[?Tags[?(Key=='elbv2.k8s.aws/cluster' || Key=='aerol:run') && Value=='$name']].ResourceArn\" --output text; done"
check "ECR repositories" "aws ecr describe-repositories $r --query \"repositories[?starts_with(repositoryName, '$name/')].repositoryName\" --output text"
check "IAM roles" "aws iam list-roles --query \"Roles[?starts_with(RoleName, '$name-')].RoleName\" --output text"
check "OIDC providers" "aws iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn' --output text | tr '\t' '\n' | while read -r p; do [ -n \"\$p\" ] && aws iam list-open-id-connect-provider-tags --open-id-connect-provider-arn \"\$p\" --query \"Tags[?Key=='aerol:run' && Value=='$name'].Value\" --output text | grep -q . && echo \"\$p\"; done; true"
check "teardown Lambda" "aws lambda list-functions $r --query \"Functions[?FunctionName == '$name-teardown'].FunctionName\" --output text"
check "schedules" "aws scheduler list-schedules $r --name-prefix $name- --query 'Schedules[].Name' --output text"
check "log groups" "aws logs describe-log-groups $r --log-group-name-prefix /aws/eks/$name/ --query 'logGroups[].logGroupName' --output text; aws logs describe-log-groups $r --log-group-name-prefix /aws/lambda/$name- --query 'logGroups[].logGroupName' --output text"
# The source copies the run put in the artifact bucket (12 MB each) are
# kept on purpose, like every run's builds/: listed, not counted.
if [[ "$dry" == 1 ]]; then echo "dry-run: artifact bucket objects under k8s-m1/ and m1-vm/ (listed, not counted)"
else echo "artifact bucket (kept, not counted): $(aws s3 ls "s3://aerol-itest-artifacts-$acct/k8s-m1/" 2>/dev/null | wc -l | tr -d ' ') under k8s-m1/, $(aws s3 ls "s3://aerol-itest-artifacts-$acct/m1-vm/" --recursive 2>/dev/null | wc -l | tr -d ' ') under m1-vm/"; fi
if [[ "$left" == 0 ]]; then echo "leak-check: nothing of $name or $vm is left"; else echo "leak-check: something of $name or $vm is left (above)"; fi
exit "$left"

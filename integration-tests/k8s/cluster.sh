#!/usr/bin/env bash
# cluster.sh: bring a throwaway Phase 0 EKS cluster up or down
# (plans/kubernetes-v2-phase0.md, step H0).
#
#   cluster.sh up   <name> [--ttl 3h] [--ami AL2023_x86_64_STANDARD|BOTTLEROCKET_x86_64]
#                          [--type m7i.xlarge] [--workers 1] [--version 1.36]
#                          [--release 1.36.5-20261031] [--karpenter]
#                          [--zones 2] [--system 1] [--system-type t3.medium]
#                          [--imds-hop-limit 1] [--ebs-csi] [--ecr aerolvm,aerolvm-runtime]
#                          [--network-policy]
#   cluster.sh down <name>
#   cluster.sh kubeconfig <name>      # prints the kubeconfig path
#   cluster.sh allow-ip <name>        # let this machine's current address in
#
# Each run keeps its Terraform state in .state/<name>/ (git-ignored), so two
# runs never share state, and `down` removes exactly what `up` made. `up`
# tags everything with an aerol:ttl, and reap.sh deletes clusters past it if
# a run dies before `down`.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$HERE/terraform"
KARPENTER_VERSION=1.15.1

die() { echo "cluster.sh: $*" >&2; exit 1; }

usage() { sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }

# ttl_from_now turns "3h" or "90m" into an RFC 3339 UTC time. macOS date and
# GNU date spell the offset differently.
ttl_from_now() {
  local d="$1" n unit
  n="${d%[hm]}"; unit="${d: -1}"
  [[ "$n" =~ ^[0-9]+$ && ( "$unit" == h || "$unit" == m ) ]] || die "--ttl wants a number and h or m, got $d"
  if date -u -v+1H >/dev/null 2>&1; then
    [[ "$unit" == h ]] && date -u -v+"${n}"H +%Y-%m-%dT%H:%M:%SZ || date -u -v+"${n}"M +%Y-%m-%dT%H:%M:%SZ
  else
    [[ "$unit" == h ]] && date -u -d "+${n} hours" +%Y-%m-%dT%H:%M:%SZ || date -u -d "+${n} minutes" +%Y-%m-%dT%H:%M:%SZ
  fi
}

state_dir() { echo "$HERE/.state/$1"; }

tf() {
  local name="$1"; shift
  local sd; sd="$(state_dir "$name")"
  mkdir -p "$sd"
  # TF_DATA_DIR per run, so providers and the plan cache never cross runs.
  TF_DATA_DIR="$sd/.terraform" terraform -chdir="$TF_DIR" "$@"
}

cmd_up() {
  local name="${1:-}"; [[ -n "$name" ]] || usage; shift
  local ttl="3h" ami="AL2023_x86_64_STANDARD" type="m7i.xlarge" workers=1 version="1.36"
  local release="" karpenter=false
  # The Phase 2 cell (cell.sh); the defaults are the spikes' shape.
  local zones=2 system=1 system_type="t3.medium" hop=0 ebs=false ecr="" netpol=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      # The worker node group's AMI release; S5 starts one behind to upgrade.
      --release) release="$2"; shift 2 ;;
      # Spike S5: Karpenter's IAM in Terraform, and its chart once up.
      --karpenter) karpenter=true; shift ;;
      --ttl) ttl="$2"; shift 2 ;;
      --ami) ami="$2"; shift 2 ;;
      --type) type="$2"; shift 2 ;;
      --workers) workers="$2"; shift 2 ;;
      --version) version="$2"; shift 2 ;;
      --zones) zones="$2"; shift 2 ;;
      --system) system="$2"; shift 2 ;;
      --system-type) system_type="$2"; shift 2 ;;
      --imds-hop-limit) hop="$2"; shift 2 ;;
      --ebs-csi) ebs=true; shift ;;
      --ecr) ecr="$2"; shift 2 ;;
      --network-policy) netpol=true; shift ;;
      *) die "unknown flag $1" ;;
    esac
  done
  [[ "$name" =~ ^[a-z][a-z0-9-]{2,30}$ ]] || die "name must be 3-31 chars of a-z, 0-9 and -"
  local ip; ip="$(curl -fsS --max-time 10 https://checkip.amazonaws.com | tr -d '[:space:]')"
  [[ "$ip" =~ ^[0-9.]+$ ]] || die "could not learn this machine's public address"
  local sd; sd="$(state_dir "$name")"
  mkdir -p "$sd"
  # The run's inputs are saved, so `down` destroys with the same values `up`
  # applied (the zone list, for one, depends on the worker type).
  jq -n --arg name "$name" --arg ttl "$(ttl_from_now "$ttl")" --arg ami "$ami" \
    --arg type "$type" --argjson workers "$workers" --arg version "$version" --arg cidr "${ip}/32" \
    --arg release "$release" --argjson karpenter "$karpenter" \
    --argjson zones "$zones" --argjson system "$system" --arg system_type "$system_type" \
    --argjson hop "$hop" --argjson ebs "$ebs" --arg ecr "$ecr" --argjson netpol "$netpol" \
    '{name: $name, ttl: $ttl, worker_ami_type: $ami, worker_instance_type: $type,
      worker_count: $workers, kubernetes_version: $version, api_allowed_cidrs: [$cidr],
      worker_release_version: $release, karpenter: $karpenter,
      zone_count: $zones, system_count: $system, system_instance_type: $system_type,
      worker_imds_hop_limit: $hop, ebs_csi: $ebs, network_policy: $netpol,
      ecr_repos: ($ecr | split(",") | map(select(length > 0)))}' \
    > "$sd/run.tfvars.json"
  tf "$name" init -input=false -backend=false >/dev/null
  tf "$name" apply -input=false -auto-approve -state="$sd/terraform.tfstate" -var-file="$sd/run.tfvars.json"
  local region; region="$(tf "$name" output -state="$sd/terraform.tfstate" -raw region)"
  aws eks update-kubeconfig --name "$name" --region "$region" --kubeconfig "$sd/kubeconfig" >/dev/null
  if [[ "$karpenter" == true ]]; then
    # Karpenter's chart is only on an OCI registry, which Helm reads from
    # 3.8 on (the first S5 run stopped here on 3.6). HELM picks the binary.
    local helm="${HELM:-helm}" hv
    hv="$("$helm" version --short 2>/dev/null | sed -E 's/^v([0-9]+)\.([0-9]+).*/\1 \2/')"
    read -r hmaj hmin <<<"${hv:-0 0}"
    (( hmaj > 3 || (hmaj == 3 && hmin >= 8) )) || die "Karpenter's chart needs Helm 3.8 or newer; $helm is ${hv:-missing} (set HELM=)"
    # One replica: the chart's two want two machines, and the only machine
    # without the worker taint is the one system node.
    KUBECONFIG="$sd/kubeconfig" "$helm" upgrade --install karpenter oci://public.ecr.aws/karpenter/karpenter \
      --version "$KARPENTER_VERSION" --namespace kube-system \
      --set settings.clusterName="$name" --set replicas=1 --wait >/dev/null
    echo "up: Karpenter $KARPENTER_VERSION installed"
  fi
  date -u +%Y-%m-%dT%H:%M:%SZ > "$sd/started-at"
  echo "up: $name; kubeconfig $sd/kubeconfig"
}

# remove_leftovers deletes what the cluster's own add-ons made outside
# Terraform and can leave behind: network interfaces the VPC CNI made for a
# node ("aws-K8S-<instance>", tagged with the cluster's name), left
# "available" when the node is terminated, and EKS's own cluster security
# group, which EKS keeps while such an interface uses it. Either one holds
# its subnet or VPC, and destroy waits 20 minutes and fails (N1's teardown).
remove_leftovers() {
  local name="$1" region="$2" id
  for id in $(aws ec2 describe-network-interfaces --region "$region" \
      --filters "Name=tag:cluster.k8s.amazonaws.com/name,Values=$name" Name=status,Values=available \
      --query 'NetworkInterfaces[].NetworkInterfaceId' --output text); do
    aws ec2 delete-network-interface --region "$region" --network-interface-id "$id" &&
      echo "down: removed a network interface the VPC CNI left behind: $id"
  done
  [[ "${3:-}" == with-cluster-sg ]] || return 0
  for id in $(aws ec2 describe-security-groups --region "$region" \
      --filters "Name=tag:aws:eks:cluster-name,Values=$name" --query 'SecurityGroups[].GroupId' --output text); do
    aws ec2 delete-security-group --region "$region" --group-id "$id" >/dev/null &&
      echo "down: removed EKS's cluster security group $id"
  done
}

cmd_down() {
  local name="${1:-}"; [[ -n "$name" ]] || usage
  local sd; sd="$(state_dir "$name")"
  [[ -f "$sd/terraform.tfstate" ]] || die "no state for $name in $sd"
  local state=(-input=false -auto-approve -state="$sd/terraform.tfstate" -var-file="$sd/run.tfvars.json")
  local region; region="$(tf "$name" output -state="$sd/terraform.tfstate" -raw region 2>/dev/null || echo "${AWS_REGION:-us-east-1}")"
  tf "$name" init -input=false -backend=false >/dev/null
  if jq -e '.karpenter == true' "$sd/run.tfvars.json" >/dev/null 2>&1; then
    # Karpenter's machines and instance profiles are not in Terraform's
    # state: have Karpenter remove them (deleting its NodePools ends their
    # machines; deleting the EC2NodeClasses ends the profiles, which would
    # otherwise keep the node role from being deleted), then end any machine
    # it left.
    KUBECONFIG="$sd/kubeconfig" kubectl delete nodepools.karpenter.sh --all --timeout=10m >/dev/null 2>&1 || true
    KUBECONFIG="$sd/kubeconfig" kubectl delete ec2nodeclasses.karpenter.k8s.aws --all --timeout=5m >/dev/null 2>&1 || true
    local left; left="$(aws ec2 describe-instances --region "$region" \
      --filters "Name=tag:kubernetes.io/cluster/$name,Values=owned" "Name=tag-key,Values=karpenter.sh/nodepool" \
        Name=instance-state-name,Values=pending,running,stopping,stopped \
      --query 'Reservations[].Instances[].InstanceId' --output text)"
    if [[ -n "$left" ]]; then
      echo "down: ending machines Karpenter left: $left"
      # shellcheck disable=SC2086
      aws ec2 terminate-instances --region "$region" --instance-ids $left >/dev/null
      # shellcheck disable=SC2086
      aws ec2 wait instance-terminated --region "$region" --instance-ids $left
    fi
  fi
  # Machines first, then what they left, then the rest.
  tf "$name" destroy "${state[@]}" -target=aws_eks_node_group.worker -target=aws_eks_node_group.system
  remove_leftovers "$name" "$region"
  if ! tf "$name" destroy "${state[@]}"; then
    echo "down: destroy failed; removing leftovers and trying once more" >&2
    remove_leftovers "$name" "$region" with-cluster-sg
    tf "$name" destroy "${state[@]}"
  fi
  if [[ -f "$sd/started-at" ]]; then
    echo "down: $name; ran from $(cat "$sd/started-at") to $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi
}

cmd_kubeconfig() {
  local name="${1:-}"; [[ -n "$name" ]] || usage
  local f; f="$(state_dir "$name")/kubeconfig"
  [[ -f "$f" ]] || die "no kubeconfig for $name"
  echo "$f"
}

# cmd_allow_ip adds this machine's current public address to the cluster
# API's allow list. `up` allows only the address it ran from, and a home
# connection's address can change mid-run (it did during S3's sixth run, and
# every kubectl call then timed out). The saved inputs get it too, so `down`
# does not try to take it away.
cmd_allow_ip() {
  local name="${1:-}"; [[ -n "$name" ]] || usage
  local sd; sd="$(state_dir "$name")"
  [[ -f "$sd/run.tfvars.json" ]] || die "no saved inputs for $name"
  local ip; ip="$(curl -fsS --max-time 10 https://checkip.amazonaws.com | tr -d '[:space:]')"
  [[ "$ip" =~ ^[0-9.]+$ ]] || die "could not learn this machine's public address"
  if jq -e --arg c "${ip}/32" '.api_allowed_cidrs | index($c)' "$sd/run.tfvars.json" >/dev/null; then
    echo "allow-ip: ${ip}/32 is already allowed"; return 0
  fi
  local cidrs; cidrs="$(jq -r --arg c "${ip}/32" '(.api_allowed_cidrs + [$c]) | join(",")' "$sd/run.tfvars.json")"
  local id; id="$(aws eks update-cluster-config --name "$name" \
    --resources-vpc-config "publicAccessCidrs=$cidrs" --query update.id --output text)"
  while [[ "$(aws eks describe-update --name "$name" --update-id "$id" --query update.status --output text)" == InProgress ]]; do
    sleep 15
  done
  jq --arg c "${ip}/32" '.api_allowed_cidrs += [$c]' "$sd/run.tfvars.json" > "$sd/run.tfvars.json.new"
  mv "$sd/run.tfvars.json.new" "$sd/run.tfvars.json"
  echo "allow-ip: $name now allows $cidrs"
}

case "${1:-}" in
  up) shift; cmd_up "$@" ;;
  allow-ip) shift; cmd_allow_ip "$@" ;;
  down) shift; cmd_down "$@" ;;
  kubeconfig) shift; cmd_kubeconfig "$@" ;;
  *) usage ;;
esac

#!/usr/bin/env bash
# cluster.sh: bring a throwaway Phase 0 EKS cluster up or down
# (plans/kubernetes-v2-phase0.md, step H0).
#
#   cluster.sh up   <name> [--ttl 3h] [--ami AL2023_x86_64_STANDARD|BOTTLEROCKET_x86_64]
#                          [--type m7i.xlarge] [--workers 1] [--version 1.36]
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

die() { echo "cluster.sh: $*" >&2; exit 1; }

usage() { sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }

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
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ttl) ttl="$2"; shift 2 ;;
      --ami) ami="$2"; shift 2 ;;
      --type) type="$2"; shift 2 ;;
      --workers) workers="$2"; shift 2 ;;
      --version) version="$2"; shift 2 ;;
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
    '{name: $name, ttl: $ttl, worker_ami_type: $ami, worker_instance_type: $type,
      worker_count: $workers, kubernetes_version: $version, api_allowed_cidrs: [$cidr]}' \
    > "$sd/run.tfvars.json"
  tf "$name" init -input=false -backend=false >/dev/null
  tf "$name" apply -input=false -auto-approve -state="$sd/terraform.tfstate" -var-file="$sd/run.tfvars.json"
  local region; region="$(tf "$name" output -state="$sd/terraform.tfstate" -raw region)"
  aws eks update-kubeconfig --name "$name" --region "$region" --kubeconfig "$sd/kubeconfig" >/dev/null
  date -u +%Y-%m-%dT%H:%M:%SZ > "$sd/started-at"
  echo "up: $name; kubeconfig $sd/kubeconfig"
}

cmd_down() {
  local name="${1:-}"; [[ -n "$name" ]] || usage
  local sd; sd="$(state_dir "$name")"
  [[ -f "$sd/terraform.tfstate" ]] || die "no state for $name in $sd"
  tf "$name" init -input=false -backend=false >/dev/null
  tf "$name" destroy -input=false -auto-approve -state="$sd/terraform.tfstate" -var-file="$sd/run.tfvars.json"
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

#!/usr/bin/env bash
# run.sh — orchestrate one integration scenario end to end:
#   provision (isolated TF state) -> wait ready -> run suite -> report -> teardown
#
# Usage:
#   integration-tests/run.sh <scenario> [--keep] [--prod-tls] [--metal-on-demand]
#   integration-tests/run.sh all       [flags]
#
# Scenarios: single-node | local-mode | cluster-3-mixed | cluster-hetero
#
# Safety: every dangerous input is gated by provision.sh check-safety BEFORE any
# apply. Teardown runs on EXIT/INT/TERM (trap) so a crash can't leak EC2; the
# standalone scripts/integration-reap.sh is the second net.
#
# Prereqs: terraform, yq, jq, go, awscli, curl, openssl. Real AWS creds + a
# populated integration-tests/scenarios/domains.yml + config/secrets.yml.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/.." && pwd)"
# shellcheck source=lib/common.sh
source "${HERE}/lib/common.sh"
PROVISION="${HERE}/lib/provision.sh"

KEEP=0
PROD_TLS=0
METAL_ON_DEMAND=0
SCENARIO=""

for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --prod-tls) PROD_TLS=1 ;;
    --metal-on-demand) METAL_ON_DEMAND=1 ;;
    -*) echo "unknown flag: $arg" >&2; exit 2 ;;
    *) SCENARIO="$arg" ;;
  esac
done
[[ -n "$SCENARIO" ]] || { echo "usage: run.sh <scenario|all> [--keep] [--prod-tls] [--metal-on-demand]" >&2; exit 2; }

DOMAINS_FILE="${HERE}/scenarios/domains.yml"
CONFIG_CLUSTER="${REPO_ROOT}/config/cluster.yml"

# AWS access config (profile, region, ssh_key_name, etc.) is reused from the
# operator's existing config/terraform.tfvars — chained FIRST so the scenario
# var-file (chained second) overrides only topology/identity/tags/cert-storage.
# Terraform applies multiple -var-file in order, last value wins per variable.
PROD_TFVARS="${REPO_ROOT}/config/terraform.tfvars"

# tf_varfile_args echoes the ordered -var-file flags shared by apply + destroy.
tf_varfile_args() {
  local scenario="$1"
  printf -- '-var-file=%s -var-file=%s' "$PROD_TFVARS" "${HERE}/scenarios/${scenario}.tfvars"
}

teardown() {
  local scenario="$1"
  if [[ "$KEEP" == "1" ]]; then
    echo "--keep set: leaving ${scenario} infra up. Reap later with: make integration-reap"
    return
  fi
  echo "teardown: destroying ${scenario}"
  # shellcheck disable=SC2046
  TF_DATA_DIR="${REPO_ROOT}/integration-tests/.tf/${scenario}" \
    terraform -chdir="${REPO_ROOT}/Terraform" destroy -auto-approve -input=false \
    $(tf_varfile_args "$scenario") \
    -var="config_dir=${REPO_ROOT}/integration-tests/.tf/${scenario}/config" || \
    echo "teardown: destroy returned non-zero for ${scenario} — run 'make integration-reap'" >&2
}

# lease_domain picks a test domain for the scenario (round-robin by index in the
# pool). Phase 0: index 0. Later phases rotate via a persisted lease file.
lease_domain() {
  yq -r '.itest.domains[0]' "$DOMAINS_FILE"
}

run_one() {
  local scenario="$1"
  local sdir="${REPO_ROOT}/integration-tests/.tf/${scenario}"
  local overlay="${sdir}/config"
  mkdir -p "$overlay"

  local prod_domain leased cluster_name state_key
  prod_domain=$(yq -r '.ingress.domain_name' "$CONFIG_CLUSTER")
  cluster_name="aerolvm-itest-${scenario}"
  state_key="integration/${scenario}/terraform.tfstate"

  local caps_domain
  caps_domain=$(grep -q 'domain' "${HERE}/scenarios/${scenario}.caps.yml" && echo 1 || echo 0)
  if [[ "$caps_domain" == "1" ]]; then
    leased=$(lease_domain)
  else
    leased="" # local-mode: no domain
  fi

  # SAFETY GATE — before any apply.
  bash "$PROVISION" check-safety "$state_key" "${leased:-none.itest.invalid}" "$prod_domain" "$cluster_name"

  # Config overlay: start from prod config, neutralize prod-only side effects,
  # set the leased domain. Secrets are symlinked (never copied).
  local acme_issuer="https://acme-staging-v02.api.letsencrypt.org/directory"
  [[ "$PROD_TLS" == "1" ]] && acme_issuer="" # empty -> Caddy default (prod LE)
  yq '.auto_import.enabled = false
      | .mirror.host = ""
      | .fleet_control_plane.enabled = false
      | (.ingress.acme_ca // "") = "'"$acme_issuer"'"
      | (.ingress.domain_name) = "'"${leased:-localhost}"'"' \
    "$CONFIG_CLUSTER" > "${overlay}/cluster.yml"
  ln -sf "${REPO_ROOT}/config/secrets.yml" "${overlay}/secrets.yml"

  trap "teardown '${scenario}'" EXIT INT TERM

  echo "=== provisioning ${scenario} (domain=${leased:-none}) ==="
  TF_DATA_DIR="$sdir" terraform -chdir="${REPO_ROOT}/Terraform" init -reconfigure -input=false \
    -backend-config="key=${state_key}"
  # shellcheck disable=SC2046
  TF_DATA_DIR="$sdir" terraform -chdir="${REPO_ROOT}/Terraform" apply -auto-approve -input=false \
    $(tf_varfile_args "$scenario") \
    -var="config_dir=${overlay}"

  # Discover endpoint.
  local targets base_url pat
  targets=$(TF_DATA_DIR="$sdir" terraform -chdir="${REPO_ROOT}/Terraform" output -json integration_targets)
  pat=$(yq -r '.cluster.pat_token' "${REPO_ROOT}/config/secrets.yml")

  local inconclusive=0
  if [[ "$caps_domain" == "1" ]]; then
    base_url=$(echo "$targets" | jq -r '.base_url')
    wait_for_dns "$leased" || inconclusive=1
    wait_for_tls "$leased" || inconclusive=1
    wait_for_health "$base_url" "$pat" || inconclusive=1
  else
    # local-mode: SSH tunnel to the seed, talk to localhost:21212.
    local seed_ip
    seed_ip=$(echo "$targets" | jq -r '.seed_ip')
    ssh -fN -o StrictHostKeyChecking=no -L 21212:localhost:21212 "ubuntu@${seed_ip}"
    base_url="http://localhost:21212"
    wait_for_health "$base_url" "$pat" || inconclusive=1
  fi

  mkdir -p "${HERE}/reports"
  local json_out="${sdir}/test.json"
  if [[ "$inconclusive" == "1" ]]; then
    echo "scenario ${scenario}: infra not ready (spot reclaim / propagation) — marking inconclusive" >&2
    : > "$json_out"
    AEROL_SCENARIO="$scenario" go run "${HERE}/report" -scenario "$scenario" -inconclusive \
      -json "$json_out" -out "${HERE}/reports"
    return 0
  fi

  echo "=== running suite against ${base_url} ==="
  set +e
  AEROL_BASE_URL="$base_url" AEROL_PAT="$pat" AEROL_SCENARIO="$scenario" \
    AEROL_CAPS="${HERE}/scenarios/${scenario}.caps.yml" \
    go test -tags=integration -json ./integration-tests/suite/... > "$json_out"
  set -e

  AEROL_SCENARIO="$scenario" go run "${HERE}/report" -scenario "$scenario" \
    -json "$json_out" -out "${HERE}/reports"
}

if [[ "$SCENARIO" == "all" ]]; then
  for s in single-node cluster-3-mixed cluster-hetero; do
    ( run_one "$s" )
  done
else
  run_one "$SCENARIO"
fi

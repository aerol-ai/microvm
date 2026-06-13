#!/usr/bin/env bash
# provision.sh — scenario provisioning + the prod-safety tripwires.
#
# The integration harness reuses the PRODUCTION Terraform module but MUST never
# touch prod state, prod DNS records, or prod resource names. Every dangerous
# input passes through check_safety() first. That function is pure (args in,
# exit code out, no AWS) so it can be unit-tested offline — see
# integration-tests/safety/tripwire_test.go.
#
# Subcommands:
#   provision.sh check-safety <state_key> <leased_domain> <prod_domain> <cluster_name>
#       Run ONLY the tripwires. Exit 0 if safe, non-zero (with reason) if not.
#   provision.sh apply  <scenario>
#   provision.sh destroy <scenario>
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TF_DIR="${REPO_ROOT}/Terraform"
STATE_BUCKET_PREFIX="integration/" # all integration state lives under this key prefix

# check_safety enforces the three tripwires. Returns non-zero with a message on
# stderr the moment any check fails. Kept argument-driven and side-effect-free
# for offline testing.
check_safety() {
  local state_key="$1" leased_domain="$2" prod_domain="$3" cluster_name="$4"

  # 1. State key MUST live under integration/ and MUST NOT be the prod key.
  case "$state_key" in
    prod/*)
      echo "TRIPWIRE: state key '$state_key' targets PROD state — refusing." >&2
      return 1
      ;;
    "${STATE_BUCKET_PREFIX}"*) : ;; # ok
    *)
      echo "TRIPWIRE: state key '$state_key' is not under '${STATE_BUCKET_PREFIX}' — refusing." >&2
      return 1
      ;;
  esac

  # 2. Leased domain must not equal or be a suffix-match of the prod domain.
  if [[ -n "$prod_domain" ]]; then
    if [[ "$leased_domain" == "$prod_domain" || "$leased_domain" == *".${prod_domain}" ]]; then
      echo "TRIPWIRE: leased domain '$leased_domain' collides with prod domain '$prod_domain' — refusing." >&2
      return 1
    fi
  fi

  # 3. cluster_name must carry the itest marker so resources can't collide with
  #    prod and the reaper can find them.
  if [[ "$cluster_name" != *itest* ]]; then
    echo "TRIPWIRE: cluster_name '$cluster_name' lacks the 'itest' marker — refusing." >&2
    return 1
  fi

  return 0
}

# tf_init points the SAME module at an isolated state key + data dir so prod
# state is never opened. Callers pass a scenario name.
tf_init() {
  local scenario="$1"
  local key="${STATE_BUCKET_PREFIX}${scenario}/terraform.tfstate"
  TF_DATA_DIR="${REPO_ROOT}/integration-tests/.tf/${scenario}" \
    terraform -chdir="$TF_DIR" init -reconfigure -input=false \
    -backend-config="key=${key}"
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    check-safety)
      shift
      [[ $# -eq 4 ]] || { echo "usage: provision.sh check-safety <state_key> <leased_domain> <prod_domain> <cluster_name>" >&2; exit 2; }
      check_safety "$@"
      ;;
    apply | destroy)
      echo "provision.sh $cmd: live AWS path is wired in Phase 0 build-out (not run in unit tests)" >&2
      exit 3
      ;;
    *)
      echo "usage: provision.sh {check-safety|apply|destroy} ..." >&2
      exit 2
      ;;
  esac
}

main "$@"

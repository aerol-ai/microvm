#!/usr/bin/env bash

# terraform.sh — wrapper that runs Terraform with the right -chdir + var-file.
#
# Why this exists: the cluster's Terraform inputs (config/terraform.tfvars)
# live OUTSIDE the Terraform/ module directory so all cluster config + secrets
# sit in one place — alongside config/cluster.yml and config/secrets.yml.
# Terraform only auto-loads terraform.tfvars from its working directory, so
# every plan/apply needs an explicit -var-file. This wrapper injects it so
# operators never have to remember the flag.
#
# Usage (from anywhere inside the repo):
#   scripts/terraform.sh init
#   scripts/terraform.sh plan
#   scripts/terraform.sh apply
#   scripts/terraform.sh destroy
#   scripts/terraform.sh output -json
#   scripts/terraform.sh state list
#
# Pass-through: every argument after the subcommand is forwarded verbatim.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="${REPO_ROOT}/Terraform"
TFVARS="${REPO_ROOT}/config/terraform.tfvars"

if ! command -v terraform >/dev/null 2>&1; then
  echo "error: terraform not found on PATH" >&2
  exit 127
fi

if [[ $# -lt 1 ]]; then
  echo "usage: $(basename "$0") <terraform-subcommand> [args...]" >&2
  echo "       wraps: terraform -chdir=${TF_DIR} <subcommand> [-var-file=${TFVARS}] [args...]" >&2
  exit 2
fi

SUBCOMMAND="$1"
shift

# Subcommands that consume root-module variables. Everything else (init, fmt,
# providers, version, output, state, workspace, ...) ignores -var-file and
# Terraform refuses to accept it for those — so only inject when needed.
needs_varfile=false
case "$SUBCOMMAND" in
  plan|apply|destroy|refresh|import|console|validate|taint|untaint|test)
    needs_varfile=true
    ;;
esac

# `terraform validate` does NOT need credentials/tfvars to typecheck the
# module, and silently tolerates -var-file for parity with plan/apply. We pass
# it through anyway so the same wrapper works for `validate -json` in CI.

extra_args=()
if $needs_varfile; then
  if [[ ! -f "$TFVARS" ]]; then
    cat >&2 <<EOF
error: ${TFVARS} not found.

Bootstrap with:
  cp config/terraform.tfvars.example config/terraform.tfvars
  # then edit it with your AWS placement, node list, etc.

Cluster secrets (cluster.pat_token, cloudflare.api_token, aocr.*, fleet.token)
live in config/secrets.yml — bootstrap from config/secrets.example.yml.
EOF
    exit 1
  fi
  extra_args+=("-var-file=${TFVARS}")
fi

exec terraform -chdir="$TF_DIR" "$SUBCOMMAND" "${extra_args[@]}" "$@"

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
#   provision.sh cert-store-init
#       Idempotently create the PERSISTENT cross-run Caddy cert bucket + ensure
#       config/secrets.yml carries a stable encryption key. Run once per
#       operator/account. Live AWS.
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

# tfvar_scalar greps a top-level `key = "value"` out of a HCL tfvars file
# without a full HCL parse. Only used for the two non-secret AWS coordinates
# (aws_profile / aws_region) the operator already put in terraform.tfvars.
tfvar_scalar() {
  local file="$1" key="$2"
  sed -nE "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*\"([^\"]*)\".*/\1/p" "$file" | head -1
}

# cert_store_init creates (idempotently) the PERSISTENT S3 bucket that holds
# integration-test Caddy certs ACROSS runs, and ensures config/secrets.yml
# carries the matching stable encryption key. Unlike the per-scenario managed
# bucket (created + destroyed with every cluster), this bucket lives outside
# all scenario state — like the TF state backend bucket — so a leased-domain
# wildcard cert issued on one run is READ on the next instead of re-issued
# against Let's Encrypt. The domain pool is finite, so over time each domain
# issues exactly once and is fetched thereafter. Run ONCE per operator/account;
# safe to re-run (never regenerates the key).
cert_store_init() {
  local tfvars="${REPO_ROOT}/config/terraform.tfvars"
  local secrets="${REPO_ROOT}/config/secrets.yml"
  [[ -f "$tfvars" ]] || { echo "cert-store-init: ${tfvars} missing (copy from terraform.tfvars.example)" >&2; return 1; }
  [[ -f "$secrets" ]] || { echo "cert-store-init: ${secrets} missing (copy from secrets.example.yml)" >&2; return 1; }
  for bin in aws yq openssl; do
    command -v "$bin" >/dev/null 2>&1 || { echo "cert-store-init: '$bin' not found on PATH" >&2; return 1; }
  done

  # Reuse the exact profile/region the harness provisions with, so the bucket
  # lands in the same account as the nodes' instance roles (that's what makes
  # BYO + no-static-creds resolve via the default credential chain — see
  # Terraform/iam.tf caddy_certs_attach_iam).
  local profile region
  profile=$(tfvar_scalar "$tfvars" aws_profile)
  region=$(tfvar_scalar "$tfvars" aws_region)
  [[ -n "$region" ]] || { echo "cert-store-init: aws_region not set in ${tfvars}" >&2; return 1; }
  local awscli=(aws)
  [[ -n "$profile" ]] && awscli+=(--profile "$profile")

  local account
  account=$("${awscli[@]}" sts get-caller-identity --query Account --output text 2>/dev/null) \
    || { echo "cert-store-init: could not resolve AWS account (check creds/profile '${profile:-default}')" >&2; return 1; }
  local bucket="aerol-itest-caddy-certs-${account}"
  local prefix="itest-caddy-certs"

  echo "cert-store-init: ensuring s3://${bucket} (region ${region}, profile ${profile:-default})"

  # Idempotent create. head-bucket succeeds iff we already own it.
  if "${awscli[@]}" --region "$region" s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
    echo "  bucket exists"
  else
    # us-east-1 rejects a LocationConstraint; every other region requires it.
    if [[ "$region" == "us-east-1" ]]; then
      "${awscli[@]}" --region "$region" s3api create-bucket --bucket "$bucket" >/dev/null
    else
      "${awscli[@]}" --region "$region" s3api create-bucket --bucket "$bucket" \
        --create-bucket-configuration "LocationConstraint=${region}" >/dev/null
    fi
    echo "  bucket created"
  fi

  # Harden to match the managed cert bucket (Terraform/iam.tf): block all public
  # access, AES256 SSE at rest, and versioning so an accidental delete of a
  # renewed cert stays recoverable.
  "${awscli[@]}" --region "$region" s3api put-public-access-block --bucket "$bucket" \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" >/dev/null
  "${awscli[@]}" --region "$region" s3api put-bucket-encryption --bucket "$bucket" \
    --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' >/dev/null
  "${awscli[@]}" --region "$region" s3api put-bucket-versioning --bucket "$bucket" \
    --versioning-configuration "Status=Enabled" >/dev/null
  echo "  hardened (public-access-block + AES256 + versioning)"

  # Stable encryption key: generate ONCE, then reuse forever. certmagic-s3
  # encrypts the cert+key bytes with it; a new key orphans every stored cert
  # (unreadable → full re-issue), which is exactly the rate-limit cost we're
  # avoiding. So only mint one when the block is empty.
  local key
  key=$(yq -r '.caddy_cert_store.encryption_key // ""' "$secrets")
  if [[ -z "$key" ]]; then
    key=$(openssl rand -base64 32)
    echo "  generated new encryption key"
  else
    echo "  reusing existing encryption key"
  fi

  # Persist bucket coords + key back into secrets.yml. yq -i edits in place and
  # leaves every other top-level key (cluster/aocr/cloudflare/fleet) untouched.
  bucket="$bucket" region="$region" prefix="$prefix" key="$key" \
    yq -i '
      .caddy_cert_store.bucket = strenv(bucket)
      | .caddy_cert_store.region = strenv(region)
      | .caddy_cert_store.prefix = strenv(prefix)
      | .caddy_cert_store.encryption_key = strenv(key)
    ' "$secrets"
  chmod 600 "$secrets"

  echo "cert-store-init: done."
  echo "  bucket:  s3://${bucket}/${prefix}"
  echo "  secrets: config/secrets.yml → caddy_cert_store (encryption_key set)"
  echo "  Every domain-bearing integration scenario now REUSES stored certs"
  echo "  instead of re-issuing. Save the key like any root credential —"
  echo "  losing it orphans the stored certs."
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    check-safety)
      shift
      [[ $# -eq 4 ]] || { echo "usage: provision.sh check-safety <state_key> <leased_domain> <prod_domain> <cluster_name>" >&2; exit 2; }
      check_safety "$@"
      ;;
    cert-store-init)
      cert_store_init
      ;;
    apply | destroy)
      echo "provision.sh $cmd: live AWS path is wired in Phase 0 build-out (not run in unit tests)" >&2
      exit 3
      ;;
    *)
      echo "usage: provision.sh {check-safety|cert-store-init|apply|destroy} ..." >&2
      exit 2
      ;;
  esac
}

main "$@"

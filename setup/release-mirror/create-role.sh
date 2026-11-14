#!/usr/bin/env bash
# One-time setup for the release workflow's `mirror` job
# (.github/workflows/release.yml, RELEASING.md "The download mirror").
#
# Creates (or updates) the IAM role that job assumes through GitHub OIDC: only
# a workflow run of aerol-ai/microvm for a v* tag can assume it (the token
# names the repository and the ref, not the workflow file), and it can only
# write and list under s3://aerolvm-downloads/aerolvm/ (release files) and
# deps/ (the third-party files install.sh pins). No keys are
# stored anywhere. The account id is filled in here so it is not in the repo.
# Needs AWS credentials that can manage IAM, and the GitHub OIDC provider
# (token.actions.githubusercontent.com) already in the account.
#
# Then point the workflow at the role:
#   gh variable set AEROLVM_MIRROR_ROLE_ARN -R aerol-ai/microvm --body <printed arn>
set -euo pipefail

ROLE=aerolvm-release-mirror-publisher
here=$(cd "$(dirname "$0")" && pwd)
account=$(aws sts get-caller-identity --query Account --output text)
provider="arn:aws:iam::${account}:oidc-provider/token.actions.githubusercontent.com"
if ! aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$provider" >/dev/null 2>&1; then
  echo "create-role.sh: no GitHub OIDC provider in account ${account}; add token.actions.githubusercontent.com first" >&2
  exit 1
fi
trust=$(sed "s/ACCOUNT_ID/${account}/" "${here}/trust-policy.json")

if aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  aws iam update-assume-role-policy --role-name "$ROLE" --policy-document "$trust"
  aws iam update-role --role-name "$ROLE" --max-session-duration 3600
else
  aws iam create-role --role-name "$ROLE" \
    --assume-role-policy-document "$trust" \
    --max-session-duration 3600 \
    --description "Release workflow (aerol-ai/microvm, v* tags) copies release files and pinned third-party files to s3://aerolvm-downloads/aerolvm/ and deps/" \
    --tags Key=Purpose,Value=release-download-mirror >/dev/null
fi
aws iam put-role-policy --role-name "$ROLE" --policy-name write-release-files \
  --policy-document "file://${here}/permissions-policy.json"

echo "arn:aws:iam::${account}:role/${ROLE}"

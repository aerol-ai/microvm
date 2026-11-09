#!/usr/bin/env bash
# stage-to-node.sh — copy files from this machine to one or more test nodes
# through S3 (lib/stage.sh), the way to hot-patch a kept scenario's sandboxd
# or hand a node a test binary. Never scp a build to a node: see lib/stage.sh.
#
# Usage:
#   integration-tests/scripts/stage-to-node.sh [--scenario <name>] \
#     <remote-dir> <local-file>... -- <ip-or-user@host>...
#
#   e.g. hot-patch every node of a kept cluster-chaos stack:
#     ips=$(TF_DATA_DIR=integration-tests/.tf/cluster-chaos \
#       terraform -chdir=Terraform/root output -json integration_targets | jq -r '.nodes[].public_ip')
#     integration-tests/scripts/stage-to-node.sh --scenario cluster-chaos /tmp/aerol-stage \
#       integration-tests/.build/<build id>/sandboxd_linux_amd64 -- $ips
#     # then on each node: sudo install -m0755 /tmp/aerol-stage/sandboxd_linux_amd64 /usr/local/bin/sandboxd
#
# --scenario picks the SSH key the way run.sh does (that scenario's tfvars,
# then config/terraform.tfvars); AEROL_SSH_IDENTITY_FILE overrides it. A bare
# IP means ubuntu@<ip>.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/lib/common.sh"

usage() { sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }

SCENARIO=""
[[ "${1:-}" == "--scenario" ]] && { SCENARIO="${2:?--scenario needs a name}"; shift 2; }
[[ $# -ge 3 ]] || usage
DIR="$1"
shift
FILES=()
while [[ $# -gt 0 && "$1" != "--" ]]; do FILES+=("$1"); shift; done
[[ "${1:-}" == "--" ]] || usage
shift
[[ ${#FILES[@]} -gt 0 && $# -gt 0 ]] || usage

scenario_tfvars=""
[[ -n "$SCENARIO" ]] && scenario_tfvars="$HERE/scenarios/${SCENARIO}.tfvars"
resolve_ssh_identity "$scenario_tfvars" "$REPO_ROOT/config/terraform.tfvars"

rc=0
for host in "$@"; do
  [[ "$host" == *@* ]] || host="ubuntu@${host}"
  if stage_to_node "$host" "$DIR" "${FILES[@]}"; then
    echo "staged ${#FILES[@]} file(s) on ${host}:${DIR}" >&2
  else
    echo "staging on ${host} failed" >&2
    rc=1
  fi
done
exit "$rc"

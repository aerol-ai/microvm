#!/usr/bin/env bash
# run-on-node.sh — run selected live-suite tests from a node INSIDE a kept
# scenario's VPC instead of from this machine.
#
# Usage:
#   integration-tests/scripts/run-on-node.sh <scenario> -run '<regex>' \
#     [--node <name>] [--label <label>] [--timeout <go duration>] \
#     [--keep-remote] [--dry-run] [-- <extra test-binary flags>]
#
# Why: a latency gate measured from a laptop measures the laptop's Wi-Fi and
# ISP as much as the cluster, and a laptop SSH or DNS blip fails a case that
# had nothing to do with the code (integration-tests/README.md, "Routing gate
# from inside the VPC"). Run from a node, the client sits next to the
# cluster on the same public path a customer's servers in the region use.
#
# What it does:
#   1. reads the stack from this worktree's .tf/<scenario> (or an exported
#      AEROL_INTEGRATION_TARGETS) and picks the node: --node, else a
#      server-only node (Raft voter, not on the public data path);
#   2. builds `go test -c -tags integration ./integration-tests/suite/` for
#      the node's OS and architecture;
#   3. copies the binary, the caps file and an env file (the same AEROL_*
#      run.sh hands the suite) to the node with the harness's SSH key, and
#      starts the binary detached, so an SSH drop here does not kill it;
#   4. waits, then copies back the raw output, test.json (go test -json
#      shape), test.log, <scenario>-bank.json, and report/<scenario>-node.md
#      into integration-tests/reports/run-on-node/<scenario>/<stamp>[-<label>]/.
#
# Exit status is the test binary's. --keep-remote leaves the remote
# directory, including its 0600 env file with the suite's 24 h token.
#
# Not for every case: the node has no SSH key, no AWS credentials and no
# repo checkout, so cases that SSH into nodes, call the AWS CLI or read repo
# files skip or fail there. AEROL_ALLOW_DISRUPTIVE is forced to 0 for the
# same reason. Run those from the laptop with run.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${HERE}/.." && pwd)"
# shellcheck source=../lib/common.sh
source "${HERE}/lib/common.sh"
# shellcheck source=../lib/node-run.sh
source "${HERE}/lib/node-run.sh"

usage() {
  sed -n '5,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
}

SCENARIO=""
RUN_REGEX=""
NODE=""
LABEL=""
TIMEOUT="60m"
KEEP_REMOTE=0
DRY_RUN=0
EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -run | --run)
      [[ $# -ge 2 ]] || { echo "$1 needs a regex" >&2; exit 2; }
      RUN_REGEX="$2"
      shift 2
      ;;
    -run=* | --run=*) RUN_REGEX="${1#*=}"; shift ;;
    --node)
      [[ $# -ge 2 ]] || { echo "--node needs a node name" >&2; exit 2; }
      NODE="$2"
      shift 2
      ;;
    --label)
      [[ $# -ge 2 ]] || { echo "--label needs a value" >&2; exit 2; }
      LABEL="$2"
      shift 2
      ;;
    --timeout)
      [[ $# -ge 2 ]] || { echo "--timeout needs a Go duration (e.g. 45m)" >&2; exit 2; }
      TIMEOUT="$2"
      shift 2
      ;;
    --keep-remote) KEEP_REMOTE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h | --help) usage; exit 0 ;;
    --) shift; EXTRA=("$@"); break ;;
    -*) echo "unknown flag: $1 (test-binary flags go after --, e.g. -- -test.v)" >&2; exit 2 ;;
    *)
      [[ -z "$SCENARIO" ]] || { echo "one scenario only (got ${SCENARIO} and $1)" >&2; exit 2; }
      SCENARIO="$1"
      shift
      ;;
  esac
done
[[ -n "$SCENARIO" ]] || { usage; exit 2; }
# A whole-suite run from a node would mostly measure which cases cannot run
# there (no SSH key, no AWS, no checkout), so a selection is required.
[[ -n "$RUN_REGEX" ]] || { echo "-run '<regex>' is required: pick the cases to run from the node" >&2; exit 2; }
if [[ "$SCENARIO" == *[^A-Za-z0-9._-]* ]]; then
  echo "scenario name contains unsafe characters (refusing: ${SCENARIO})" >&2
  exit 2
fi
if [[ -n "$LABEL" && "$LABEL" == *[^A-Za-z0-9._-]* ]]; then
  echo "--label may hold only letters, digits, '.', '_' and '-' (it names a directory)" >&2
  exit 2
fi
if [[ ! "$TIMEOUT" =~ ^[0-9]+(s|m|h)$ ]]; then
  echo "--timeout must be a whole number of s, m or h (got ${TIMEOUT})" >&2
  exit 2
fi
CAPS_FILE="${HERE}/scenarios/${SCENARIO}.caps.yml"
[[ -f "$CAPS_FILE" ]] || { echo "unknown scenario ${SCENARIO}: no ${CAPS_FILE}" >&2; exit 2; }

TARGETS=$(kept_targets "$REPO_ROOT" "$SCENARIO")
BASE_URL=$(jq -r '.base_url // empty' <<<"$TARGETS")
DOMAIN=$(jq -r '.domain // empty' <<<"$TARGETS")
SEED_IP=$(jq -r '.seed_ip // empty' <<<"$TARGETS")
if [[ -z "$BASE_URL" || "$BASE_URL" == http://localhost* ]]; then
  # A local-mode stack answers only on the seed's loopback, through the SSH
  # tunnel run.sh opens; there is no public path to measure from a node.
  echo "scenario ${SCENARIO} has no public base URL (local mode?); run it with run.sh" >&2
  exit 2
fi
row=$(pick_gate_node "$TARGETS" "$NODE")
NODE_NAME="${row%%$'\t'*}"
NODE_IP="${row#*$'\t'}"
TARGET="${AEROL_SSH_USER:-ubuntu}@${NODE_IP}"
EXPECTED_MEMBERS=$(yq -r '.expected_members // ""' "$CAPS_FILE")
PAT_SCOPE_HOST=$(yq -r '.capabilities | contains(["pat-scope-host"])' "$CAPS_FILE")

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${HERE}/reports/run-on-node/${SCENARIO}/${STAMP}${LABEL:+-${LABEL}}"
# -test.v=test2json: the node has no Go toolchain, so the binary writes the
# framed output and `go tool test2json` turns it into go test -json here.
TEST_ARGS=(-test.run "$RUN_REGEX" -test.count=1 -test.timeout "$TIMEOUT" -test.v=test2json ${EXTRA[@]+"${EXTRA[@]}"})
# The env names this script sets itself (ENV_ARGS below); every other
# exported AEROL_* passes through.
SET_NAMES=(AEROL_BASE_URL AEROL_PAT AEROL_OPERATOR_PAT AEROL_SCENARIO AEROL_CAPS AEROL_DOMAIN
  AEROL_EXPECTED_MEMBERS AEROL_INTEGRATION_TARGETS AEROL_ALLOW_DISRUPTIVE AEROL_REPORTS_DIR AEROL_CATALOGUE_OUT)

if [[ "$DRY_RUN" == "1" ]]; then
  # Everything decided, nothing touched: no build, no SSH, no token.
  printf 'node=%s\nnode_ip=%s\nbase_url=%s\nout_dir=%s\n' "$NODE_NAME" "$NODE_IP" "$BASE_URL" "$OUT_DIR"
  printf 'test_args='
  printf '%q ' "${TEST_ARGS[@]}"
  printf '\n'
  printf 'passthrough=%s\n' "$(aerol_passthrough_names "${SET_NAMES[@]}" | tr '\n' ' ')"
  exit 0
fi

resolve_ssh_identity "${HERE}/scenarios/${SCENARIO}.tfvars" "${REPO_ROOT}/config/terraform.tfvars"
PAT=$(yq -r '.cluster.pat_token' "${REPO_ROOT}/config/secrets.yml")
API_TOKEN="$PAT"
if [[ "$PAT_SCOPE_HOST" == "true" ]]; then
  # Through Caddy the PAT is refused under SB_PAT_SCOPE=host, exactly as on
  # a laptop run; run.sh mints the same admin token on the seed.
  API_TOKEN=$(mint_suite_token "${AEROL_SSH_USER:-ubuntu}@${SEED_IP}" "$PAT" "$SCENARIO" 120)
fi

echo "=== ${SCENARIO}: running ${RUN_REGEX} from ${NODE_NAME} (${NODE_IP}) ===" >&2
ARCH=$(ssh "${SSH_OPTS[@]}" "$TARGET" 'uname -m')
GOARCH=$(goarch_for "$ARCH")

WORK=$(mktemp -d -t aerol-run-on-node.XXXXXX)
REMOTE_DIR=""
REMOTE_PID_KNOWN=0
cleanup() {
  local rc=$?
  if [[ -n "$REMOTE_DIR" && "$REMOTE_PID_KNOWN" == "1" && ! -s "${WORK}/finished" ]]; then
    # Interrupted while the binary runs: stop it, or it keeps churning
    # sandboxes on the cluster with nobody collecting the result.
    echo "stopping the remote run in ${REMOTE_DIR}" >&2
    ssh "${SSH_OPTS[@]}" "$TARGET" "kill -- -\$(cat $(printf '%q' "$REMOTE_DIR")/pid) 2>/dev/null || true" || true
  fi
  if [[ -n "$REMOTE_DIR" && "$KEEP_REMOTE" != "1" ]]; then
    ssh "${SSH_OPTS[@]}" "$TARGET" "rm -rf $(printf '%q' "$REMOTE_DIR")" || true
  fi
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "building the suite for linux/${GOARCH}" >&2
(cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" \
  go test -c -tags integration -ldflags='-s -w' -o "${WORK}/suite.test" ./integration-tests/suite/)

REMOTE_DIR=$(ssh "${SSH_OPTS[@]}" "$TARGET" 'mktemp -d /tmp/aerol-suite.XXXXXX')
RDIR_Q=$(printf '%q' "$REMOTE_DIR")

# The env run.sh hands the suite (its go test invocation), pointed at the
# node's own paths. AEROL_ALLOW_DISRUPTIVE is 0: the disruptive cases stop
# and start other nodes over SSH and the AWS CLI, which the node has neither
# key nor credentials for.
ENV_ARGS=(
  AEROL_BASE_URL "$BASE_URL"
  AEROL_PAT "$API_TOKEN"
  AEROL_OPERATOR_PAT "$PAT"
  AEROL_SCENARIO "$SCENARIO"
  AEROL_CAPS "${REMOTE_DIR}/${SCENARIO}.caps.yml"
  AEROL_DOMAIN "$DOMAIN"
  AEROL_EXPECTED_MEMBERS "$EXPECTED_MEMBERS"
  AEROL_INTEGRATION_TARGETS "$(jq -c . <<<"$TARGETS")"
  AEROL_ALLOW_DISRUPTIVE 0
  AEROL_REPORTS_DIR "$REMOTE_DIR"
  AEROL_CATALOGUE_OUT "${REMOTE_DIR}/${SCENARIO}-catalogue.json"
)
while IFS= read -r name; do
  ENV_ARGS+=("$name" "${!name}")
done < <(aerol_passthrough_names "${SET_NAMES[@]}")
write_env_file "${WORK}/suite.env" "${ENV_ARGS[@]}"

{
  echo 'cd "$(dirname "$0")"'
  echo 'echo $$ > pid'
  echo 'set -a; . ./suite.env; set +a'
  printf './suite.test'
  printf ' %q' "${TEST_ARGS[@]}"
  printf ' > suite.out 2>&1\n'
  echo 'echo $? > exit_code'
} >"${WORK}/runner.sh"

echo "copying the suite to ${NODE_NAME}:${REMOTE_DIR}" >&2
# Through S3, not scp: the test binary is tens of MB, and one scp stream
# over this machine's uplink takes minutes (lib/stage.sh).
stage_to_node "$TARGET" "$REMOTE_DIR" "${WORK}/suite.test" "${WORK}/runner.sh" "$CAPS_FILE"
# On stdin, into a 0600 file: the env holds the tokens.
ssh "${SSH_OPTS[@]}" "$TARGET" "umask 077 && cat > ${RDIR_Q}/suite.env" <"${WORK}/suite.env"

# The node checks its own path to the API before the run, so a broken
# cluster reads as that and not as a wall of failed cases.
code=$(printf 'Authorization: Bearer %s\n' "$API_TOKEN" | ssh "${SSH_OPTS[@]}" "$TARGET" \
  "curl -sS -o /dev/null -m 20 -w '%{http_code}' -H @- $(printf '%q' "${BASE_URL}/v1/capacity")" 2>/dev/null) || code=000
if [[ "$code" != "200" ]]; then
  echo "${NODE_NAME} cannot reach ${BASE_URL}/v1/capacity (HTTP ${code}); is the stack healthy?" >&2
  exit 2
fi

# Detached (setsid + nohup), so the run outlives an SSH drop from this
# machine; this script then only polls for the exit code.
ssh "${SSH_OPTS[@]}" "$TARGET" "cd ${RDIR_Q} && chmod +x suite.test && (setsid nohup bash ./runner.sh </dev/null >/dev/null 2>&1 &)"
REMOTE_PID_KNOWN=1
echo "started; waiting (timeout ${TIMEOUT})" >&2

case "${TIMEOUT: -1}" in
  s) unit=1 ;;
  m) unit=60 ;;
  *) unit=3600 ;;
esac
timeout_s=$(( ${TIMEOUT%?} * unit ))
# The binary enforces -test.timeout itself; the slack covers its cleanup.
deadline=$(( $(date +%s) + timeout_s + 600 ))
started=$(date +%s)
rc=""
while (( $(date +%s) < deadline )); do
  sleep 15
  # An SSH failure here is this machine's network, not the run's: retry.
  if out=$(ssh "${SSH_OPTS[@]}" "$TARGET" "cat ${RDIR_Q}/exit_code 2>/dev/null || echo running" 2>/dev/null); then
    if [[ "$out" =~ ^[0-9]+$ ]]; then
      rc="$out"
      break
    fi
  fi
  elapsed=$(( $(date +%s) - started ))
  if (( elapsed % 120 < 15 )); then
    echo "  ... ${elapsed}s" >&2
  fi
done
if [[ -z "$rc" ]]; then
  echo "the remote run did not finish before the deadline" >&2
  rc=124
else
  echo finished >"${WORK}/finished"
fi

mkdir -p "$OUT_DIR"
# Everything but the binary and the env file (it holds the tokens).
ssh "${SSH_OPTS[@]}" "$TARGET" "cd ${RDIR_Q} && tar czf - --exclude=suite.test --exclude=suite.env ." | tar xzf - -C "$OUT_DIR" || true
if [[ -s "${OUT_DIR}/suite.out" ]]; then
  go tool test2json -t -p github.com/aerol-ai/microvm/integration-tests/suite <"${OUT_DIR}/suite.out" >"${OUT_DIR}/test.json" || true
  jq -j 'select(.Action == "output") | .Output' "${OUT_DIR}/test.json" >"${OUT_DIR}/test.log" 2>/dev/null || true
  # Under its own name, like run.sh's partial runs: a narrowed run must not
  # pass for the scenario's full report. In report/, because gen rebuilds an
  # index from every *.json in its directory and test.json is JSON lines.
  # gen exits 1 for the use cases this run did not select ("missing"), so
  # only a missing report file is a failure.
  (cd "$REPO_ROOT" && AEROL_SCENARIO="$SCENARIO" go run ./integration-tests/report -scenario "${SCENARIO}-node" \
    -json "${OUT_DIR}/test.json" -out "${OUT_DIR}/report") >/dev/null 2>&1 || true
  [[ -f "${OUT_DIR}/report/${SCENARIO}-node.md" ]] || echo "report generation failed; test.json is still in ${OUT_DIR}" >&2
fi
echo "=== ${SCENARIO} from ${NODE_NAME}: exit ${rc}; results in ${OUT_DIR} ===" >&2
if [[ -f "${OUT_DIR}/test.json" ]]; then
  jq -r 'select(.Action == "pass" or .Action == "fail" or .Action == "skip") | select(.Test != null) | "  \(.Action)\t\(.Test)"' \
    "${OUT_DIR}/test.json" >&2 || true
  grep -h 'ucdetail=' "${OUT_DIR}/test.log" 2>/dev/null | sed 's/^ */  /' >&2 || true
fi
exit "$rc"

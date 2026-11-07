#!/usr/bin/env bash
# adopt-gate.sh — the adopt half of the Phase 2 gate
# (plans/kubectl-style-cluster-ops.md §4.4, §9 Phase 2 row).
#
# A cluster built with the old scripts (cluster-init.sh, the two-pass
# cluster-join.sh and the seed's CSR loop) on an old release is moved to this
# build the way an operator does the first hop (re-run this build's
# install.sh on each node), adopted with `sandboxd adopt` (the seed first,
# then every other server), and then grown by one machine with the line
# `aerolvm join-command` prints. The scenario has one blank node (Terraform
# nodes[].blank) for that last step.
#
# Each check prints "UC-63x PASS|FAIL <what>". Exit 0 only if every check
# passed.
#
#   UC-630 the seed's adopt imports its CA key and admits every member
#   UC-631 every other server's adopt fetches the CA key from a server over mTLS
#   UC-632 adopt again changes nothing (everyone admitted before)
#   UC-633 a blank machine joins the adopted cluster with the join-command line
#   UC-634 the cluster is healthy afterwards: every member Ready on this build,
#          the new worker takes a sandbox
#
# Usage: adopt-gate.sh <scenario> --from <tag> [--keep]
set -euo pipefail

if ((BASH_VERSINFO[0] < 4)); then
  echo "adopt-gate.sh needs bash >= 4 (brew install bash, then run via it)" >&2; exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
RUN="$HERE/run.sh"
PROD_TFVARS="$REPO_ROOT/config/terraform.tfvars"
SECRETS="$REPO_ROOT/config/secrets.yml"
# shellcheck source=/dev/null
source "$HERE/lib/common.sh"

SCENARIO=""
FROM_TAG=""
KEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) FROM_TAG="${2:-}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) grep '^#' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) SCENARIO="$1"; shift ;;
  esac
done
[[ -n "$SCENARIO" && -n "$FROM_TAG" ]] || { echo "usage: adopt-gate.sh <scenario> --from <tag> [--keep]" >&2; exit 2; }

SDIR="$HERE/.tf/$SCENARIO"
fail=0
step() { echo; echo "===== $* ====="; }
pass() { echo "$1 PASS $2"; }
die()  { echo "$1 FAIL $2" >&2; fail=1; }

resolve_ssh_identity "$HERE/scenarios/${SCENARIO}.tfvars" "$PROD_TFVARS"
SSH_ID=("${SSH_OPTS[@]}")
[[ -n "${AEROL_SSH_IDENTITY_FILE:-}" ]] || { echo "no SSH identity resolved" >&2; exit 2; }
on_node() { ssh "${SSH_ID[@]}" "ubuntu@$1" "$2" 2>&1; }

teardown() {
  if [[ "$KEEP" == 1 ]]; then
    echo "--keep: leaving $SCENARIO up. Destroy later with: $RUN $SCENARIO --destroy-only" >&2
    return
  fi
  step "teardown"
  "$RUN" "$SCENARIO" --destroy-only || echo "teardown returned non-zero; run 'make integration-reap'" >&2
}
trap teardown EXIT

step "1/6 provision $SCENARIO on $FROM_TAG with the old scripts (no suite cases)"
AEROL_TEST_RUN='^$' "$RUN" "$SCENARIO" --version "$FROM_TAG" --keep || true

step "2/6 read targets"
targets="$(TF_DATA_DIR="$SDIR" terraform -chdir="$REPO_ROOT/Terraform" output -json integration_targets)" \
  || { echo "could not read integration_targets from $SDIR" >&2; exit 2; }
BASE="$(jq -r '.base_url // empty' <<<"$targets")"
TOKEN="$(yq -r '.cluster.pat_token' "$SECRETS")"
SEED_IP="$(jq -r '.nodes[] | select(.seed) | .public_ip' <<<"$targets")"
BLANK_IP="$(jq -r '.nodes[] | select(.name | endswith("spare-1")) | .public_ip' <<<"$targets")"
mapfile -t SERVER_IPS < <(jq -r '.nodes[] | select((.seed | not) and (.role | test("server"))) | .public_ip' <<<"$targets")
mapfile -t MEMBER_IPS < <(jq -r '.nodes[] | select(.name | endswith("spare-1") | not) | .public_ip' <<<"$targets")
[[ -n "$BASE" && -n "$TOKEN" && -n "$SEED_IP" && -n "$BLANK_IP" && ${#SERVER_IPS[@]} -gt 0 ]] ||
  { echo "missing base_url, token, seed, spare-1 or servers in the targets" >&2; exit 2; }
echo "base=$BASE seed=$SEED_IP servers=${SERVER_IPS[*]} blank=$BLANK_IP members=${MEMBER_IPS[*]}"
AUTH=(-sS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")
api() { curl "${AUTH[@]}" "$@"; }
members_alive() { api "$BASE/v1/cluster/members" | jq '[.members[] | select(.alive)] | length'; }
BEFORE_MEMBERS="$(members_alive)"
echo "alive members on $FROM_TAG: $BEFORE_MEMBERS"

step "3/6 build this tree; move every scripted node to it (the install.sh first hop)"
make -C "$REPO_ROOT" itest-build >/dev/null
BIN="$(ls -t "$HERE"/.build/*/sandboxd_linux_amd64 2>/dev/null | head -1)"
[[ -n "$BIN" ]] || { echo "no cross-compiled sandboxd_linux_amd64 under .build/" >&2; exit 2; }
BUILD_DIR="$(dirname "$BIN")"
WANT_VERSION="itest-$(basename "$BUILD_DIR")"
for f in install.sh sandboxd_linux_amd64 toolboxd_linux_amd64 checksums.txt; do
  [[ -f "$BUILD_DIR/$f" ]] || { echo "build $BUILD_DIR has no $f" >&2; exit 2; }
done
# This build's checksums.txt names no Caddy; the old release's is the one
# the nodes already run (upgrade-gate.sh does the same).
CADDY_URL="https://github.com/aerol-ai/microvm/releases/download/${FROM_TAG}/caddy_linux_amd64"
curl -fsIL -o /dev/null --max-time 20 "$CADDY_URL" ||
  CADDY_URL="https://github.com/aerol-ai/microvm/releases/latest/download/caddy_linux_amd64"
STAGE=/tmp/aerolvm-adopt
FILE_FLAGS="--sandboxd-url file://$STAGE/sandboxd_linux_amd64 --toolboxd-url file://$STAGE/toolboxd_linux_amd64 --checksums-url file://$STAGE/checksums.txt --caddy-binary-url $CADDY_URL"
# Through S3, not scp (lib/stage.sh says why): this machine uploads the build
# once at most (not at all when it is already published), and each node
# downloads it inside AWS. The node still runs install.sh from local files,
# which is what the gate checks.
stage_build() {
  on_node "$1" "rm -rf $STAGE && mkdir -p $STAGE" >/dev/null
  stage_to_node "ubuntu@$1" "$STAGE" "$BUILD_DIR/install.sh" "$BUILD_DIR/sandboxd_linux_amd64" "$BUILD_DIR/toolboxd_linux_amd64" \
    "$BUILD_DIR/checksums.txt" >/dev/null
}
health_version() { on_node "$1" "curl -fsS --max-time 5 http://127.0.0.1:21212/health | sed -n 's/.*\"version\":\"\\([^\"]*\\)\".*/\\1/p'" | tail -n1; }
mkdir -p "$HERE/reports"
for ip in "${MEMBER_IPS[@]}"; do
  echo "  first hop on $ip ..."
  stage_build "$ip" || { die UC-634 "staging the build on $ip failed"; continue; }
  log="$HERE/reports/adopt-gate-${SCENARIO}-install-${ip}.log"
  on_node "$ip" "cd /tmp && sudo bash $STAGE/install.sh $FILE_FLAGS" >"$log" 2>&1 || die UC-634 "$ip: install.sh re-run failed; see $log"
  for _ in $(seq 1 30); do [[ "$(health_version "$ip")" == "$WANT_VERSION" ]] && break; sleep 5; done
  v="$(health_version "$ip")"
  [[ "$v" == "$WANT_VERSION" ]] && echo "    $ip runs $v" || die UC-634 "$ip runs '$v' after the first hop, want $WANT_VERSION"
done
wait_for_health "$BASE" "$TOKEN" || die UC-634 "the cluster is not healthy after the first hop"
for _ in $(seq 1 30); do [[ "$(members_alive)" == "$BEFORE_MEMBERS" ]] && break; sleep 5; done

step "4/6 adopt: the seed, then every other server, then the seed again"
out="$(on_node "$SEED_IP" "sudo /usr/local/bin/sandboxd adopt")" || true
echo "$out" | sed 's/^/    seed: /'
if grep -q "adopted on this server" <<<"$out" && grep -q "admitted now: " <<<"$out" && ! grep -q "admitted now: none" <<<"$out"; then
  pass UC-630 "the seed imported its CA key and admitted the members"
else
  die UC-630 "the seed's adopt did not admit the members"
fi
for ip in "${SERVER_IPS[@]}"; do
  out="$(on_node "$ip" "sudo /usr/local/bin/sandboxd adopt; echo; sudo test -s /etc/sandboxd/cluster-ca/ca.key && echo HAS_CA_KEY")" || true
  echo "$out" | sed "s/^/    $ip: /"
  if grep -q "CA key from peer" <<<"$out" && grep -q HAS_CA_KEY <<<"$out"; then
    pass UC-631 "$ip fetched the CA key from another server and holds it"
  else
    die UC-631 "$ip did not get the CA key from a server"
  fi
done
out="$(on_node "$SEED_IP" "sudo /usr/local/bin/sandboxd adopt")" || true
if grep -q "admitted now: none" <<<"$out"; then
  pass UC-632 "adopt again admitted nobody new"
else
  echo "$out" | sed 's/^/    seed again: /'
  die UC-632 "a second adopt changed the admitted set"
fi

step "5/6 a blank machine joins with the join-command line"
AEROLVM="$(mktemp -d)/aerolvm"
(cd "$REPO_ROOT" && go build -o "$AEROLVM" ./cmd/aerolvm)
line="$(SB_API_URL="$BASE" SB_PAT_TOKEN="$TOKEN" XDG_CONFIG_HOME="$(mktemp -d)" "$AEROLVM" join-command --role worker)"
echo "  join-command printed: ${line%%--token*}--token <hidden> ..."
args="${line#*bash -s -- }"
[[ "$args" == join\ https://* ]] || die UC-633 "join-command printed an unexpected line"
stage_build "$BLANK_IP" || die UC-633 "staging the build on the blank node failed"
log="$HERE/reports/adopt-gate-${SCENARIO}-join.log"
# The printed words run unchanged; only the installer is this build's, from
# the staged files, because a dev build is not on the release CDN.
if on_node "$BLANK_IP" "cd /tmp && sudo bash $STAGE/install.sh $FILE_FLAGS $args" >"$log" 2>&1 &&
  grep -q "joined the cluster as a worker node" "$log"; then
  pass UC-633 "the blank machine joined the adopted cluster with one line"
else
  tail -n 40 "$log" | sed 's/^/    /'
  die UC-633 "the blank machine did not join; see $log"
fi

step "6/6 the cluster afterwards"
want=$((BEFORE_MEMBERS + 1))
for _ in $(seq 1 30); do [[ "$(members_alive)" == "$want" ]] && break; sleep 5; done
got="$(members_alive)"
versions="$(api "$BASE/v1/cluster/members" | jq -r '[.members[].version] | unique | join(",")')"
if [[ "$got" == "$want" && "$versions" == "$WANT_VERSION" ]]; then
  pass UC-634 "$got members alive, all on $WANT_VERSION"
else
  die UC-634 "$got members alive (want $want), versions $versions"
fi
sb="$(api -X POST "$BASE/v1/sandboxes" -d '{"name":"adopt-gate-after","image":"alpine:3.20"}')"
id="$(jq -r '.id // empty' <<<"$sb")"
if [[ -n "$id" ]]; then
  pass UC-634 "a sandbox was created after the join ($id)"
  api -X DELETE "$BASE/v1/sandboxes/$id" >/dev/null 2>&1 || true
else
  die UC-634 "no sandbox after the join: $sb"
fi

echo
if [[ "$fail" == 0 ]]; then
  echo "ADOPT-GATE PASS"
else
  echo "ADOPT-GATE FAIL" >&2
fi
exit "$fail"

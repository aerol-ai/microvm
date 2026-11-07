#!/usr/bin/env bash
# upgrade-gate.sh — automate the warm-upgrade release gate.
#
# Provisions a scenario on an OLD released tag, seeds snapshots + an alias,
# upgrades every node's daemon in place to the LOCAL build, and verifies the
# schema migration preserved every row. This is the executable form of
# SNAPSHOT-MIGRATION-UPGRADE.md: a destructive migration (e.g. the per-owner
# snapshot namespace's migrateSnapshotOwnerPK) only runs on a pre-existing
# old-schema DB, which a fresh provision never produces — so the only way to
# exercise it is to stand up the old release and upgrade in place.
#
# The upgrade is what the docs tell an operator to do
# (plans/kubectl-style-cluster-ops.md Phase 0): re-run THIS build's
# install.sh on each node with no node flags. The only flags passed say where
# this build's files are (--sandboxd-url, --toolboxd-url, --checksums-url,
# --caddy-binary-url), which install.sh never saves; every node setting must
# come back from what the old release wrote. Per node it checks that the PAT
# is kept, /etc/sandboxd/node.json is written (0600, root, no PAT), sandboxd
# was restarted onto the new binary (new PID, /health reports the new
# version), and `sandboxd --version` prints the new version, exits by itself
# and leaves the running daemon alone.
#
# Usage: upgrade-gate.sh <scenario> --from <tag> [--keep] [--swap-binary]
#   <scenario>     e.g. single-node, cluster-hetero
#   --from <tag>   the released tag to provision first (the old schema), e.g. v0.6.7
#   --keep         leave the deployment up after the gate (default: destroy)
#   --swap-binary  upgrade by copying the binary in and restarting, the
#                  pre-Phase-0 way, to check a schema migration alone when the
#                  installer path is what is broken
#
# Exit 0 only if every node migrated with no data loss AND the API still serves
# the seeded snapshots. Any failure is loud and non-zero.
set -euo pipefail

# Needs bash >= 4 (mapfile, associative arrays). `/usr/bin/env bash` is the
# homebrew bash on the harness hosts; /bin/bash on macOS is 3.2.
if ((BASH_VERSINFO[0] < 4)); then
  echo "upgrade-gate.sh needs bash >= 4 (brew install bash, then run via it)" >&2; exit 2
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
SWAP_BINARY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) FROM_TAG="${2:-}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --swap-binary) SWAP_BINARY=1; shift ;;
    -h|--help) grep '^#' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) SCENARIO="$1"; shift ;;
  esac
done
[[ -n "$SCENARIO" && -n "$FROM_TAG" ]] || {
  echo "usage: upgrade-gate.sh <scenario> --from <tag> [--keep] [--swap-binary]" >&2; exit 2; }

SDIR="$HERE/.tf/$SCENARIO"
fail=0
step() { echo; echo "===== $* ====="; }
die()  { echo "UPGRADE-GATE FAIL: $*" >&2; fail=1; }

# Resolve the SSH key the nodes trust (exports AEROL_SSH_IDENTITY_FILE + fills
# SSH_OPTS) so the in-place upgrade and schema checks can reach every node.
resolve_ssh_identity "$HERE/scenarios/${SCENARIO}.tfvars" "$PROD_TFVARS"
SSH_ID=("${SSH_OPTS[@]}")
[[ -n "${AEROL_SSH_IDENTITY_FILE:-}" ]] || { echo "no SSH identity resolved" >&2; exit 2; }
on_node() { ssh "${SSH_ID[@]}" "ubuntu@$1" "$2" 2>/dev/null; }

teardown() {
  if [[ "$KEEP" == 1 ]]; then
    echo "--keep: leaving $SCENARIO up. Destroy later with: $RUN $SCENARIO --destroy-only" >&2
    return
  fi
  step "teardown"
  "$RUN" "$SCENARIO" --destroy-only || echo "teardown returned non-zero; run 'make integration-reap'" >&2
}
trap teardown EXIT

# ---------------------------------------------------------------------------
step "1/6 provision $SCENARIO on $FROM_TAG (old schema), 0 suite tests"
# AEROL_TEST_RUN='^$' runs no suite cases: we only need the deployment and a
# clean DB. --keep so teardown is ours to control (the trap above).
AEROL_TEST_RUN='^$' "$RUN" "$SCENARIO" --version "$FROM_TAG" --keep || true

step "2/6 read targets"
targets="$(TF_DATA_DIR="$SDIR" terraform -chdir="$REPO_ROOT/Terraform" output -json integration_targets)" \
  || { echo "could not read integration_targets from $SDIR" >&2; exit 2; }
BASE="$(jq -r '.base_url // empty' <<<"$targets")"
TOKEN="$(yq -r '.cluster.pat_token' "$SECRETS")"
mapfile -t IPS < <(jq -r '.nodes[].public_ip' <<<"$targets" | grep -vE '^$|null')
[[ -n "$BASE" && -n "$TOKEN" && ${#IPS[@]} -gt 0 ]] || { echo "missing base_url/token/nodes" >&2; exit 2; }
echo "base=$BASE  nodes=${#IPS[@]}  (${IPS[*]})"

AUTH=(-sS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")
api()  { curl "${AUTH[@]}" "$@"; }
code() { curl "${AUTH[@]}" -o /dev/null -w '%{http_code}' "$@"; }
DB=/var/lib/sandboxd/state.db
# sqlite3 is not on the base image; install once per node for the schema checks.
for ip in "${IPS[@]}"; do on_node "$ip" "command -v sqlite3 >/dev/null || sudo apt-get install -y -q sqlite3 >/dev/null 2>&1" || true; done

step "3/6 seed snapshots (2 registered + 1 committed) + a legacy alias"
api -X POST "$BASE/v1/snapshots" -d '{"name":"upg-img-a","image":"alpine:3.20"}' >/dev/null; echo "  registered upg-img-a"
api -X POST "$BASE/v1/snapshots" -d '{"name":"upg-img-b","image":"alpine:3.20"}' >/dev/null; echo "  registered upg-img-b"
SB="$(api -X POST "$BASE/v1/sandboxes" -d '{"name":"upg-seed","image":"alpine:3.20"}')"
ID="$(jq -r '.id // empty' <<<"$SB")"
[[ -n "$ID" ]] || die "seed sandbox create returned no id"
for _ in $(seq 1 40); do
  st="$(api "$BASE/v1/sandboxes/$ID" | jq -r '.status // empty')"
  [[ "$st" == running || "$st" == started ]] && break; sleep 3
done
api -X POST "$BASE/v1/sandboxes/$ID/snapshot" -d '{"name":"upg-committed"}' >/dev/null; echo "  committed upg-committed"
api -X DELETE "$BASE/v1/sandboxes/$ID" >/dev/null 2>&1 || true
# Insert a legacy alias on every node that holds a snapshot row, so the
# migration's alias owner_ref backfill + composite FK are exercised too.
for ip in "${IPS[@]}"; do
  name="$(on_node "$ip" "sudo sqlite3 $DB 'SELECT name FROM sandbox_snapshots LIMIT 1;'")" || true
  [[ -n "$name" ]] && on_node "$ip" "sudo sqlite3 $DB \"INSERT OR IGNORE INTO snapshot_aliases(alias,snapshot_name,facade,extra_names_json,state_json,created_at,updated_at) VALUES('upg-gate-alias','$name','daytona','[]','',datetime('now'),datetime('now'));\"" && echo "  inserted alias on $ip -> $name"
done

step "4/6 record pre-upgrade state + confirm OLD schema on every node"
declare -A PRE_SNAPS PRE_ALIASES
for ip in "${IPS[@]}"; do
  pk="$(on_node "$ip" "sudo sqlite3 $DB 'SELECT group_concat(name) FROM pragma_table_info(\"sandbox_snapshots\") WHERE pk>0;'")" || true
  PRE_SNAPS[$ip]="$(on_node "$ip" "sudo sqlite3 $DB 'SELECT count(*) FROM sandbox_snapshots;'")"
  PRE_ALIASES[$ip]="$(on_node "$ip" "sudo sqlite3 $DB 'SELECT count(*) FROM snapshot_aliases;'")"
  echo "  $ip: pk=[$pk] snaps=${PRE_SNAPS[$ip]} aliases=${PRE_ALIASES[$ip]}"
  [[ "$pk" == "name" ]] || echo "  note: $ip sandbox_snapshots PK is already [$pk] (not the old name-only PK)"
done

step "5/6 build local linux/amd64 artifacts + upgrade every node in place"
make -C "$REPO_ROOT" itest-build >/dev/null
BIN="$(ls -t "$HERE"/.build/*/sandboxd_linux_amd64 2>/dev/null | head -1)"
[[ -n "$BIN" ]] || { echo "no cross-compiled sandboxd_linux_amd64 under .build/" >&2; exit 2; }
file "$BIN" | grep -q x86-64 || { echo "built binary is not x86-64: $(file "$BIN")" >&2; exit 2; }
BUILD_DIR="$(dirname "$BIN")"
# build.sh stamps every binary with itest-<build id>, the directory's name.
WANT_VERSION="itest-$(basename "$BUILD_DIR")"
echo "  upgrade build: $BUILD_DIR ($WANT_VERSION)"

if [[ "$SWAP_BINARY" == 1 ]]; then
  for ip in "${IPS[@]}"; do
    echo "  upgrading $ip (binary swap) ..."
    # Through S3, not scp: one upload from here, then a download inside AWS.
    stage_to_node "ubuntu@$ip" /tmp/aerol-upgrade "$BIN" >/dev/null || { die "staging the binary on $ip failed"; continue; }
    on_node "$ip" "sudo systemctl stop sandboxd && sudo install -m0755 /tmp/aerol-upgrade/sandboxd_linux_amd64 /usr/local/bin/sandboxd && sudo systemctl start sandboxd" \
      || { die "restart on $ip failed"; continue; }
  done
else
  for f in install.sh sandboxd_linux_amd64 toolboxd_linux_amd64 checksums.txt; do
    [[ -f "$BUILD_DIR/$f" ]] || { echo "build $BUILD_DIR has no $f" >&2; exit 2; }
  done
  # install.sh checks a Caddy download against --checksums-url unless the URL
  # is given explicitly, and this build's checksums.txt names no Caddy (the
  # caddy trap in lib/build.sh). The old release's Caddy is the one the node
  # already runs; latest is the fallback for a tag that did not ship one.
  CADDY_URL="https://github.com/aerol-ai/microvm/releases/download/${FROM_TAG}/caddy_linux_amd64"
  curl -fsIL -o /dev/null --max-time 20 "$CADDY_URL" ||
    CADDY_URL="https://github.com/aerol-ai/microvm/releases/latest/download/caddy_linux_amd64"

  # node-state.sh prints what the gate compares before and after, as
  # key=value lines. Run on the node, so no value crosses a shell quote.
  STATE_SCRIPT="$(mktemp -t aerol-node-state.XXXXXX)"
  cat >"$STATE_SCRIPT" <<'NODESTATE'
#!/usr/bin/env bash
set -u
env_value() { awk -F= -v k="$1" '$1 == k { v = substr($0, length($1) + 2) } END { print v }' /etc/sandboxd/sandboxd.env 2>/dev/null; }
pat="$(env_value SB_PAT_TOKEN)"
echo "pat=$pat"
for k in SB_DOMAIN SB_NODE_NAME SB_PUBLIC_HOST SB_API_HOST SB_PAT_SCOPE SB_HOST_RUNTIMES; do
  echo "env_$k=$(env_value "$k")"
done
echo "main_pid=$(systemctl show -p MainPID --value sandboxd)"
echo "running_version=$(curl -fsS --max-time 5 http://127.0.0.1:21212/health 2>/dev/null | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
if [[ -e /etc/sandboxd/node.json ]]; then
  echo "node_json=$(stat -c '%a %U' /etc/sandboxd/node.json)"
  echo "node_json_format=$(sed -n 's/^ *"format": *\([0-9]*\).*/\1/p' /etc/sandboxd/node.json)"
  echo "node_json_has_pat=$(grep -cF -- "$pat" /etc/sandboxd/node.json || true)"
else
  echo "node_json=absent"
fi
# Only after the upgrade: the old release has no `sandboxd version`, and
# asking it would boot a second daemon on the live state directory.
if [[ "${1:-}" == after ]]; then
  out="$(timeout 20 /usr/local/bin/sandboxd --version 2>&1)"
  echo "version_exit=$?"
  echo "version_line=${out%%$'\n'*}"
  echo "main_pid_after_version=$(systemctl show -p MainPID --value sandboxd)"
  echo "stray_version_procs=$(pgrep -fc 'sandboxd --version' || true)"
fi
NODESTATE
  kv() { sed -n "s/^$1=//p" <<<"$2" | head -n1; }

  STAGE=/tmp/aerolvm-upgrade
  for ip in "${IPS[@]}"; do
    echo "  upgrading $ip (re-run install.sh, no node flags) ..."
    on_node "$ip" "rm -rf $STAGE && mkdir -p $STAGE" || { die "$ip: cannot make $STAGE"; continue; }
    # Through S3, not scp: one upload from here, then a download inside AWS.
    stage_to_node "ubuntu@$ip" "$STAGE" "$BUILD_DIR/install.sh" "$BUILD_DIR/sandboxd_linux_amd64" "$BUILD_DIR/toolboxd_linux_amd64" \
      "$BUILD_DIR/checksums.txt" "$STATE_SCRIPT" >/dev/null || { die "staging the build on $ip failed"; continue; }
    state_name="$(basename "$STATE_SCRIPT")"
    before="$(on_node "$ip" "sudo bash $STAGE/$state_name before")" || true
    install_log="$HERE/reports/upgrade-gate-${SCENARIO}-install-${ip}.log"
    mkdir -p "$HERE/reports"
    if ! ssh "${SSH_ID[@]}" "ubuntu@$ip" "cd /tmp && sudo bash $STAGE/install.sh --sandboxd-url file://$STAGE/sandboxd_linux_amd64 --toolboxd-url file://$STAGE/toolboxd_linux_amd64 --checksums-url file://$STAGE/checksums.txt --caddy-binary-url '$CADDY_URL'" >"$install_log" 2>&1; then
      die "$ip: install.sh re-run failed; see $install_log"
      continue
    fi
    after="$(on_node "$ip" "sudo bash $STAGE/$state_name after")" || true
    echo "    before: pid=$(kv main_pid "$before") version=$(kv running_version "$before") node.json=$(kv node_json "$before")"
    echo "    after:  pid=$(kv main_pid "$after") version=$(kv running_version "$after") node.json=$(kv node_json "$after") --version='$(kv version_line "$after")'"

    [[ -n "$(kv pat "$before")" ]] || die "$ip: no SB_PAT_TOKEN before the upgrade"
    [[ "$(kv pat "$after")" == "$(kv pat "$before")" ]] || die "$ip: the re-run changed the PAT"
    for k in SB_DOMAIN SB_NODE_NAME SB_PUBLIC_HOST SB_API_HOST SB_PAT_SCOPE SB_HOST_RUNTIMES; do
      [[ "$(kv "env_$k" "$after")" == "$(kv "env_$k" "$before")" ]] ||
        die "$ip: the re-run changed $k: '$(kv "env_$k" "$before")' -> '$(kv "env_$k" "$after")'"
    done
    if [[ "$(kv node_json "$before")" == absent ]]; then
      grep -q "reading this node's settings back from" "$install_log" ||
        die "$ip: install.sh did not read the old node's settings back; see $install_log"
    else
      echo "    note: $ip already had node.json before the upgrade ($FROM_TAG writes it), so this did not test the read-back from sandboxd.env"
    fi
    [[ "$(kv node_json "$after")" == "600 root" ]] || die "$ip: node.json is '$(kv node_json "$after")', want mode 600 owned by root"
    [[ "$(kv node_json_format "$after")" == 1 ]] || die "$ip: node.json has no \"format\": 1"
    [[ "$(kv node_json_has_pat "$after")" == 0 ]] || die "$ip: node.json holds the PAT"
    grep -q "restarting sandboxd before Caddy" "$install_log" || die "$ip: install.sh did not restart sandboxd; see $install_log"
    [[ "$(kv main_pid "$after")" != "$(kv main_pid "$before")" && "$(kv main_pid "$after")" != 0 ]] ||
      die "$ip: sandboxd was not restarted (MainPID $(kv main_pid "$before") -> $(kv main_pid "$after"))"
    [[ "$(kv running_version "$after")" == "$WANT_VERSION" ]] ||
      die "$ip: the running sandboxd reports '$(kv running_version "$after")', want $WANT_VERSION"
    [[ "$(kv version_exit "$after")" == 0 && "$(kv version_line "$after")" == "sandboxd $WANT_VERSION" ]] ||
      die "$ip: sandboxd --version exited $(kv version_exit "$after") printing '$(kv version_line "$after")', want 'sandboxd $WANT_VERSION'"
    [[ "$(kv main_pid_after_version "$after")" == "$(kv main_pid "$after")" && "$(kv stray_version_procs "$after")" == 0 ]] ||
      die "$ip: sandboxd --version disturbed the daemon (MainPID $(kv main_pid "$after") -> $(kv main_pid_after_version "$after"), $(kv stray_version_procs "$after") still running)"
  done
  rm -f "$STATE_SCRIPT"
fi
wait_for_health "$BASE" "$TOKEN" || die "cluster not healthy after upgrade"

step "6/6 verify migration preserved everything + schema rebuilt"
for ip in "${IPS[@]}"; do
  pk="$(on_node "$ip" "sudo sqlite3 $DB 'SELECT group_concat(name) FROM pragma_table_info(\"sandbox_snapshots\") WHERE pk>0 ORDER BY pk;'")"
  alias_owner="$(on_node "$ip" "sudo sqlite3 $DB 'SELECT count(*) FROM pragma_table_info(\"snapshot_aliases\") WHERE name=\"owner_ref\";'")"
  snaps="$(on_node "$ip" "sudo sqlite3 $DB 'SELECT count(*) FROM sandbox_snapshots;'")"
  aliases="$(on_node "$ip" "sudo sqlite3 $DB 'SELECT count(*) FROM snapshot_aliases;'")"
  nulls="$(on_node "$ip" "sudo sqlite3 $DB 'SELECT count(*) FROM sandbox_snapshots WHERE owner_ref IS NULL;'")"
  echo "  $ip: pk=[$pk] alias_owner_ref_col=$alias_owner snaps=$snaps/${PRE_SNAPS[$ip]} aliases=$aliases/${PRE_ALIASES[$ip]} null_owner=$nulls"
  [[ "$pk" == "owner_ref,name" ]] || die "$ip PK not rebuilt to (owner_ref,name): [$pk]"
  [[ "$alias_owner" == 1 ]]       || die "$ip snapshot_aliases missing owner_ref"
  [[ "$snaps" == "${PRE_SNAPS[$ip]}" ]]   || die "$ip lost snapshot rows (${PRE_SNAPS[$ip]} -> $snaps)"
  [[ "$aliases" == "${PRE_ALIASES[$ip]}" ]] || die "$ip lost alias rows (${PRE_ALIASES[$ip]} -> $aliases)"
  [[ "$nulls" == 0 ]]             || die "$ip has $nulls NULL-owner snapshot rows after backfill"
done

# API round-trip against the migrated deployment.
for n in upg-img-a upg-img-b upg-committed; do
  c="$(code "$BASE/v1/snapshots/$n")"; echo "  GET /v1/snapshots/$n -> $c"
  [[ "$c" == 200 ]] || die "snapshot $n not resolvable after upgrade ($c)"
done
DSB="$(api -X POST "$BASE/v1/sandboxes" -d '{"name":"upg-postupg","image":"upg-committed"}')"
DID="$(jq -r '.id // empty' <<<"$DSB")"
if [[ -n "$DID" ]]; then
  ok=0
  for _ in $(seq 1 40); do
    st="$(api "$BASE/v1/sandboxes/$DID" | jq -r '.status // empty')"
    [[ "$st" == running || "$st" == started ]] && { ok=1; break; }; sleep 3
  done
  [[ "$ok" == 1 ]] || die "create-from-snapshot did not come up after upgrade"
  api -X DELETE "$BASE/v1/sandboxes/$DID" >/dev/null 2>&1 || true
  echo "  create-from-snapshot upg-committed -> ok"
else
  die "create-from-snapshot returned no id"
fi

echo
if [[ "$fail" == 0 ]]; then echo "UPGRADE-GATE PASS ($SCENARIO: $FROM_TAG -> local build)"; else echo "UPGRADE-GATE FAIL ($SCENARIO)"; fi
exit "$fail"

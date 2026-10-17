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
# Usage: upgrade-gate.sh <scenario> --from <tag> [--keep]
#   <scenario>   e.g. single-node, cluster-hetero
#   --from <tag> the released tag to provision first (the old schema), e.g. v0.6.7
#   --keep       leave the deployment up after the gate (default: destroy)
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
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) FROM_TAG="${2:-}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) grep '^#' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) SCENARIO="$1"; shift ;;
  esac
done
[[ -n "$SCENARIO" && -n "$FROM_TAG" ]] || {
  echo "usage: upgrade-gate.sh <scenario> --from <tag> [--keep]" >&2; exit 2; }

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

step "5/6 build local linux/amd64 binary + upgrade every node in place"
make -C "$REPO_ROOT" itest-build >/dev/null
BIN="$(ls -t "$HERE"/.build/*/sandboxd_linux_amd64 2>/dev/null | head -1)"
[[ -n "$BIN" ]] || { echo "no cross-compiled sandboxd_linux_amd64 under .build/" >&2; exit 2; }
file "$BIN" | grep -q x86-64 || { echo "built binary is not x86-64: $(file "$BIN")" >&2; exit 2; }
echo "  upgrade binary: $BIN"
for ip in "${IPS[@]}"; do
  echo "  upgrading $ip ..."
  scp "${SSH_ID[@]}" "$BIN" "ubuntu@$ip:/tmp/sandboxd.new" >/dev/null 2>&1 || { die "scp to $ip failed"; continue; }
  on_node "$ip" "sudo systemctl stop sandboxd && sudo install -m0755 /tmp/sandboxd.new /usr/local/bin/sandboxd && sudo systemctl start sandboxd" \
    || { die "restart on $ip failed"; continue; }
done
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

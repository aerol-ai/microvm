#!/usr/bin/env bash
# run.sh — orchestrate one integration scenario end to end:
#   provision (isolated TF state) -> wait ready -> run suite -> report -> teardown
#
# Usage:
#   integration-tests/run.sh <scenario> [--keep] [--prod-tls] [--metal-on-demand]
#   integration-tests/run.sh <scenario> [--no-disruptive]  # skip node-kill UCs
#   integration-tests/run.sh all       [flags]
#
# Scenarios: single-node | local-mode | cluster-3-mixed | cluster-hetero |
#            single-node-fc | single-node-fc-arm64 | cluster-arm64
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
NO_DISRUPTIVE=0
COLLECT_LOGS_ONLY=0
BENCH_ONLY=0
DESTROY_ONLY=0
SCENARIO=""
# PID of the local-mode SSH port-forward, so teardown can reap it. Without this
# the `ssh -fN` forks leak: each leftover keeps local :21212 bound, so the next
# run's forward fails ("Address already in use") and its health probe talks to a
# dead tunnel pointing at a destroyed box for the full 300s timeout.
SSH_TUNNEL_PID=""
# Local port the harness forwards to the seed's 127.0.0.1:21212.
LOCAL_API_PORT=21212

for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --prod-tls) PROD_TLS=1 ;;
    --metal-on-demand) METAL_ON_DEMAND=1 ;;
    --no-disruptive) NO_DISRUPTIVE=1 ;;
    # Collect logs from an ALREADY-RUNNING scenario (provisioned earlier with
    # --keep) and exit. No apply, no suite, no teardown — just dump every node's
    # forensics into reports/<scenario>-failure-logs.txt. Use this to iterate on
    # a stuck cluster without paying another bring-up.
    --collect-logs-only) COLLECT_LOGS_ONLY=1 ;;
    # Re-run UC-94/UC-95 against a cluster already provisioned with --keep.
    # Reads integration_targets from TF state; does not apply or destroy.
    --bench-only) BENCH_ONLY=1 ;;
    # Full terraform destroy of a scenario kept up with --keep (VPC, S3, IAM,
    # instances — everything, and clears the TF state). Unlike integration-reap
    # (which only terminates EC2 instances), this is the real cleanup.
    --destroy-only) DESTROY_ONLY=1 ;;
    -*) echo "unknown flag: $arg" >&2; exit 2 ;;
    *) SCENARIO="$arg" ;;
  esac
done
[[ -n "$SCENARIO" ]] || { echo "usage: run.sh <scenario|all> [--keep] [--prod-tls] [--metal-on-demand] [--no-disruptive] [--collect-logs-only] [--bench-only] [--destroy-only]" >&2; exit 2; }
# Reject shell metacharacters so a polluted SCENARIO env (or make injection)
# cannot turn one run.sh invocation into multiple shell commands.
if [[ "$SCENARIO" == *[$';#&|<>']* ]] || [[ "$SCENARIO" == *$'\n'* ]]; then
  echo "scenario name contains unsafe shell characters (refusing: ${SCENARIO})" >&2
  exit 2
fi

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

# on_demand_tfvar maps the --metal-on-demand flag to the force_on_demand TF var
# (flips firecracker bare-metal nodes off spot; cheap t3 spot nodes unaffected).
on_demand_tfvar() {
  [[ "$METAL_ON_DEMAND" == "1" ]] && echo "true" || echo "false"
}

teardown() {
  local scenario="$1"
  # Always reap the SSH tunnel, even under --keep: the forward is a local
  # process tied to THIS run, not infra, and a survivor would block the next
  # run's bind on :21212.
  if [[ -n "$SSH_TUNNEL_PID" ]]; then
    kill "$SSH_TUNNEL_PID" 2>/dev/null || true
    SSH_TUNNEL_PID=""
  fi
  if [[ "$KEEP" == "1" ]]; then
    echo "--keep set: leaving ${scenario} infra up. Reap later with: make integration-reap"
    return
  fi
  echo "teardown: destroying ${scenario}"
  # shellcheck disable=SC2046
  TF_DATA_DIR="${REPO_ROOT}/integration-tests/.tf/${scenario}" \
    terraform -chdir="${REPO_ROOT}/Terraform" destroy -auto-approve -input=false \
    $(tf_varfile_args "$scenario") \
    -var="config_dir=${REPO_ROOT}/integration-tests/.tf/${scenario}/config" \
    -var="force_on_demand=$(on_demand_tfvar)" || \
    echo "teardown: destroy returned non-zero for ${scenario} — run 'make integration-reap'" >&2
}

if [[ "$DESTROY_ONLY" == "1" ]]; then
  # Fast path: teardown() returns early when KEEP=1; force a real destroy here.
  KEEP=0
  teardown "$SCENARIO"
  exit 0
fi

# lease_domain picks a RANDOM test domain from the pool, never repeating the
# previous run's pick. Reusing one name re-requests the same cert set and trips
# Let's Encrypt's duplicate-certificate limit (5 identical sets/week); random
# selection spreads runs across the pool so each gets a fresh quota, and the
# "exclude last" rule guarantees we never hit the same FQDN twice in a row (the
# one case that actually accumulates against the duplicate limit). The persisted
# lease file under .tf/ (gitignored) only remembers the last index for that
# exclusion. With a single-domain pool there's nothing to rotate to, so it
# degrades to always returning that one.
lease_domain() {
  local n last idx
  local lease_file="${REPO_ROOT}/integration-tests/.tf/.domain-lease"
  n=$(yq -r '.itest.domains | length' "$DOMAINS_FILE")
  [[ "$n" =~ ^[0-9]+$ && "$n" -gt 0 ]] || { echo "domains pool empty in $DOMAINS_FILE" >&2; return 1; }
  last=-1
  [[ -f "$lease_file" ]] && last=$(cat "$lease_file" 2>/dev/null || echo -1)
  [[ "$last" =~ ^-?[0-9]+$ ]] || last=-1
  idx=$(( RANDOM % n ))
  # Re-roll off a collision with the previous pick (only meaningful when n>1);
  # a single deterministic bump is enough and keeps the result uniform-ish.
  if [[ "$n" -gt 1 && "$idx" -eq "$last" ]]; then
    idx=$(( (idx + 1) % n ))
  fi
  mkdir -p "$(dirname "$lease_file")"
  echo "$idx" > "$lease_file"
  yq -r ".itest.domains[$idx]" "$DOMAINS_FILE"
}

# allow_disruptive_for decides AEROL_ALLOW_DISRUPTIVE for the suite. cluster-hetero
# enables node-kill / failover fault injection by default; other scenarios stay
# off unless the operator exported AEROL_ALLOW_DISRUPTIVE already.
allow_disruptive_for() {
  local scenario="$1"
  if [[ -n "${AEROL_ALLOW_DISRUPTIVE:-}" ]]; then
    echo "$AEROL_ALLOW_DISRUPTIVE"
    return
  fi
  if [[ "$scenario" == "cluster-hetero" && "$NO_DISRUPTIVE" != "1" ]]; then
    echo "1"
    return
  fi
  echo "0"
}

is_stale_wasm_snapshot_ref() {
  local ref="${1:-}"
  # WASM runtime tests use a staged module alias such as "python". A snapshot
  # image ref from the Docker snapshot UCs is not a WASM module and always fails
  # module resolution if it leaks in from the operator's shell environment.
  [[ "$ref" == *"/cluster/"*"/snapshots"* || "$ref" == "cluster/"*"/snapshots"* ]]
}

print_bench_artifact_summary() {
  local bench_out="$1"
  [[ -f "$bench_out" ]] || return 0

  echo "benchmark summary:" >&2
  if ! jq -r '
    if ((.latency // []) | length) > 0 then
      "latency:",
      (.latency[] |
        "  \(.runtime): " +
        "api p50=\(.api_p50_ms)ms p90=\(.api_p90_ms)ms p99=\(.api_p99_ms)ms | " +
        "server p50=\(.server_p50_ms)ms p90=\(.server_p90_ms)ms p99=\(.server_p99_ms)ms | " +
        "running p50=\(.run_p50_ms)ms p90=\(.run_p90_ms)ms p99=\(.run_p99_ms)ms | " +
        "samples=\(.samples) failures=\(.failures)")
    else
      "latency: <missing>"
    end,
    if .density then
      "density: created=\(.density.created) running=\(.density.running) stopped_on_cap=\(.density.stopped_on_cap) safety_cap_hit=\(.density.safety_cap_hit)" +
      (if ((.density.stopped_reason // "") | length) > 0 then " reason=\(.density.stopped_reason)" else "" end)
    else
      "density: <missing>"
    end
  ' "$bench_out" >&2; then
    echo "benchmark summary unavailable: could not parse ${bench_out}" >&2
  fi
}

run_one() {
  local scenario="$1"
  local sdir="${REPO_ROOT}/integration-tests/.tf/${scenario}"
  local overlay="${sdir}/config"

  # Preflight: a scenario is fully described by its tfvars + caps.yml. Fail
  # cleanly here rather than mid-terraform when one is missing (e.g. `all`
  # running before a scenario's files exist).
  local tfvars_file="${HERE}/scenarios/${scenario}.tfvars"
  local caps_file="${HERE}/scenarios/${scenario}.caps.yml"
  if [[ ! -f "$tfvars_file" || ! -f "$caps_file" ]]; then
    echo "scenario ${scenario}: missing $(basename "$tfvars_file") or $(basename "$caps_file")" >&2
    return 2
  fi

  mkdir -p "$overlay"

  local prod_domain leased cluster_name state_key
  prod_domain=$(yq -r '.ingress.domain_name' "$CONFIG_CLUSTER")
  cluster_name="aerolvm-itest-${scenario}"
  state_key="integration/${scenario}/terraform.tfstate"

  # Capability checks read the structured list (not a substring grep, which
  # would false-match the word "domain" in a caps-file comment).
  local caps_domain caps_wasm caps_cluster caps_platform_volumes
  caps_domain=$(yq -r '.capabilities | contains(["domain"])' "$caps_file")
  caps_wasm=$(yq -r '.capabilities | contains(["wasm"])' "$caps_file")
  caps_cluster=$(yq -r '.capabilities | contains(["cluster"])' "$caps_file")
  caps_platform_volumes=$(yq -r '.capabilities | contains(["platform-volumes"])' "$caps_file")
  if [[ "$caps_domain" == "true" ]]; then
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
  # wasm.enabled follows the scenario's wasm capability so the wasm worker can
  # actually run modules (the wasm-runtime UCs still gate on a staged module
  # ref via AEROL_WASM_MODULE_REF; this just turns the runtime on).
  # When wasm runs we also turn on the warm-worker pool so creates skip the cold
  # module compile (CPython-on-wasm is ~10s cold on a t3). depth_default is per
  # module digest. Benchmark provisions size the default to the serial sample
  # count so `make integration-benchmark keep` measures warm creates without an
  # extra operator override; non-benchmark wasm scenarios keep the shallow pool.
  local wasm_pool_enabled="false" wasm_pool_depth=0
  if [[ "$caps_wasm" == "true" ]]; then
    local wasm_pool_default_depth=2
    if [[ "${AEROL_BENCH:-}" == "1" ]]; then
      local bench_samples="${AEROL_BENCH_SAMPLES:-10}"
      if [[ "$bench_samples" =~ ^[0-9]+$ && "$bench_samples" -gt 0 ]]; then
        wasm_pool_default_depth="$bench_samples"
      fi
    fi
    wasm_pool_enabled="true"
    wasm_pool_depth="${AEROL_WASM_POOL_DEPTH:-$wasm_pool_default_depth}"
  fi
  # Upstream auto-import (pulling private prod images through AOCR hooks) and
  # the fleet control plane are prod-only side effects we always neutralize.
  yq '.auto_import.enabled = false
      | .fleet_control_plane.enabled = false
      | .wasm.enabled = '"$caps_wasm"'
      | .wasm.pool.enabled = '"$wasm_pool_enabled"'
      | .wasm.pool.depth_default = '"$wasm_pool_depth"'
      | .platform_volumes.enabled = '"$caps_platform_volumes"'
      | .platform_volumes.backend = "s3"
      | .platform_volumes.s3_bucket = ""
      | .platform_volumes.s3_prefix = "integration-platform-volumes/'"$scenario"'"
      | .platform_volumes.s3_region = ""
      | .platform_volumes.s3_endpoint = ""
      | .platform_volumes.s3_access_key_id = ""
      | .platform_volumes.s3_secret_access_key = ""
      | (.ingress.acme_ca // "") = "'"$acme_issuer"'"
      | (.ingress.domain_name) = "'"${leased}"'"' \
    "$CONFIG_CLUSTER" > "${overlay}/cluster.yml"

  # AOCR mirror + snapshot distribution. Single-node/local-mode don't need
  # cross-node image sharing, so the mirror is fully neutralized there. Cluster
  # scenarios KEEP the mirror and turn snapshot push ON so a sandbox created
  # from a peer node's snapshot can pull it (UC-21) — mirroring prod.
  #
  # We deliberately do NOT override auto_import.cluster_id: the AOCR cluster PAT
  # (symlinked from config/secrets.yml, reused as the push credential) is bound
  # server-side to one cluster_id, and AOCR only authorizes pushes to that PAT's
  # own `cluster/<id>/...` namespace (auth/src/clusterPat.ts evaluateClusterPatScope).
  # A scenario-specific id would land outside the PAT's namespace and 403, so the
  # config's cluster_id (which the PAT is registered for) must be used as-is.
  #
  # Cleanup: snapshots push to `cluster/<id>/snapshots/<name>:latest<suffix>`.
  # We append an AOCR TTL suffix so the registry reaper auto-deletes each test
  # snapshot 1h after push (AOCR parses `--ttl-<dur>` off the tag end). Without
  # it, every uniquely-named test snapshot becomes its own repo that the
  # keep-latest rule never expires, leaking repos into the shared namespace.
  if [[ "$caps_cluster" == "true" ]]; then
    yq -i '.mirror.push_host = "aocr.aerol.ai"
        | .mirror.snapshot_push_enabled = true
        | .mirror.snapshot_push_tag_suffix = "--ttl-1h"' \
      "${overlay}/cluster.yml"
  else
    yq -i '.mirror.host = ""
        | .mirror.push_host = ""
        | .mirror.snapshot_push_enabled = false' \
      "${overlay}/cluster.yml"
  fi

  # When the scenario advertises wasm, stage the curated language runtimes by
  # splicing fixtures/wasm/modules.yml (url + sha256 per module) into
  # wasm.standard_modules. Nodes fetch + verify them at boot under their alias
  # (python/ruby/php), so the wasm-runtime UC has something real to run.
  if [[ "$caps_wasm" == "true" ]]; then
    yq -i '.wasm.standard_modules = load("'"${HERE}/fixtures/wasm/modules.yml"'").standard_modules' \
      "${overlay}/cluster.yml"
  fi
  ln -sf "${REPO_ROOT}/config/secrets.yml" "${overlay}/secrets.yml"

  trap "teardown '${scenario}'" EXIT INT TERM

  echo "=== provisioning ${scenario} (domain=${leased:-none}) ==="
  TF_DATA_DIR="$sdir" terraform -chdir="${REPO_ROOT}/Terraform" init -reconfigure -input=false \
    -backend-config="key=${state_key}"
  # shellcheck disable=SC2046
  TF_DATA_DIR="$sdir" terraform -chdir="${REPO_ROOT}/Terraform" apply -auto-approve -input=false \
    $(tf_varfile_args "$scenario") \
    -var="config_dir=${overlay}" \
    -var="force_on_demand=$(on_demand_tfvar)"

  # Discover endpoint.
  local targets base_url pat
  targets=$(TF_DATA_DIR="$sdir" terraform -chdir="${REPO_ROOT}/Terraform" output -json integration_targets)
  pat=$(yq -r '.cluster.pat_token' "${REPO_ROOT}/config/secrets.yml")

  local inconclusive=0
  if [[ "$caps_domain" == "true" ]]; then
    base_url=$(echo "$targets" | jq -r '.base_url')
    wait_for_dns "$leased" || inconclusive=1
    wait_for_tls "$leased" || inconclusive=1
    wait_for_health "$base_url" "$pat" || inconclusive=1
  else
    # local-mode: SSH tunnel to the seed, talk to localhost:21212. Unlike the
    # domain branch there's no DNS/TLS wait to absorb boot time, so wait for
    # cloud-init to finish before opening the tunnel — otherwise the lone health
    # budget would race a still-installing box and false-flag inconclusive.
    local seed_ip
    seed_ip=$(echo "$targets" | jq -r '.seed_ip')
    if wait_for_cloud_init "ubuntu@${seed_ip}"; then
      # Reap any tunnel a previous (crashed) run leaked on this port — it would
      # otherwise win the bind and point the health probe at a destroyed box.
      pkill -f "ssh.* -L ${LOCAL_API_PORT}:localhost:21212 " 2>/dev/null || true
      # Foreground-backgrounded (not -f) so we keep the PID for teardown.
      # ExitOnForwardFailure makes ssh exit immediately if the local bind
      # fails, instead of staying up forwarding nothing for 300s of health.
      ssh -N -o ExitOnForwardFailure=yes "${SSH_OPTS[@]}" \
        -L "${LOCAL_API_PORT}:localhost:21212" "ubuntu@${seed_ip}" &
      SSH_TUNNEL_PID=$!
      base_url="http://localhost:${LOCAL_API_PORT}"
      # Give ssh a beat to bind (or die on a bad forward) before probing, so a
      # bind failure surfaces as a clear message rather than a health timeout.
      sleep 2
      if ! kill -0 "$SSH_TUNNEL_PID" 2>/dev/null; then
        echo "local-mode: SSH port-forward failed to start (is :${LOCAL_API_PORT} already in use?)" >&2
        SSH_TUNNEL_PID=""
        inconclusive=1
      else
        wait_for_health "$base_url" "$pat" || inconclusive=1
      fi
    else
      inconclusive=1
    fi
  fi

  # Stage the curated wasm standard modules before the suite runs. Terraform
  # only renders the SB_WASM_STANDARD_MODULES alias contract; the bytes are
  # normally staged by Ansible (which the harness never runs), and sandboxd does
  # not fetch them at boot. Without this every wasm create fails placement with
  # ErrNoPlacementTarget. Restarts sandboxd, so re-probe health afterwards.
  if [[ "$inconclusive" != "1" && "$caps_wasm" == "true" ]]; then
    echo "=== staging wasm standard modules on ${scenario} ==="
    if stage_wasm_modules "${HERE}/fixtures/wasm" "${overlay}/cluster.yml" "$caps_domain" "$targets"; then
      wait_for_health "$base_url" "$pat" || inconclusive=1
    else
      echo "scenario ${scenario}: wasm module staging failed" >&2
      inconclusive=1
    fi
  fi

  # Expected cluster size, if the scenario's caps.yml declares one. Drives
  # AEROL_EXPECTED_MEMBERS so the cluster UCs assert an exact node count.
  local expected_members
  expected_members=$(yq -r '.expected_members // ""' "$caps_file")

  # For wasm-capable scenarios the runtime UC references a staged standard
  # module by alias; default to python (override by exporting the env var).
  local wasm_ref=""
  [[ "$caps_wasm" == "true" ]] && wasm_ref="${AEROL_WASM_MODULE_REF:-python}"
  if [[ "$caps_wasm" == "true" ]] && is_stale_wasm_snapshot_ref "$wasm_ref"; then
    echo "scenario ${scenario}: ignoring stale snapshot image ref in AEROL_WASM_MODULE_REF=${wasm_ref}; using staged wasm module alias 'python'" >&2
    wasm_ref="python"
  fi

  mkdir -p "${HERE}/reports"
  # A successful run does not collect a failure-log artifact, so clear any
  # stale copy from an earlier failed attempt before this scenario starts.
  # Otherwise a green report can sit next to old red diagnostics and send the
  # operator chasing a fixed issue.
  rm -f "${HERE}/reports/${scenario}-failure-logs.txt"
  local json_out="${sdir}/test.json"
  if [[ "$inconclusive" == "1" ]]; then
    echo "scenario ${scenario}: infra not ready (spot reclaim / propagation) — marking inconclusive" >&2
    # Capture daemon logs before teardown nukes the box. local-mode runs no
    # Caddy (API bound on 127.0.0.1), so only sandboxd exists; domain scenarios
    # (single-node + cluster) front the API with Caddy, so grab both per node.
    collect_failure_logs "$scenario" "$caps_domain" "$targets" "$pat"
    : > "$json_out"
    AEROL_SCENARIO="$scenario" go run "${HERE}/report" -scenario "$scenario" -inconclusive \
      -json "$json_out" -out "${HERE}/reports"
    return 0
  fi

  echo "=== running suite against ${base_url} ==="
  local allow_disruptive
  allow_disruptive=$(allow_disruptive_for "$scenario")
  if [[ "$allow_disruptive" == "1" ]]; then
    echo "disruptive fault-injection tests enabled (UC-58b on cluster-hetero)" >&2
  fi
  # go test runs with cwd = the package dir (integration-tests/suite), so bench
  # artifact paths from the Makefile must be absolute or WriteFile lands under
  # suite/integration-tests/reports/... and fails with ENOENT.
  local bench_out="${AEROL_BENCH_OUT:-}"
  if [[ -n "$bench_out" && "$bench_out" != /* ]]; then
    bench_out="${REPO_ROOT}/${bench_out}"
  fi
  if [[ "${AEROL_BENCH:-}" == "1" ]]; then
    echo "benchmark enabled (UC-94/UC-95); artifact=${bench_out:-logs only}" >&2
    if [[ -n "$bench_out" ]]; then
      mkdir -p "$(dirname "$bench_out")"
      rm -f "$bench_out"
    fi
  fi
  set +e
  AEROL_BASE_URL="$base_url" AEROL_PAT="$pat" AEROL_SCENARIO="$scenario" \
    AEROL_CAPS="${caps_file}" \
    AEROL_DOMAIN="${leased}" \
    AEROL_EXPECTED_MEMBERS="${expected_members}" \
    AEROL_INTEGRATION_TARGETS="${targets}" \
    AEROL_ALLOW_DISRUPTIVE="${allow_disruptive}" \
    AEROL_BENCH="${AEROL_BENCH:-}" \
    AEROL_BENCH_OUT="${bench_out}" \
    AEROL_WASM_MODULE_REF="${wasm_ref}" \
    go test -tags=integration -count=1 -timeout=60m -json ./integration-tests/suite/... > "$json_out"
  local test_rc=$?
  set -e

  # On any suite failure, grab sandboxd + caddy logs from every node BEFORE the
  # EXIT trap tears the boxes down — otherwise a real test failure (as opposed
  # to infra-not-ready above) leaves nothing to debug. Mirrors the inconclusive
  # path's collection.
  if [[ "$test_rc" != "0" ]]; then
    collect_failure_logs "$scenario" "$caps_domain" "$targets" "$pat"
  fi

  AEROL_SCENARIO="$scenario" go run "${HERE}/report" -scenario "$scenario" \
    -json "$json_out" -out "${HERE}/reports"
  if [[ "${AEROL_BENCH:-}" == "1" && -n "$bench_out" ]]; then
    print_bench_artifact_summary "$bench_out"
  fi
}

# collect_failure_logs dumps sandboxd + caddy journals/status from every node
# (domain scenarios) or the seed node (IP/local scenarios) into
# reports/<scenario>-failure-logs.txt. Shared by the inconclusive path and the
# suite-failure path so both produce the same artifact.
#
# A cluster that never forms is the hardest failure to debug, and the old
# collector made it nearly impossible: it dumped bare IPs with no hint which
# was the seed/server tier (where gossip + Raft live), and it skipped the seed
# entirely if it wasn't in the nodes[] list. So a hetero-cluster bring-up that
# produced one isolated worker yielded a report of one anonymous node spinning
# "no live server-role control-plane members" with nothing to point at. Now we
# lead with a roster (so "only N of the expected nodes exist" is obvious at a
# glance), label every dump with name+role+seed, always include the seed, dedupe
# by IP, and snapshot each node's own /v1/cluster/members + leader view so a
# split (each node an island) is visible per-node.
collect_failure_logs() {
  local scenario="$1" caps_domain="$2" targets="$3" pat="${4:-}"
  local logfile="${HERE}/reports/${scenario}-failure-logs.txt"
  echo "collecting failure logs -> ${logfile}" >&2
  {
    echo "### failure logs for scenario ${scenario} ($(date -u +%FT%TZ)) ###"

    # Roster first: how many nodes terraform actually produced, and which role
    # each plays. If this shows fewer rows than the scenario expects, the
    # failure is bring-up (partial apply / quota), not cluster logic.
    echo "--- node roster (name / role / seed / public_ip / private_ip) ---"
    echo "$targets" | jq -r '
      (.nodes // [])
      | map([.name, .role, (if .seed then "SEED" else "-" end), .public_ip, .private_ip] | join("\t"))
      | if length == 0 then "(no nodes in integration_targets output)" else .[] end'

    # The seed's PRIVATE IP is what every joiner was told to gossip to
    # (--peers <seed-private-ip>:7001 in the bootstrap template), so it is the
    # right target for each node's reachability probe.
    local seed_ip seed_private_ip
    seed_ip=$(echo "$targets" | jq -r '.seed_ip // empty')
    seed_private_ip=$(echo "$targets" | jq -r --arg s "$seed_ip" '
      ((.nodes // []) | map(select(.public_ip == $s)) | .[0].private_ip) // empty')

    if [[ "$caps_domain" == "true" ]]; then
      # Build a deduped IP list, always including the seed_ip even if it is not
      # present in nodes[] (a partial apply can drop it from the per-node list
      # while seed_ip still resolves). Carry a "name (role)" label per IP.
      declare -A seen=()
      while IFS=$'\t' read -r ip label; do
        [[ -n "$ip" && "$ip" != "null" ]] || continue
        [[ -n "${seen[$ip]:-}" ]] && continue
        seen[$ip]=1
        dump_node_diagnostics "ubuntu@${ip}" "$seed_private_ip" "$label"
        dump_cluster_membership "ubuntu@${ip}" "$pat" "$label"
        dump_service_logs "ubuntu@${ip}" sandboxd 500
        dump_service_logs "ubuntu@${ip}" caddy
      done < <(
        echo "$targets" | jq -r '
          (.nodes // [])[]
          | [.public_ip, ((.name // "?") + " (" + (.role // "?") + (if .seed then ",seed" else "" end) + ")")]
          | @tsv'
        [[ -n "$seed_ip" ]] && printf '%s\t%s\n' "$seed_ip" "seed_ip (fallback)"
      )
    else
      dump_node_diagnostics "ubuntu@${seed_ip}" "$seed_private_ip" "seed"
      dump_cluster_membership "ubuntu@${seed_ip}" "$pat" "seed"
      dump_service_logs "ubuntu@${seed_ip}" sandboxd 500
    fi
  } > "$logfile" 2>&1
}

# collect_logs_only reads an already-applied scenario's TF state and dumps the
# full per-node forensics without provisioning or tearing anything down. Pairs
# with a prior `run.sh <scenario> --keep`: bring the cluster up once, then pull
# logs as many times as you need while you debug.
collect_logs_only() {
  local scenario="$1"
  local sdir="${REPO_ROOT}/integration-tests/.tf/${scenario}"
  local caps_file="${HERE}/scenarios/${scenario}.caps.yml"
  if [[ ! -d "$sdir" ]]; then
    echo "no TF state at ${sdir} — run 'run.sh ${scenario} --keep' first" >&2
    exit 2
  fi
  local targets pat caps_domain
  targets=$(TF_DATA_DIR="$sdir" terraform -chdir="${REPO_ROOT}/Terraform" output -json integration_targets 2>/dev/null) \
    || { echo "could not read integration_targets from ${sdir} — is the cluster still up?" >&2; exit 2; }
  pat=$(yq -r '.cluster.pat_token' "${REPO_ROOT}/config/secrets.yml")
  caps_domain=$(yq -r '.capabilities | contains(["domain"])' "$caps_file" 2>/dev/null || echo true)
  mkdir -p "${HERE}/reports"
  collect_failure_logs "$scenario" "$caps_domain" "$targets" "$pat"
  echo "logs written to ${HERE}/reports/${scenario}-failure-logs.txt" >&2
}

# run_bench_only re-runs UC-94/UC-95 against an already-provisioned scenario
# (brought up with --keep). Loads API URL + domain from TF state so the operator
# does not have to hand-export AEROL_BASE_URL / AEROL_CAPS / AEROL_PAT.
run_bench_only() {
  local scenario="$1"
  local sdir="${REPO_ROOT}/integration-tests/.tf/${scenario}"
  local caps_file="${HERE}/scenarios/${scenario}.caps.yml"
  if [[ ! -d "$sdir" ]]; then
    echo "no TF state at ${sdir} — run 'make integration-${scenario} keep' (or integration-benchmark keep) first" >&2
    exit 2
  fi
  if [[ ! -f "$caps_file" ]]; then
    echo "scenario ${scenario}: missing ${caps_file}" >&2
    exit 2
  fi

  local targets pat base_url leased
  targets=$(TF_DATA_DIR="$sdir" terraform -chdir="${REPO_ROOT}/Terraform" output -json integration_targets 2>/dev/null) \
    || { echo "could not read integration_targets from ${sdir} — is the cluster still up?" >&2; exit 2; }
  pat=$(yq -r '.cluster.pat_token' "${REPO_ROOT}/config/secrets.yml")
  base_url=$(echo "$targets" | jq -r '.base_url // empty')
  leased=$(echo "$targets" | jq -r '.domain // empty')
  if [[ -z "$base_url" ]]; then
    echo "integration_targets has no base_url — is this a local-mode scenario?" >&2
    exit 2
  fi

  local caps_wasm expected_members
  caps_wasm=$(yq -r '.capabilities | contains(["wasm"])' "$caps_file")
  expected_members=$(yq -r '.expected_members // ""' "$caps_file")
  local wasm_ref=""
  [[ "$caps_wasm" == "true" ]] && wasm_ref="${AEROL_WASM_MODULE_REF:-python}"
  if [[ "$caps_wasm" == "true" ]] && is_stale_wasm_snapshot_ref "$wasm_ref"; then
    wasm_ref="python"
  fi

  local bench_out="${AEROL_BENCH_OUT:-integration-tests/reports/${scenario}-bench.json}"
  if [[ "$bench_out" != /* ]]; then
    bench_out="${REPO_ROOT}/${bench_out}"
  fi
  mkdir -p "$(dirname "$bench_out")" "${HERE}/reports"
  rm -f "$bench_out"

  echo "=== bench-only against ${base_url} (artifact=${bench_out}) ===" >&2
  if ! wait_for_health "$base_url" "$pat"; then
    echo "scenario ${scenario}: API not healthy at ${base_url}" >&2
    exit 2
  fi

  set +e
  AEROL_BENCH=1 \
  AEROL_BENCH_OUT="${bench_out}" \
  AEROL_BASE_URL="$base_url" \
  AEROL_PAT="$pat" \
  AEROL_SCENARIO="$scenario" \
  AEROL_CAPS="${caps_file}" \
  AEROL_DOMAIN="${leased}" \
  AEROL_EXPECTED_MEMBERS="${expected_members}" \
  AEROL_WASM_MODULE_REF="${wasm_ref}" \
    go test -tags=integration -count=1 -timeout=60m -v \
      -run 'TestBench' \
      ./integration-tests/suite/...
  local test_rc=$?
  set -e
  if [[ "$test_rc" != "0" ]]; then
    exit "$test_rc"
  fi
  if [[ -f "$bench_out" ]]; then
    echo "bench artifact: ${bench_out}" >&2
    print_bench_artifact_summary "$bench_out"
  else
    echo "bench tests finished but artifact missing at ${bench_out}" >&2
    exit 2
  fi
}

if [[ "$COLLECT_LOGS_ONLY" == "1" ]]; then
  collect_logs_only "$SCENARIO"
elif [[ "$BENCH_ONLY" == "1" ]]; then
  run_bench_only "$SCENARIO"
elif [[ "$SCENARIO" == "all" ]]; then
  for s in local-mode single-node single-node-wasm cluster-3-mixed cluster-3-mixed-wasm cluster-hetero single-node-fc single-node-fc-arm64 cluster-arm64; do
    ( run_one "$s" )
  done
else
  run_one "$SCENARIO"
fi

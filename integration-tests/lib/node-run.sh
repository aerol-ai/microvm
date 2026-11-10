#!/usr/bin/env bash
# node-run.sh — helpers for driving a scenario kept up with `run.sh --keep`
# from its own nodes: scripts/run-on-node.sh (run suite tests inside the VPC)
# and scripts/routing-ab.sh (flip SB_INGRESS_PROXY_ROUTING on every node).
# Sourced, not executed, after lib/common.sh (SSH_OPTS and friends).
#
# Pure helpers (no SSH, no terraform) are kept apart from the callers so the
# offline tests in integration-tests/safety can exercise them with fixtures.

# kept_targets <repo_root> <scenario>
# Prints the scenario's Terraform integration_targets JSON. An exported
# AEROL_INTEGRATION_TARGETS wins: it is how a stack kept from another
# worktree is reached (copy that worktree's targets), and how the offline
# tests run without terraform.
kept_targets() {
  local root="$1" scenario="$2" sdir
  if [[ -n "${AEROL_INTEGRATION_TARGETS:-}" ]]; then
    printf '%s\n' "$AEROL_INTEGRATION_TARGETS"
    return 0
  fi
  sdir="${root}/integration-tests/.tf/${scenario}"
  if [[ ! -d "$sdir" ]]; then
    echo "no TF state at ${sdir}: bring the scenario up from this worktree with 'integration-tests/run.sh ${scenario} --keep' first" >&2
    return 2
  fi
  TF_DATA_DIR="$sdir" terraform -chdir="${root}/Terraform" output -json integration_targets 2>/dev/null \
    || { echo "could not read integration_targets from ${sdir}: is the stack still up?" >&2; return 2; }
}

# nodes_seed_first <targets_json>
# One line per node: name, role (spaces removed), seed|-, public IP. The seed
# comes first: every cluster-wide restart in this harness is seed-first,
# because joiners restarted while the seed is down have no one to rejoin
# (harness.WithClusterEnv has the live incident).
# A blank node (nodes[].blank) is plain Ubuntu that has not joined, so it
# is left out here and below: there is no sandboxd on it to restart or run
# from.
nodes_seed_first() {
  jq -r '(.nodes // []) | map(select(.blank != true)) | (map(select(.seed == true)) + map(select(.seed != true)))[]
    | [.name, ((.role // "") | gsub(" "; "")), (if .seed == true then "seed" else "-" end), (.public_ip // "")]
    | @tsv' <<<"$1"
}

# pick_gate_node <targets_json> [name]
# Prints "name<TAB>public_ip" of the node to run the suite from. With a name,
# that node. Without one, a server-only node: a Raft voter that serves no
# sandbox and is not behind the domain's A records, so the load generator
# neither competes with the sandboxes it measures nor shortcuts the public
# path. A non-seed server is preferred because the seed also mints the
# suite's token and answers the harness's own checks.
pick_gate_node() {
  local targets="$1" want="${2:-}" row
  if [[ -n "$want" ]]; then
    row=$(jq -r --arg n "$want" '(.nodes // [])[] | select(.name == $n) | [.name, (.public_ip // "")] | @tsv' <<<"$targets" | head -n 1)
    if [[ -z "$row" ]]; then
      echo "node ${want} is not in this scenario (nodes: $(jq -r '[(.nodes // [])[].name] | join(", ")' <<<"$targets"))" >&2
      return 2
    fi
  else
    row=$(jq -r '(.nodes // [])
      | map(select(.blank != true))
      | map(select(((.role // "") | gsub(" "; "")) == "server"))
      | (map(select(.seed != true)) + map(select(.seed == true)))
      | first // empty
      | [.name, (.public_ip // "")] | @tsv' <<<"$targets")
    if [[ -z "$row" ]]; then
      echo "this scenario has no server-only node (every node serves sandboxes or ingress); pick one with --node <name>" >&2
      return 2
    fi
  fi
  if [[ -z "${row#*$'\t'}" ]]; then
    echo "node ${row%%$'\t'*} has no public IP to reach over SSH" >&2
    return 2
  fi
  printf '%s\n' "$row"
}

# goarch_for <uname -m output>
goarch_for() {
  case "$1" in
    x86_64 | amd64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *)
      echo "unsupported node architecture: ${1:-<empty>}" >&2
      return 2
      ;;
  esac
}

# write_env_file <file> NAME VALUE [NAME VALUE ...]
# A file bash can source, every value %q-quoted: the targets JSON is full of
# quotes, and a token must reach the node in a file, never in a remote argv
# that `ps` and the sudo log would show (mint_suite_token says the same).
write_env_file() {
  local file="$1"
  shift
  (umask 077 && : >"$file")
  while (($# >= 2)); do
    printf '%s=%q\n' "$1" "$2" >>"$file"
    shift 2
  done
}

# aerol_passthrough_names <name-to-skip>...
# The exported AEROL_* variables the operator set that the caller does not
# set itself, one per line: a use case's tuning knobs (AEROL_OVERLOAD_*,
# AEROL_FAIRNESS_*, ...) then reach the node as they would reach a laptop
# run. The local-only ones are never passed: a laptop key path or the pinned
# run.sh copy mean nothing on the node.
aerol_passthrough_names() {
  local name skip
  local -a skips=("$@" AEROL_SSH_IDENTITY_FILE AEROL_RUNSH_PINNED)
  while IFS= read -r name; do
    [[ "$name" == AEROL_* ]] || continue
    for skip in "${skips[@]}"; do
      [[ "$name" == "$skip" ]] && continue 2
    done
    printf '%s\n' "$name"
  done < <(compgen -e | LC_ALL=C sort)
}

###############################################################################
# Routing A/B (scripts/routing-ab.sh)
###############################################################################

# The A/B override is a drop-in of its own, never an edit to sandboxd.env or
# cluster.env, for the reason harness.applyNodeEnvOverride gives: restoring
# is a file delete, which cannot half-succeed. "zz-ab-" sorts after
# cluster-init's cluster.conf, so it wins over the installed value, and
# before the suite's zz-itest-override.conf, so a case that sets its own
# override still wins over the A/B.
AB_ROUTING_ENV_FILE="/etc/sandboxd/ab-routing.env"
AB_ROUTING_DROPIN="/etc/systemd/system/sandboxd.service.d/zz-ab-routing.conf"

# ab_apply_script <off|on>
# The remote script that sets the override (off) or removes it (on). "on"
# is "back to what the node was installed with", which on a routing scenario
# is the flag on; ab_node_settled then proves the node really engaged.
ab_apply_script() {
  case "$1" in
    off)
      cat <<EOF
set -e
sudo install -d -m 0755 /etc/systemd/system/sandboxd.service.d
printf '%s\n' '# Routing A/B override (integration-tests/scripts/routing-ab.sh). Remove with: routing-ab.sh <scenario> on' 'SB_INGRESS_PROXY_ROUTING=false' | sudo tee ${AB_ROUTING_ENV_FILE} >/dev/null
printf '%s\n' '[Service]' 'EnvironmentFile=${AB_ROUTING_ENV_FILE}' | sudo tee ${AB_ROUTING_DROPIN} >/dev/null
sudo systemctl daemon-reload
EOF
      ;;
    on)
      cat <<EOF
set -e
sudo rm -f ${AB_ROUTING_DROPIN} ${AB_ROUTING_ENV_FILE}
sudo systemctl daemon-reload
EOF
      ;;
    *)
      echo "ab_apply_script: want off or on, got ${1:-<empty>}" >&2
      return 2
      ;;
  esac
}

# ab_probe_script
# The remote script that reports a node's routing state as key=value lines:
#   override      present|absent  the A/B drop-in
#   configured    the SB_INGRESS_PROXY_ROUTING the unit will see
#   marker        true|false|none ingress_proxy_routing_last_enabled, which
#                 the daemon writes true when it engages and false after a
#                 completed rollback (pkg/daemon/ingress_routing_wiring.go)
#   static_route  yes|no|unknown  Caddy holds the static "sandbox-ingress-
#                 proxy" route, i.e. the engage was committed
#   active        systemctl is-active sandboxd
ab_probe_script() {
  cat <<'EOF'
if [ -f /etc/systemd/system/sandboxd.service.d/zz-ab-routing.conf ]; then echo override=present; else echo override=absent; fi
vals=$(sudo bash -c 'for f in /etc/sandboxd/sandboxd.env /etc/sandboxd/cluster.env /etc/sandboxd/ab-routing.env /etc/sandboxd/itest-override.env; do [ -f "$f" ] && . "$f"; done; printf "%s %s" "${SB_INGRESS_PROXY_ROUTING:-unset}" "${SB_DB_PATH:-/var/lib/sandboxd/state.db}"' 2>/dev/null)
echo "configured=${vals%% *}"
m=$(sudo cat "$(dirname "${vals#* }")/ingress_proxy_routing_last_enabled" 2>/dev/null | tr -d '[:space:]')
echo "marker=${m:-none}"
if cfg=$(curl -fsS -m 5 http://127.0.0.1:2019/config/ 2>/dev/null); then
  case "$cfg" in *'"sandbox-ingress-proxy"'*) echo static_route=yes ;; *) echo static_route=no ;; esac
else
  echo static_route=unknown
fi
echo "active=$(systemctl is-active sandboxd 2>/dev/null || true)"
EOF
}

# probe_value <probe_output> <key>
probe_value() {
  sed -n "s/^${2}=//p" <<<"$1" | tail -n 1
}

# ab_node_settled <role> <off|on> <probe_output>
# True when the node is where the A/B wants it. A pure server never routes
# (the daemon returns before engaging), so only its override is checked. A
# routing node is settled off when it has the override, no static route and
# no "true" marker (rolled back, or never engaged), and settled on when it
# has no override, the marker says it engaged and Caddy holds the static
# route (the commit happened).
ab_node_settled() {
  local role="$1" want="$2" probe="$3"
  local override marker static
  override=$(probe_value "$probe" override)
  marker=$(probe_value "$probe" marker)
  static=$(probe_value "$probe" static_route)
  case "$want" in
    off)
      [[ "$override" == present ]] || return 1
      [[ "$role" == server ]] && return 0
      [[ "$marker" != true && "$static" == no ]]
      ;;
    on)
      [[ "$override" == absent ]] || return 1
      [[ "$role" == server ]] && return 0
      [[ "$marker" == true && "$static" == yes ]]
      ;;
    *) return 2 ;;
  esac
}

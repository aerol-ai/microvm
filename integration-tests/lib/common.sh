#!/usr/bin/env bash
# common.sh — readiness helpers shared by run.sh. Sourced, not executed.
#
# All waits are bounded with backoff so slow DNS/TLS propagation produces a
# clear timeout, never a hang and never a false "ready".

# SSH_OPTS — shared non-interactive options for every harness SSH call. No host
# key prompts (throwaway boxes) and a short connect timeout so a not-yet-booted
# instance fails fast into the retry loop instead of hanging ~2 minutes on the
# kernel TCP timeout.
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=10 -o BatchMode=yes)

# wait_for_cloud_init <ssh_target> [timeout_s]
# Blocks until the instance's user-data (cloud-init) has finished. Domain
# scenarios get this slack for free from the DNS+TLS waits that run before the
# health probe; local-mode has neither, so without this the single health
# budget starts the moment `terraform apply` returns — which is when the
# instance reaches "running", well before apt/sandboxd-download/docker/daemon
# start finish. `cloud-init status --wait` is the canonical "box is ready"
# signal: it blocks server-side until user-data completes, then exits non-zero
# iff user-data errored (which we surface rather than racing the daemon).
wait_for_cloud_init() {
  local target="$1" timeout="${2:-600}"
  local deadline=$(( $(date +%s) + timeout ))
  # Outer loop: tolerate the window where sshd itself isn't up yet. Each
  # attempt blocks in `--wait`, so a single success ends it.
  while (( $(date +%s) < deadline )); do
    local out rc
    out=$(ssh "${SSH_OPTS[@]}" "$target" 'sudo cloud-init status --wait' 2>&1)
    rc=$?
    if (( rc == 0 )); then
      echo "cloud-init: ${target} done"
      return 0
    fi
    # rc 2 == cloud-init finished with a recoverable warning ("degraded done");
    # the daemon may still be fine, so treat it as ready but note it.
    if grep -q 'status: done' <<<"$out"; then
      echo "cloud-init: ${target} done (with warnings)"
      return 0
    fi
    sleep 10
  done
  echo "cloud-init: ${target} did not finish after ${timeout}s" >&2
  return 1
}

# dump_service_logs <ssh_target> <service> [lines]
# Best-effort dump of a systemd unit's STATE + journal from a remote node. The
# journal alone doesn't answer "is the app actually running?" — a unit can be
# crash-looping (active=activating, restart-counting), dead after exhausting its
# restart budget, or never installed. So we lead with is-active / is-enabled and
# the `systemctl status` header (load/active/sub state, main PID, last exit
# code, NRestarts) before the log tail, then probe whether anything is listening
# on the API port. Never fails the caller — this runs on the already-broken
# inconclusive path, so a node we can't SSH into (spot reclaim) must not mask the
# original problem.
dump_service_logs() {
  local target="$1" svc="$2" lines="${3:-200}"
  echo "===== ${svc} @ ${target} ====="
  if ! ssh -n "${SSH_OPTS[@]}" "$target" "
      echo '--- is-active / is-enabled ---'
      systemctl is-active ${svc}; systemctl is-enabled ${svc} 2>/dev/null || true
      echo '--- systemctl status (state, main PID, last exit, restarts) ---'
      sudo systemctl status ${svc} --no-pager -n 0 || true
      echo '--- listeners on :21212 (is the API actually bound?) ---'
      sudo ss -ltnp 2>/dev/null | grep -E ':21212\b' || echo '(nothing listening on 21212)'
      if [[ '${svc}' == sandboxd ]]; then
        echo '--- cluster/gossip/raft events (FULL boot journal, grepped) ---'
        # The steady-state tail below loses the boot-time gossip/raft/memberlist
        # handshake — exactly the lines that explain a stuck join. Pull them from
        # the whole current-boot journal (-b) so they survive regardless of age.
        sudo journalctl -u ${svc} -b --no-pager 2>/dev/null \
          | grep -iE 'cluster|gossip|memberlist|serf|raft|swim|join|leav|voter|leader|peer|bootstrap|secret|encrypt|decrypt|mtls|handshake|advertise|bind' \
          | grep -ivE 'request complete|drain-state lookup|placements lookup' \
          || echo '(no cluster/gossip/raft lines in boot journal)'
      fi
      echo '--- journal (last ${lines} lines) ---'
      sudo journalctl -u ${svc} --no-pager -n ${lines}
    " 2>&1; then
    echo "(could not reach ${target} or unit ${svc} absent)"
  fi
  echo "===== end ${svc} @ ${target} ====="
}

# dump_cluster_membership <ssh_target> <pat> [label]
# Snapshot what ONE node believes the cluster looks like, hit on its own
# loopback API (127.0.0.1:21212) so the answer is that node's local view rather
# than whatever the ingress/LB happens to route to. Prints the member list and
# the current Raft leader. The whole point on a failed bring-up is to see a
# split: if every node reports members=1 and no leader, gossip never converged
# and the control-plane tier is unreachable (firewall, key mismatch, or the
# seed/server nodes never came up). Never fails the caller — best-effort, runs
# on the already-broken path next to dump_service_logs.
dump_cluster_membership() {
  local target="$1" pat="$2" label="${3:-}"
  echo "===== cluster view @ ${target} ${label:+(${label})} ====="
  if ! ssh -n "${SSH_OPTS[@]}" "$target" "
      auth=''
      [[ -n '${pat}' ]] && auth='-H \"Authorization: Bearer ${pat}\"'
      echo '--- /v1/cluster/members (this node'\''s local view) ---'
      eval curl -s --max-time 5 \$auth http://127.0.0.1:21212/v1/cluster/members | jq . 2>/dev/null \
        || echo '(members query failed — API down or not in cluster mode)'
      echo '--- /v1/cluster/leader ---'
      eval curl -s --max-time 5 \$auth http://127.0.0.1:21212/v1/cluster/leader | jq . 2>/dev/null \
        || echo '(leader query failed)'
    " 2>&1; then
    echo "(could not reach ${target})"
  fi
  echo "===== end cluster view @ ${target} ====="
}

# dump_node_diagnostics <ssh_target> [seed_private_ip] [label]
# Deep per-node forensics for a cluster that won't form. The journal alone never
# explains a failed JOIN, because the join happens in user-data long before
# sandboxd's own logs: the bootstrap template runs cluster-init.sh (seed) or
# polls S3 for the seed's gossip key + TLS bundle and runs cluster-join.sh
# (joiner), all teed to /var/log/aerolvm-bootstrap.log. This grabs that file
# plus the rendered cluster.env (peers / role / bind+advertise addrs — secrets
# redacted), the actual listening sockets on the raft/gossip/API ports, and a
# live TCP reachability probe from this node to the seed's raft (7000) and
# gossip-tcp (7001) ports. Together those answer the three real questions:
# did the join script run and succeed? is the daemon bound on the cluster
# ports? and can this node even reach the seed across the security group?
# Best-effort: never fails the caller (runs on the already-broken path).
dump_node_diagnostics() {
  local target="$1" seed_private_ip="${2:-}" label="${3:-}"
  echo "===== node diagnostics @ ${target} ${label:+(${label})} ====="
  if ! ssh -n "${SSH_OPTS[@]}" "$target" "
      echo '--- identity (hostname / role tag / ip / routes) ---'
      hostname; echo
      ip -4 -o addr show scope global 2>/dev/null || true
      echo
      echo '--- bootstrap + cluster-init/join log (/var/log/aerolvm-bootstrap.log) ---'
      sudo cat /var/log/aerolvm-bootstrap.log 2>/dev/null || echo '(no bootstrap log — user-data may not have run)'
      echo
      echo '--- cloud-init tail (/var/log/cloud-init-output.log, last 120) ---'
      sudo tail -n 120 /var/log/cloud-init-output.log 2>/dev/null || echo '(no cloud-init-output.log)'
      echo
      echo '--- cloud-init status ---'
      sudo cloud-init status --long 2>/dev/null || true
      echo
      echo '--- rendered cluster config (/etc/sandboxd/cluster.env, secrets redacted) ---'
      if sudo test -f /etc/sandboxd/cluster.env; then
        sudo sed -E 's/^(SB_GOSSIP_SECRET_KEY|SB_CREDENTIAL_ENCRYPTION_KEY)=.*/\1=<redacted>/' /etc/sandboxd/cluster.env
      else
        echo '(no cluster.env — this node never ran cluster-init/join; it is NOT in cluster mode)'
      fi
      echo
      echo '--- listeners on cluster ports (7000 raft / 7001 gossip / 7002 mTLS / 21212 api) ---'
      sudo ss -ltnup 2>/dev/null | grep -E ':(7000|7001|7002|21212)\b' || echo '(nothing listening on cluster ports)'
      echo
      echo '--- reachability probe to seed (${seed_private_ip}) ---'
      if [[ -n '${seed_private_ip}' ]]; then
        for port in 7000 7001; do
          if timeout 3 bash -c \"echo > /dev/tcp/${seed_private_ip}/\$port\" 2>/dev/null; then
            echo \"  seed ${seed_private_ip}:\$port  OPEN\"
          else
            echo \"  seed ${seed_private_ip}:\$port  UNREACHABLE (security group / seed down / not bound)\"
          fi
        done
      else
        echo '  (seed private IP unknown — skipping probe)'
      fi
    " 2>&1; then
    echo "(could not reach ${target})"
  fi
  echo "===== end node diagnostics @ ${target} ====="
}

# stage_wasm_modules <fixtures_dir> <config_cluster_yml> <caps_domain> <targets_json>
# Copies the curated standard .wasm modules onto every node's modules_dir under
# their reserved alias filename, then restarts sandboxd. Returns non-zero on any
# failure so the caller can mark the scenario inconclusive.
#
# WHY this exists: the harness provisions with Terraform ONLY (never Ansible).
# Terraform flattens wasm.standard_modules to the "alias=alias.wasm" contract
# (SB_WASM_STANDARD_MODULES) but does NOT stage the bytes — that is Ansible's
# playbooks/stage-wasm-modules.yml. sandboxd's seedStandardModules resolves each
# alias to a PRE-STAGED local file and does not fetch URL-sourced modules at
# boot. So without this step modules_dir is empty, the node advertises no wasm
# inventory, and cluster placement (every scenario runs cluster-init, so even
# single-node is a 1-member real cluster) rejects each wasm create with
# ErrNoPlacementTarget. This mirrors what stage-wasm-modules.yml does, but reuses
# the committed, digest-verified fixture bytes instead of re-downloading on-box.
stage_wasm_modules() {
  local fxdir="$1" config_cluster="$2" caps_domain="$3" targets="$4"
  local modules_dir
  modules_dir=$(yq -r '.wasm.modules_dir // "/var/lib/sandboxd/wasm/modules"' "$config_cluster")

  # Ensure the (gitignored) fixture bytes exist + match their pinned sha256.
  if ! bash "${fxdir}/fetch.sh"; then
    echo "stage_wasm: fetching fixture modules failed" >&2
    return 1
  fi

  # Resolve the per-node IP set. Domain scenarios only stage worker-capable
  # nodes: pure ingress/server roles do not own sandboxes, and restarting them
  # for module staging can destabilize health/gossip during bootstrap.
  local ips=()
  if [[ "$caps_domain" == "true" ]]; then
    while IFS= read -r ip; do [[ -n "$ip" ]] && ips+=("$ip"); done \
      < <(echo "$targets" | jq -r '
        .nodes[]
        | select(
            ((.role // "mixed") | ascii_downcase | split(",") | map(gsub("^\\s+|\\s+$"; ""))) as $roles
            | ($roles | any(. == "worker" or . == "mixed"))
          )
        | .public_ip
      ')
  else
    ips+=("$(echo "$targets" | jq -r '.seed_ip')")
  fi
  [[ "${#ips[@]}" -gt 0 ]] || { echo "stage_wasm: no worker-capable node IPs in targets" >&2; return 1; }

  local n
  n=$(yq -r '.standard_modules | length' "${fxdir}/modules.yml")
  [[ "$n" =~ ^[0-9]+$ && "$n" -gt 0 ]] || { echo "stage_wasm: no modules in ${fxdir}/modules.yml" >&2; return 1; }

  local ip tgt i alias ref file
  for ip in "${ips[@]}"; do
    tgt="ubuntu@${ip}"
    # Block until THIS node's user-data finished before touching its sandboxd.
    # The domain branch only waits on DNS/TLS/health, which proves the SEED
    # answers (Caddy fronts the API) — a joiner can still be mid-bootstrap here.
    # install.sh writes+enables the sandboxd unit late, so a restart that races
    # it fails "Unit sandboxd.service not found" and aborts the whole scenario
    # as inconclusive. cloud-init status --wait is idempotent and returns at
    # once on an already-finished box, so this only costs time on the real race.
    if ! wait_for_cloud_init "$tgt"; then
      echo "stage_wasm: ${tgt} cloud-init did not finish" >&2
      return 1
    fi
    if ! ssh "${SSH_OPTS[@]}" "$tgt" "sudo mkdir -p '${modules_dir}'"; then
      echo "stage_wasm: mkdir ${modules_dir} on ${tgt} failed" >&2
      return 1
    fi
    for i in $(seq 0 $((n - 1))); do
      alias=$(yq -r ".standard_modules[$i].alias" "${fxdir}/modules.yml")
      ref=$(yq -r ".standard_modules[$i].ref" "${fxdir}/modules.yml")
      # fetch.sh names each local file after the URL basename (sans query).
      file="${fxdir}/$(basename "${ref%\?*}")"
      # ubuntu can't write modules_dir directly; land in /tmp then sudo-install
      # under the reserved alias filename SB_WASM_STANDARD_MODULES expects.
      if ! scp "${SSH_OPTS[@]}" "$file" "${tgt}:/tmp/${alias}.wasm" \
        || ! ssh "${SSH_OPTS[@]}" "$tgt" \
             "sudo install -m 0644 '/tmp/${alias}.wasm' '${modules_dir}/${alias}.wasm' && rm -f '/tmp/${alias}.wasm'"; then
        echo "stage_wasm: staging ${alias} on ${tgt} failed" >&2
        return 1
      fi
    done
    # sandboxd seeds standard modules only at boot, so restart to pick up the
    # now-staged files and re-advertise the node's wasm inventory to placement.
    if ! ssh "${SSH_OPTS[@]}" "$tgt" "sudo systemctl restart sandboxd"; then
      echo "stage_wasm: restarting sandboxd on ${tgt} failed" >&2
      return 1
    fi
    echo "stage_wasm: ${tgt} staged ${n} modules + restarted sandboxd"
  done
}

# wait_for_health <base_url> <pat> [timeout_s]
# Polls /v1/capacity (authenticated) until HTTP 200 or timeout.
wait_for_health() {
  local base="$1" pat="$2" timeout="${3:-300}"
  local deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) < deadline )); do
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer ${pat}" "${base}/v1/capacity" || echo 000)
    if [[ "$code" == "200" ]]; then
      echo "health: ${base} ready"
      return 0
    fi
    sleep 5
  done
  echo "health: ${base} not ready after ${timeout}s" >&2
  return 1
}

# wait_for_dns <hostname> [timeout_s]
# Waits until the hostname resolves to at least one A record.
wait_for_dns() {
  local host="$1" timeout="${2:-300}"
  local deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) < deadline )); do
    if host "$host" >/dev/null 2>&1 || nslookup "$host" >/dev/null 2>&1; then
      echo "dns: ${host} resolves"
      return 0
    fi
    sleep 10
  done
  echo "dns: ${host} did not resolve after ${timeout}s" >&2
  return 1
}

# wait_for_tls <hostname> [timeout_s]
# Waits until a TLS handshake to :443 succeeds. With LE staging the chain is
# untrusted, so we don't verify here — the suite's UC-09 does chain validation
# against the pinned staging root.
wait_for_tls() {
  local host="$1" timeout="${2:-300}"
  local deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) < deadline )); do
    if echo | openssl s_client -connect "${host}:443" -servername "$host" >/dev/null 2>&1; then
      echo "tls: ${host} handshake ok"
      return 0
    fi
    sleep 10
  done
  echo "tls: ${host} handshake failed after ${timeout}s" >&2
  return 1
}

# wait_for_members <base_url> <pat> <expected> [timeout_s]
# Cluster scenarios: wait until /v1/cluster/members lists the expected count.
wait_for_members() {
  local base="$1" pat="$2" expected="$3" timeout="${4:-300}"
  local deadline=$(( $(date +%s) + timeout ))
  local last=0
  while (( $(date +%s) < deadline )); do
    local n
    n=$(curl -sS --max-time 10 -H "Authorization: Bearer ${pat}" "${base}/v1/cluster/members" 2>/dev/null \
      | jq -r 'if type == "array" then length else (.members // [] | length) end' 2>/dev/null || echo 0)
    last="$n"
    if [[ "$n" == "$expected" ]]; then
      echo "cluster: ${n} members"
      return 0
    fi
    sleep 5
  done
  echo "cluster: expected ${expected} members, never reached (last ${last})" >&2
  return 1
}

# wait_for_grafana <url> [timeout_s]
# Polls Grafana /api/health until HTTP 200 or timeout.
wait_for_grafana() {
  local url="$1" timeout="${2:-600}"
  local deadline=$(( $(date +%s) + timeout ))
  url="${url%/}"
  while (( $(date +%s) < deadline )); do
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' "${url}/api/health" || echo 000)
    if [[ "$code" == "200" ]]; then
      echo "grafana: ${url} ready"
      return 0
    fi
    sleep 10
  done
  echo "grafana: ${url} not ready after ${timeout}s" >&2
  return 1
}

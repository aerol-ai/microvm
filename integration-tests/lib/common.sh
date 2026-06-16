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
  if ! ssh "${SSH_OPTS[@]}" "$target" "
      echo '--- is-active / is-enabled ---'
      systemctl is-active ${svc}; systemctl is-enabled ${svc} 2>/dev/null || true
      echo '--- systemctl status (state, main PID, last exit, restarts) ---'
      sudo systemctl status ${svc} --no-pager -n 0 || true
      echo '--- listeners on :21212 (is the API actually bound?) ---'
      sudo ss -ltnp 2>/dev/null | grep -E ':21212\b' || echo '(nothing listening on 21212)'
      echo '--- journal (last ${lines} lines) ---'
      sudo journalctl -u ${svc} --no-pager -n ${lines}
    " 2>&1; then
    echo "(could not reach ${target} or unit ${svc} absent)"
  fi
  echo "===== end ${svc} @ ${target} ====="
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

  # Resolve the per-node IP set: domain scenarios stage every node so a sandbox
  # can be placed anywhere; IP/local scenarios have only the seed.
  local ips=()
  if [[ "$caps_domain" == "true" ]]; then
    while IFS= read -r ip; do [[ -n "$ip" ]] && ips+=("$ip"); done \
      < <(echo "$targets" | jq -r '.nodes[].public_ip')
  else
    ips+=("$(echo "$targets" | jq -r '.seed_ip')")
  fi
  [[ "${#ips[@]}" -gt 0 ]] || { echo "stage_wasm: no node IPs in targets" >&2; return 1; }

  local n
  n=$(yq -r '.standard_modules | length' "${fxdir}/modules.yml")
  [[ "$n" =~ ^[0-9]+$ && "$n" -gt 0 ]] || { echo "stage_wasm: no modules in ${fxdir}/modules.yml" >&2; return 1; }

  local ip tgt i alias ref file
  for ip in "${ips[@]}"; do
    tgt="ubuntu@${ip}"
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
  while (( $(date +%s) < deadline )); do
    local n
    n=$(curl -s -H "Authorization: Bearer ${pat}" "${base}/v1/cluster/members" \
      | jq 'length' 2>/dev/null || echo 0)
    if [[ "$n" == "$expected" ]]; then
      echo "cluster: ${n} members"
      return 0
    fi
    sleep 5
  done
  echo "cluster: expected ${expected} members, never reached" >&2
  return 1
}

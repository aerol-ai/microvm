#!/usr/bin/env bash
# common.sh — readiness helpers shared by run.sh. Sourced, not executed.
#
# All waits are bounded with backoff so slow DNS/TLS propagation produces a
# clear timeout, never a hang and never a false "ready".

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

# port-forward.sh: kubectl port-forwards that the bank run's scripts own for
# sure (eks-bank.sh, drills-eks.sh and drills-lib.sh source it).
# shellcheck shell=bash
#
# pf_start <var> <local port> <kubectl args...>
#   Runs kubectl <args> (a port-forward to <local port>) in the background
#   and puts kubectl's PID in <var>. It is kubectl itself (`command`), never
#   a shell function such as kc: a function sent to the background is a
#   subshell, so $! was that subshell, and killing it left kubectl running
#   and holding the port. In the fifth EKS run one gateway's forward
#   outlived its read, and the reads of the ten other gateways all got that
#   gateway's Caddy config.
#   Ready means kubectl said "Forwarding from 127.0.0.1:<port>", so it
#   listens. A fixed `sleep 3` was too short once: the gVisor check's
#   placement read got "connection refused".
#   Returns 1, with the reason in pf_error (and on stderr) and nothing left
#   running, when:
#     something already answers on the port (another process's forward; a
#     read through it would reach the wrong pod);
#     kubectl ends before it forwards;
#     it does not forward within PF_WAIT_SECONDS (30).
# pf_stop <pid>: TERM to that kubectl, then wait for it to end.
pf_error=""
pf_fail() { pf_error="$*"; echo "$pf_error" >&2; }
pf_start() {
  local _pf_var="$1" _pf_port="$2" _pf_log _pf_pid _pf_end
  shift 2
  pf_error=""
  if (: <>"/dev/tcp/127.0.0.1/$_pf_port") 2>/dev/null; then
    pf_fail "port-forward: something already answers on 127.0.0.1:$_pf_port (another process's forward); nothing read through it"
    return 1
  fi
  _pf_log="$(mktemp "${TMPDIR:-/tmp}/pf.XXXXXX")"
  command kubectl "$@" > "$_pf_log" 2>&1 &
  _pf_pid=$!
  _pf_end=$(( SECONDS + ${PF_WAIT_SECONDS:-30} ))
  while :; do
    if grep -q "^Forwarding from 127.0.0.1:$_pf_port " "$_pf_log"; then
      # kubectl keeps writing to the file it was given; it is only unlinked.
      rm -f "$_pf_log"
      printf -v "$_pf_var" '%s' "$_pf_pid"
      return 0
    fi
    if ! kill -0 "$_pf_pid" 2>/dev/null; then
      wait "$_pf_pid" 2>/dev/null || true
      pf_fail "port-forward to 127.0.0.1:$_pf_port: kubectl ended before it forwarded: $(tr '\n' ' ' < "$_pf_log" | cut -c1-240)"
      rm -f "$_pf_log"
      return 1
    fi
    if (( SECONDS >= _pf_end )); then
      pf_stop "$_pf_pid"
      pf_fail "port-forward to 127.0.0.1:$_pf_port: not forwarding after ${PF_WAIT_SECONDS:-30}s: $(tr '\n' ' ' < "$_pf_log" | cut -c1-240)"
      rm -f "$_pf_log"
      return 1
    fi
    command sleep 0.2
  done
}
pf_stop() {
  [[ -n "${1:-}" ]] || return 0
  kill -TERM "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}

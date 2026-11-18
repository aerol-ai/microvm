# helm-fetch.sh: fetch a Helm chart with a time limit, and without anyone's
# registry credentials. Sourced by cluster.sh, eks-bank.sh and drills-lib.sh.
#
# bank-1's third run (2026-11-18) waited 9.5 minutes on the Karpenter chart
# with the cluster billing. Helm looks up registry credentials even for a
# public OCI chart. On this laptop that means running Docker Desktop's
# credential helper (~/.docker/config.json, credsStore "desktop"), and after
# a Docker Desktop restart that helper never answered.
#
# - No credentials. Every chart the runs fetch is public: Karpenter
#   (oci://public.ecr.aws), the AWS Load Balancer Controller and
#   kube-prometheus-stack (HTTPS chart repositories). So each fetch runs
#   with DOCKER_CONFIG and HELM_REGISTRY_CONFIG pointed at a folder made for
#   that fetch, holding a config that names no helper and no store, removed
#   when the fetch ends. Not an empty folder: with no auth configured at
#   all, Helm's registry client looks for the platform's default helper
#   (docker-credential-osxkeychain on macOS) and runs that. One placeholder
#   entry for a host that cannot exist (RFC 2606 .invalid) turns that
#   lookup off; the real host then has no entry, and Helm pulls anonymously.
# - A time limit. HELM_FETCH_SECONDS (180) per fetch: past it, that Helm
#   process and its children are stopped by PID (TERM, then KILL: the
#   helper above ignored TERM), and the fetch fails naming the chart and the
#   limit. macOS has no timeout(1), so a watchdog subshell checks the PID
#   once a second.
# shellcheck shell=bash

helm_fetch_seconds="${HELM_FETCH_SECONDS:-180}"

# pid_tree <pid>: the PID and its descendants, deepest first.
pid_tree() {
  local kid
  for kid in $(pgrep -P "$1" 2>/dev/null || true); do pid_tree "$kid"; done
  echo "$1"
}

# stop_pid_tree <pid>: TERM the PID and its descendants, then KILL whichever
# of them is still there 2 s later.
stop_pid_tree() {
  local pids p
  pids="$(pid_tree "$1")"
  for p in $pids; do kill -TERM "$p" 2>/dev/null || true; done
  sleep 2
  for p in $pids; do
    if kill -0 "$p" 2>/dev/null; then kill -KILL "$p" 2>/dev/null || true; fi
  done
  return 0
}

# run_bounded <seconds> <cmd...>: runs cmd. Past <seconds> it stops cmd and
# its children and returns 124 (timeout(1)'s code); otherwise cmd's status.
run_bounded() {
  local limit="$1"; shift
  local mark rc=0
  mark="$(mktemp -d "${TMPDIR:-/tmp}/aerolvm-bound.XXXXXX")"
  "$@" &
  local pid=$!
  (
    n=0
    while kill -0 "$pid" 2>/dev/null; do
      if (( n >= limit )); then
        : > "$mark/fired"
        stop_pid_tree "$pid"
        exit 0
      fi
      sleep 1
      n=$((n + 1))
    done
  ) </dev/null >/dev/null 2>&1 &
  local dog=$!
  wait "$pid" || rc=$?
  wait "$dog" 2>/dev/null || true
  if [[ -e "$mark/fired" ]]; then
    rc=124
  fi
  rm -rf "$mark"
  return "$rc"
}

# helm_fetch <helm> <dest dir> <what> <helm pull args...>: helm pull into
# <dest dir>, with no credentials and within helm_fetch_seconds. <what>
# names the chart in the failure message.
helm_fetch() {
  local helm="$1" dest="$2" what="$3"; shift 3
  if [[ ! "$helm_fetch_seconds" =~ ^[1-9][0-9]*$ ]]; then
    echo "helm: HELM_FETCH_SECONDS wants whole seconds, at least 1 (got \"$helm_fetch_seconds\")" >&2
    return 2
  fi
  local cfg rc=0
  cfg="$(mktemp -d "${TMPDIR:-/tmp}/aerolvm-helm-anon.XXXXXX")"
  printf '{"auths": {"credentials.invalid": {}}}\n' > "$cfg/config.json"
  run_bounded "$helm_fetch_seconds" env DOCKER_CONFIG="$cfg" HELM_REGISTRY_CONFIG="$cfg/config.json" \
    "$helm" pull "$@" -d "$dest" || rc=$?
  rm -rf "$cfg"
  case "$rc" in
    0) return 0 ;;
    124) echo "helm: fetching $what did not finish within ${helm_fetch_seconds}s (HELM_FETCH_SECONDS); stopped it" >&2 ;;
    *) echo "helm: fetching $what failed (exit $rc)" >&2 ;;
  esac
  return 1
}

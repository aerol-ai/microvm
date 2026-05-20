#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat >&2 <<'EOF'
Usage:
  sandboxd-node-lifecycle.sh drain [NODE] [--wait-empty] [--timeout SECONDS]
  sandboxd-node-lifecycle.sh uncordon [NODE]
  sandboxd-node-lifecycle.sh remove-member [NODE] [--force]
  sandboxd-node-lifecycle.sh pre-role-change [NODE] [--timeout SECONDS]

Options:
  --node NODE       Node ID. Defaults to SB_NODE_ID from env files.
  --api-url URL     sandboxd API URL. Defaults to http://127.0.0.1:${SB_API_PORT:-21212}.
  --env-file PATH   Env file to source. May be repeated.
  --wait-empty      After drain, wait until the node owns zero placements.
  --timeout SEC     Wait timeout. pre-role-change defaults to 3600; drain defaults to 0.
  --force           remove-member may remove a live raft member.

The script reads SB_PAT_TOKEN from /etc/sandboxd/sandboxd.env by default and
SB_NODE_ID from /etc/sandboxd/cluster.env by default.
EOF
	exit 2
}

if [[ $# -lt 1 ]]; then
	usage
fi

cmd="$1"
shift

env_files=(/etc/sandboxd/sandboxd.env /etc/sandboxd/cluster.env)
node_arg=""
api_url_arg=""
wait_empty=false
force=false
timeout_s=0

case "$cmd" in
	drain) ;;
	uncordon) ;;
	remove-member) ;;
	pre-role-change)
		wait_empty=true
		timeout_s=3600
		;;
	*) usage ;;
esac

while [[ $# -gt 0 ]]; do
	case "$1" in
		--node)
			node_arg="${2:-}"
			shift 2
			;;
		--api-url)
			api_url_arg="${2:-}"
			shift 2
			;;
		--env-file)
			env_files+=("${2:-}")
			shift 2
			;;
		--wait-empty)
			wait_empty=true
			shift
			;;
		--timeout)
			timeout_s="${2:-}"
			shift 2
			;;
		--force)
			force=true
			shift
			;;
		-*)
			usage
			;;
		*)
			if [[ -n "$node_arg" ]]; then
				usage
			fi
			node_arg="$1"
			shift
			;;
	esac
done

for env_file in "${env_files[@]}"; do
	if [[ -f "$env_file" ]]; then
		set -a
		# shellcheck disable=SC1090
		. "$env_file"
		set +a
	fi
done

node_id="${node_arg:-${SB_NODE_ID:-}}"
api_url="${api_url_arg:-http://127.0.0.1:${SB_API_PORT:-21212}}"
api_url="${api_url%/}"

if [[ -z "$node_id" ]]; then
	echo "node id required: pass NODE/--node or set SB_NODE_ID" >&2
	exit 2
fi
if [[ -z "${SB_PAT_TOKEN:-}" ]]; then
	echo "SB_PAT_TOKEN required in environment or env file" >&2
	exit 2
fi
if ! [[ "$timeout_s" =~ ^[0-9]+$ ]]; then
	echo "--timeout must be a non-negative integer" >&2
	exit 2
fi

urlencode() {
	python3 - "$1" <<'PY'
import sys
from urllib.parse import quote
print(quote(sys.argv[1], safe=""))
PY
}

request() {
	local method="$1"
	local path="$2"
	curl -fsS -X "$method" \
		-H "Authorization: Bearer ${SB_PAT_TOKEN}" \
		"${api_url}${path}" >/dev/null
}

owned_count() {
	python3 - "$api_url" "$SB_PAT_TOKEN" "$node_id" <<'PY'
import json
import sys
import urllib.parse
import urllib.request

api_url, token, node_id = sys.argv[1:4]
count = 0
page_token = ""

while True:
    query = {"limit": "5000"}
    if page_token:
        query["page_token"] = page_token
    url = api_url.rstrip("/") + "/v1/cluster/sandbox-index?" + urllib.parse.urlencode(query)
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = json.load(resp)
    for placement in body.get("placements", []):
        if placement.get("owner_node_id") == node_id:
            count += 1
    page_token = body.get("next_page_token") or ""
    if not page_token:
        break

print(count)
PY
}

wait_for_empty() {
	local start now count
	start="$(date +%s)"
	while true; do
		count="$(owned_count)"
		if [[ "$count" == "0" ]]; then
			echo "node ${node_id} owns zero placements"
			return 0
		fi
		now="$(date +%s)"
		if (( timeout_s == 0 || now - start >= timeout_s )); then
			echo "node ${node_id} still owns ${count} placement(s) after drain" >&2
			return 1
		fi
		echo "waiting for node ${node_id} to empty; ${count} placement(s) remain"
		sleep 10
	done
}

encoded_node="$(urlencode "$node_id")"

case "$cmd" in
	drain|pre-role-change)
		request POST "/v1/cluster/nodes/${encoded_node}/drain"
		echo "drained node ${node_id}"
		if [[ "$wait_empty" == "true" ]]; then
			wait_for_empty
		fi
		;;
	uncordon)
		request POST "/v1/cluster/nodes/${encoded_node}/uncordon"
		echo "uncordoned node ${node_id}"
		;;
	remove-member)
		path="/v1/cluster/members/${encoded_node}"
		if [[ "$force" == "true" ]]; then
			path="${path}?force=true"
		fi
		request DELETE "$path"
		echo "removed raft member ${node_id}"
		;;
esac

#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: raft-lost-quorum-recover.sh --raft-dir /var/lib/sandboxd/raft --node-id NODE --raft-address HOST:7000 [--force]

Writes peers.json for sandboxd's startup-time lost-quorum recovery path. Run
only after stopping sandboxd on every survivor and choosing the survivor with
the most advanced Raft log.

Options:
  --raft-dir PATH       Raft data directory. Default: /var/lib/sandboxd/raft
  --node-id ID          Survivor node ID to make the sole voter. Required.
  --raft-address ADDR   Survivor Raft advertise address. Required.
  --force              Overwrite an existing peers.json.
  -h, --help           Show this help.
USAGE
}

raft_dir="/var/lib/sandboxd/raft"
node_id=""
raft_address=""
force="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --raft-dir) raft_dir="${2:?missing --raft-dir value}"; shift 2 ;;
    --node-id) node_id="${2:?missing --node-id value}"; shift 2 ;;
    --raft-address) raft_address="${2:?missing --raft-address value}"; shift 2 ;;
    --force) force="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$node_id" || -z "$raft_address" ]]; then
  echo "--node-id and --raft-address are required" >&2
  usage >&2
  exit 2
fi

mkdir -p "$raft_dir"
peers="$raft_dir/peers.json"
if [[ -e "$peers" && "$force" != "true" ]]; then
  echo "$peers already exists; pass --force to overwrite" >&2
  exit 1
fi

tmp="$(mktemp "$raft_dir/.peers.json.XXXXXX")"
cat > "$tmp" <<JSON
[
  {
    "id": "$node_id",
    "address": "$raft_address",
    "non_voter": false,
    "suffrage": "Voter"
  }
]
JSON
chmod 0600 "$tmp"
mv "$tmp" "$peers"
echo "wrote $peers"
echo "start sandboxd on this node only; successful recovery renames the file to peers.json.applied.<unix>"

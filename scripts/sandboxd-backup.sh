#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: sandboxd-backup.sh --output /path/sandboxd-backup.tar.gz [options]

Options:
  --state-db PATH        SQLite state DB. Default: /var/lib/sandboxd/state.db
  --raft-dir PATH        Raft data directory. Default: /var/lib/sandboxd/raft
  --config-dir PATH      sandboxd config directory. Default: /etc/sandboxd
  --output PATH          Destination .tar.gz archive. Required.
  -h, --help             Show this help.
USAGE
}

state_db="/var/lib/sandboxd/state.db"
raft_dir="/var/lib/sandboxd/raft"
config_dir="/etc/sandboxd"
output=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --state-db) state_db="${2:?missing --state-db value}"; shift 2 ;;
    --raft-dir) raft_dir="${2:?missing --raft-dir value}"; shift 2 ;;
    --config-dir) config_dir="${2:?missing --config-dir value}"; shift 2 ;;
    --output) output="${2:?missing --output value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$output" ]]; then
  echo "--output is required" >&2
  usage >&2
  exit 2
fi

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

mkdir -p "$tmpdir/root"
manifest="$tmpdir/root/MANIFEST.txt"
{
  echo "created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "hostname=$(hostname)"
  echo "state_db=$state_db"
  echo "raft_dir=$raft_dir"
  echo "config_dir=$config_dir"
} > "$manifest"

copy_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -e "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp -a "$src" "$dst"
    echo "included=$src" >> "$manifest"
  else
    echo "missing=$src" >> "$manifest"
  fi
}

copy_if_exists "$state_db" "$tmpdir/root/var/lib/sandboxd/state.db"
copy_if_exists "$raft_dir" "$tmpdir/root/var/lib/sandboxd/raft"
copy_if_exists "$config_dir" "$tmpdir/root/etc/sandboxd"

mkdir -p "$(dirname "$output")"
tar -C "$tmpdir/root" -czf "$output" .
chmod 0600 "$output"
echo "wrote $output"

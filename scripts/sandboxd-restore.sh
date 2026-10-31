#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: sandboxd-restore.sh --input /path/sandboxd-backup.tar.gz --target-root / [--force]

Restores the archive produced by sandboxd-backup.sh. Stop sandboxd first.

Options:
  --input PATH        Backup archive. Required.
  --target-root PATH  Restore root. Default: /
  --force            Required acknowledgement for writes.
  -h, --help         Show this help.
USAGE
}

input=""
target_root="/"
force="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input) input="${2:?missing --input value}"; shift 2 ;;
    --target-root) target_root="${2:?missing --target-root value}"; shift 2 ;;
    --force) force="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$input" ]]; then
  echo "--input is required" >&2
  usage >&2
  exit 2
fi
if [[ "$force" != "true" ]]; then
  echo "refusing to restore without --force; stop sandboxd and confirm this is the intended target" >&2
  exit 2
fi
if [[ ! -f "$input" ]]; then
  echo "backup archive not found: $input" >&2
  exit 1
fi

mkdir -p "$target_root"
# A restore replaces the node's database and Raft log, never merges into
# them: SQLite would replay a leftover state.db-wal from the database being
# replaced onto the restored one, and two Raft logs in one directory are not
# one log. A replacement node that already ran a fresh install has both.
# What the archive brings is moved aside first, kept rather than deleted.
listing="$(tar -tzf "$input")"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
set_aside() {
  local path="$target_root/$1"
  if [[ -e "$path" ]]; then
    mv "$path" "$path.pre-restore-$stamp"
    echo "moved aside: $path -> $path.pre-restore-$stamp"
  fi
}
if grep -qx '\./var/lib/sandboxd/state\.db' <<<"$listing"; then
  set_aside var/lib/sandboxd/state.db
  set_aside var/lib/sandboxd/state.db-wal
  set_aside var/lib/sandboxd/state.db-shm
fi
if grep -qE '^\./var/lib/sandboxd/raft/?$' <<<"$listing"; then
  set_aside var/lib/sandboxd/raft
fi
tar -C "$target_root" -xzf "$input"
echo "restored $input into $target_root"
wrapped="$target_root/var/lib/sandboxd/credential_encryption.key.wrapped"
if [[ -f "$wrapped" ]]; then
  # Key custody "wrapped": sandboxd unwraps this at boot through the key
  # store, which must be reachable. A backup taken before a key version was
  # retired no longer opens once that version is gone.
  chmod 0600 "$wrapped"
  echo "the server key is wrapped: run \`sandboxd key verify\` with the key store reachable before starting sandboxd"
fi
ring="$target_root/var/lib/sandboxd/credential_encryption.key.ring"
if [[ -f "$ring" ]]; then
  # A rotated plaintext key (custody "file"): the ring holds every live key.
  chmod 0600 "$ring"
  echo "the server key was rotated: the ring at $ring holds it; keep it with SB_CREDENTIAL_KEY_RING_PATH unset or pointing there"
fi
echo "verify ownership/modes, then start sandboxd"

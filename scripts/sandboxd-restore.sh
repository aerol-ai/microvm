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
tar -C "$target_root" -xzf "$input"
echo "restored $input into $target_root"
echo "verify ownership/modes, then start sandboxd"

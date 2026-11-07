#!/usr/bin/env bash
# sandboxd-backup.sh is kept for the cron jobs and runbooks that call it.
# The backup itself is `sandboxd backup` (plans/kubectl-style-cluster-ops.md
# §3.1): every argument is passed through, and `sandboxd backup --help` lists
# them (--output, --state-db, --raft-dir, --config-dir, --wrapped-key,
# --key-ring, --key-file, plus --stop).
set -euo pipefail

bin="${SANDBOXD_BIN:-}"
if [[ -z "$bin" ]]; then
  bin="$(command -v sandboxd 2>/dev/null || true)"
  [[ -n "$bin" ]] || bin=/usr/local/bin/sandboxd
fi
# A sandboxd from before the command reads `backup` as no command at all and
# boots a second daemon on the live state directory, so it runs only when
# the binary carries the command's usage text.
if [[ ! -x "$bin" ]] || ! grep -aqF 'usage: sandboxd backup' "$bin"; then
  echo "sandboxd-backup.sh: $bin has no 'sandboxd backup' command: this node's sandboxd is too old." >&2
  echo "Upgrade sandboxd first (sudo sandboxd upgrade node <version>, or re-run install.sh)," >&2
  echo "or run the sandboxd-backup.sh of the release this node runs." >&2
  exit 1
fi
exec "$bin" backup "$@"

#!/usr/bin/env bash
# raft-lost-quorum-recover.sh is kept for the runbooks that call it. The
# recovery itself is `sandboxd recover-quorum`
# (plans/kubectl-style-cluster-ops.md §3.1): every argument is passed
# through, and `sandboxd recover-quorum --help` lists them (--raft-dir,
# --node-id, --raft-address, --force, plus --start, --rejoin and the backup
# it now takes first).
set -euo pipefail

bin="${SANDBOXD_BIN:-}"
if [[ -z "$bin" ]]; then
  bin="$(command -v sandboxd 2>/dev/null || true)"
  [[ -n "$bin" ]] || bin=/usr/local/bin/sandboxd
fi
# A sandboxd from before the command reads `recover-quorum` as no command at
# all and boots a second daemon on the live state directory, so it runs only
# when the binary carries the command's usage text.
if [[ ! -x "$bin" ]] || ! grep -aqF 'usage: sandboxd recover-quorum' "$bin"; then
  echo "raft-lost-quorum-recover.sh: $bin has no 'sandboxd recover-quorum' command: this node's sandboxd is too old." >&2
  echo "Upgrade sandboxd first (sudo sandboxd upgrade node <version>, or re-run install.sh)," >&2
  echo "or run the raft-lost-quorum-recover.sh of the release this node runs." >&2
  exit 1
fi
exec "$bin" recover-quorum "$@"

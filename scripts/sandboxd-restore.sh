#!/usr/bin/env bash
# sandboxd-restore.sh is kept for the runbooks that call it. The restore
# itself is `sandboxd restore` (plans/kubectl-style-cluster-ops.md §3.1):
# every argument is passed through, and `sandboxd restore --help` lists them
# (--input, --target-root, --force, plus --start).
set -euo pipefail

bin="${SANDBOXD_BIN:-}"
if [[ -z "$bin" ]]; then
  bin="$(command -v sandboxd 2>/dev/null || true)"
  [[ -n "$bin" ]] || bin=/usr/local/bin/sandboxd
fi
# A sandboxd from before the command reads `restore` as no command at all
# and boots a second daemon on the live state directory, so it runs only
# when the binary carries the command's usage text.
if [[ ! -x "$bin" ]] || ! grep -aqF 'usage: sandboxd restore' "$bin"; then
  echo "sandboxd-restore.sh: $bin has no 'sandboxd restore' command: this node's sandboxd is too old." >&2
  echo "Upgrade sandboxd first (sudo sandboxd upgrade node <version>, or re-run install.sh)," >&2
  echo "or run the sandboxd-restore.sh of the release this node runs." >&2
  exit 1
fi
exec "$bin" restore "$@"

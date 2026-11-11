#!/usr/bin/env bash
# runtime-supervisor.sh: the runtime container run by Phase 1's Go supervisor
# (cmd/aerolvm-supervisor, C7) instead of runtime.sh's shell stand-in. It
# shapes this container's cgroup (supervisor/, sandboxes/ capped at the
# container's limit minus a reserve, containerd in sandboxes/_runtime), tells
# the agent the parent, and keeps containerd running. s3.sh --supervisor
# uses it to prove F10's full fix with the code that ships.
#
# The binary is this build's, published to S3 by s3.sh and handed over as a
# presigned URL with its SHA-256 (rule 3: nothing uploaded from a laptop
# straight to a node).
set -euo pipefail
: "${SUPERVISOR_URL:?}" "${SUPERVISOR_SHA256:?}"
curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 10 \
  -o /opt/aerolvm/bin/aerolvm-supervisor "$SUPERVISOR_URL"
echo "$SUPERVISOR_SHA256  /opt/aerolvm/bin/aerolvm-supervisor" | sha256sum -c --quiet -
chmod 0755 /opt/aerolvm/bin/aerolvm-supervisor
export PATH="/opt/aerolvm/bin:$PATH"
export SB_CONTAINERD_BINARY=/opt/aerolvm/bin/containerd
echo "runtime: starting aerolvm-supervisor"
exec aerolvm-supervisor

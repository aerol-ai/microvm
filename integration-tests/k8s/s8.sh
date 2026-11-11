#!/usr/bin/env bash
# s8.sh: spike S8 (plans/kubernetes-v2-phase0.md, plan C27, eng review D8).
# Per-sandbox disk limits with XFS project quotas on the machine's local NVMe.
#
#   cluster.sh up <name> --type m6id.xlarge
#   s8.sh <name>          # writes .state/<name>/s8-report.txt
#   cluster.sh down <name>
#
# The worker formats the NVMe instance store as XFS with project quotas and
# mounts it as containerd's root. Two gVisor sandboxes; one gets a 100 MB
# project quota on its writable layer (the containerd snapshot's upper
# directory, where gVisor keeps its root overlay's file store). Each writes
# 300 MB into its root filesystem. Expected: the limited one stops near
# 100 MB with a quota or space error; the other finishes.
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

name="${1:?usage: s8.sh <name>}"
lib_init "$name" s8-report.txt
publish_build
load_br_netfilter

manifest="$sd/worker-s8.yaml"
python3 - "$LIB_DIR/manifests/worker-h0.yaml" "$manifest" <<'PY'
import sys
s = open(sys.argv[1]).read()
s = s.replace('        - name: POD_NAME\n', '        - name: AEROL_S8_NVME\n          value: "1"\n        - name: POD_NAME\n', 1)
open(sys.argv[2], "w").write(s)
PY
apply_worker "$manifest" 1
wait_ready
wait_api
say "$(kubectl -n "$NS" logs "$POD" -c worker | grep 'is XFS with project quotas' | head -1)"

mk() { api /v1/sandboxes -X POST -d '{"image":"alpine:3.20","runtime":"gvisor","disk_gb":1}' | jq -r '.id // empty'; }
limited="$(mk)"; free="$(mk)"
[[ -n "$limited" && -n "$free" ]] || { echo "s8: creates failed" >&2; exit 1; }
say "sandboxes: limited $limited, unlimited $free"

# The sandbox's writable layer: containerd's snapshot for it (named after the
# sandbox), read with ctr from inside the worker.
upper="$(kubectl -n "$NS" exec "$POD" -c worker -- sh -c \
  "/opt/aerolvm/bin/ctr -n aerolvm snapshots mounts /tmp/x $limited | grep -o 'upperdir=[^,]*' | head -1 | cut -d= -f2")"
[[ -n "$upper" ]] || { echo "s8: no upper dir for $limited" >&2; exit 1; }
say "limited sandbox's writable layer: $upper"
kubectl -n "$NS" exec "$POD" -c worker -- sh -c \
  "xfs_quota -x -c 'project -s -p $upper 42' -c 'limit -p bhard=100m 42' /var/lib/containerd >/dev/null && xfs_quota -x -c 'report -p -h' /var/lib/containerd | grep -E '^#42|Project'" | tee -a "$report"

write300() {
  api "/v1/sandboxes/$1/toolbox/process/execute" -X POST \
    -d '{"command":"dd if=/dev/zero of=/root/big bs=1M count=300 2>&1 | tail -1; ls -l /root/big | awk \"{print \\$5}\"; df -m / | tail -1"}' |
    jq -r '"exit \(.exit_code): \(.stdout | gsub("\n"; " | "))"'
}
say "limited sandbox writes 300 MB: $(write300 "$limited")"
say "unlimited sandbox writes 300 MB: $(write300 "$free")"
say "--- the quota after the writes"
kubectl -n "$NS" exec "$POD" -c worker -- sh -c "xfs_quota -x -c 'report -p -h' /var/lib/containerd | grep -E '^#42'" | tee -a "$report"
say "--- done; report in $report"

#!/usr/bin/env bash
# s8q.sh: C27 live. sandboxd itself gives each sandbox's writable layer an
# XFS project quota of its disk_gb (SB_CONTAINERD_DISK_QUOTA) and refuses new
# creates while the sandbox volume is under its disk floor
# (SB_DISK_FLOOR_RATIO). The worker's NVMe is containerd's root, XFS with
# prjquota, as in S8; unlike S8, nothing here sets a limit by hand.
#
#   cluster.sh up <name> --type m6id.xlarge
#   AEROL_BUILD_REF=<a commit with both C27 changes> s8q.sh <name>
#   cluster.sh down <name>
#
# Expected: gVisor and runc sandboxes with disk_gb 1 stop writing near 1 GiB
# with "No space left on device"; one with disk_gb 3 writes 2 GiB; a resize
# to 2 lets the first write about 1 GiB more; with the volume filled past 90%
# a create gets 503 and "disk floor breached", and after the filler is gone
# a create succeeds again.
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

name="${1:?usage: s8q.sh <name>}"
lib_init "$name" s8q-report.txt
publish_build
load_br_netfilter

manifest="$sd/worker-s8q.yaml"
python3 - "$LIB_DIR/manifests/worker-h0.yaml" "$manifest" <<'PY'
import sys
s = open(sys.argv[1]).read()
env = ''.join(f'        - name: {k}\n          value: "{v}"\n' for k, v in [
    ("AEROL_S8_NVME", "1"),
    ("SB_CONTAINERD_DISK_QUOTA", "true"),
    ("SB_DISK_FLOOR_RATIO", "0.10"),
])
s = s.replace('        - name: POD_NAME\n', env + '        - name: POD_NAME\n', 1)
open(sys.argv[2], "w").write(s)
PY
apply_worker "$manifest" 1
wait_ready
wait_api
say "$(kubectl -n "$NS" logs "$POD" -c worker | grep 'is XFS with project quotas' | head -1)"
say "sandboxd: $(kubectl -n "$NS" logs "$POD" -c worker | grep 'msg="sandbox volume"' | head -1 | cut -c1-240)"

mk() { api /v1/sandboxes -X POST -d "{\"image\":\"alpine:3.20\",\"runtime\":\"$1\",\"disk_gb\":$2}" | jq -r '.id // empty'; }
# fill <id> <file> <MB>: dd's last line and the file's size afterwards.
fill() {
  api "/v1/sandboxes/$1/toolbox/process/execute" -X POST \
    -d "{\"command\":\"dd if=/dev/zero of=$2 bs=1M count=$3 2>&1 | tail -1; sync; stat -c %s $2\"}" |
    jq -r '"exit \(.exit_code): \(.stdout | gsub("\n"; " | "))"'
}

g1="$(mk gvisor 1)"; r1="$(mk docker 1)"; g3="$(mk gvisor 3)"
[[ -n "$g1" && -n "$r1" && -n "$g3" ]] || { echo "s8q: creates failed" >&2; exit 1; }
say "sandboxes: gVisor 1 GB $g1, runc 1 GB $r1, gVisor 3 GB $g3"
say "gVisor, disk_gb 1, writes 2048 MB: $(fill "$g1" /fill 2048)"
say "runc, disk_gb 1, writes 2048 MB: $(fill "$r1" /fill 2048)"
say "gVisor, disk_gb 3, writes 2048 MB: $(fill "$g3" /fill 2048)"
api "/v1/sandboxes/$g1/resize" -X POST -d '{"disk_gb":2}' >/dev/null
say "gVisor resized to disk_gb 2, writes 1536 MB more: $(fill "$g1" /fill2 1536)"

qdev="$(kubectl -n "$NS" exec "$POD" -c worker -- sh -c "awk '\$2 == \"/var/lib/containerd\" {print \$1}' /proc/mounts | tail -1")"
say "--- the project quotas sandboxd set"
kubectl -n "$NS" exec "$POD" -c worker -- sh -c "xfs_quota -x -c 'report -p -h' $qdev | grep -E '^#[1-9]'" | tee -a "$report"

say "--- the disk floor"
cap() { api /v1/capacity | jq -c '{can_admit, disk_floor_ratio, sandbox_disk_total_mb, sandbox_disk_free_mb, reasons}'; }
say "capacity: $(cap)"
read -r total free < <(api /v1/capacity | jq -r '"\(.sandbox_disk_total_mb) \(.sandbox_disk_free_mb)"')
filler=$(( free - total / 20 ))
kubectl -n "$NS" exec "$POD" -c worker -- fallocate -l "${filler}M" /var/lib/containerd/c27-filler
say "filled ${filler} MB, leaving about 5% free; capacity: $(cap)"
code="$(curl -sS -o "$sd/floor-create.json" -w '%{http_code}' --max-time 120 -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' http://127.0.0.1:21212/v1/sandboxes -X POST \
  -d '{"image":"alpine:3.20","runtime":"gvisor","disk_gb":1}')"
say "create under the floor: HTTP $code: $(head -c 300 "$sd/floor-create.json")"
kubectl -n "$NS" exec "$POD" -c worker -- rm -f /var/lib/containerd/c27-filler
say "filler removed; capacity: $(cap)"
after="$(mk gvisor 1)"
say "create after the filler went: ${after:-FAILED}"
say "--- done; report in $report"

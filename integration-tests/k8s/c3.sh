#!/usr/bin/env bash
# c3.sh: C3 live. The containerd sandbox range as a setting
# (SB_CONTAINERD_BRIDGE_SUBNET=10.200.0.0/16): the conflist sandboxd writes,
# the AEROLVM-USER rules and the sandboxes' addresses all use it, and a
# sandbox still reaches the internet through it.
#
#   cluster.sh up <name>
#   AEROL_BUILD_REF=<a commit with C3> c3.sh <name>
#   cluster.sh down <name>
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

name="${1:?usage: c3.sh <name>}"
lib_init "$name" c3-report.txt
publish_build
load_br_netfilter

manifest="$sd/worker-c3.yaml"
python3 - "$LIB_DIR/manifests/worker-h0.yaml" "$manifest" <<'PY'
import sys
s = open(sys.argv[1]).read()
s = s.replace('        - name: POD_NAME\n', '        - name: SB_CONTAINERD_BRIDGE_SUBNET\n          value: "10.200.0.0/16"\n        - name: POD_NAME\n', 1)
open(sys.argv[2], "w").write(s)
PY
apply_worker "$manifest" 1
wait_ready
wait_api
wx() { kubectl -n "$NS" exec "$POD" -c worker -- sh -c "$1"; }
say "conflist range: $(wx "grep -o '\"subnet\": *\"[^\"]*\"' /etc/cni/net.d/aerolvm.conflist")"
mk() { api /v1/sandboxes -X POST -d "{\"image\":\"alpine:3.20\",\"runtime\":\"$1\"}" | jq -r '.id // empty'; }
run() { api "/v1/sandboxes/$1/toolbox/process/execute" -X POST -d "{\"command\":\"$2\"}" | jq -r '"exit \(.exit_code): \(.stdout | gsub("\n"; " | ") | .[0:200])"'; }
r="$(mk docker)"; g="$(mk gvisor)"
[[ -n "$r" && -n "$g" ]] || { echo "c3: creates failed" >&2; exit 1; }
say "runc $r address: $(api "/v1/sandboxes/$r/toolbox/process/execute" -X POST -d '{"command":"ip -4 -o addr show eth0"}' | jq -r .stdout | awk '{print $4}')"
say "gVisor $g address: $(api "/v1/sandboxes/$g" | jq -r '.container_ip // .ip // empty')"
say "runc reaches example.com: $(run "$r" 'wget -q -T 10 -O- https://example.com | grep -o \"<title>[^<]*\"')"
say "gVisor reaches example.com: $(run "$g" 'wget -q -T 10 -O- https://example.com | grep -o \"<title>[^<]*\"')"
say "rules naming 10.200.0.0/16: $(wx 'nft list ruleset 2>/dev/null | grep -c 10.200.0.0/16 || iptables-save | grep -c 10.200.0.0/16')"
say "rules naming 10.88.0.0/16: $(wx 'nft list ruleset 2>/dev/null | grep -c 10.88.0.0/16 || true')"
say "--- done; report in $report"

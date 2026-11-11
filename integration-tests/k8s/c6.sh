#!/usr/bin/env bash
# c6.sh: C6 live. The egress gateway runs with no systemd, as a pod runs it:
# its own process, a numeric user, two capabilities, a socket it makes
# itself, SB_EGRESS_PEER_CGROUP=none, and SB_EGRESS_GATEWAY_USER=65532 for
# sandboxd (worker/run.sh, AEROL_EGRESS_GATEWAY=1).
#
#   cluster.sh up <name>
#   AEROL_BUILD_REF=<a commit with C6> c6.sh <name>
#   cluster.sh down <name>
#
# Expected: sandboxd logs "egress gateway ready"; /v1/capacity says
# egress_gateway_ready; a gVisor sandbox allowed only example.com reaches it
# and cannot reach another site.
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

name="${1:?usage: c6.sh <name>}"
lib_init "$name" c6-report.txt
publish_build
load_br_netfilter

manifest="$sd/worker-c6.yaml"
python3 - "$LIB_DIR/manifests/worker-h0.yaml" "$manifest" <<'PY'
import sys
s = open(sys.argv[1]).read()
s = s.replace('        - name: POD_NAME\n', '        - name: AEROL_EGRESS_GATEWAY\n          value: "1"\n        - name: POD_NAME\n', 1)
open(sys.argv[2], "w").write(s)
PY
apply_worker "$manifest" 1
wait_ready
wait_api
logs() { kubectl -n "$NS" logs "$POD" -c worker; }
say "$(logs | grep -m1 'egress gateway started')"
say "gateway: $(logs | grep -m1 '\[gateway\].*serving' | cut -c1-220)"
for _ in $(seq 1 30); do logs | grep -q 'egress gateway ready' && break; sleep 2; done
say "sandboxd: $(logs | grep -m1 'egress gateway ready' | cut -c1-200)"
say "gateway process: $(kubectl -n "$NS" exec "$POD" -c worker -- sh -c 'p=$(pgrep -f "sandboxd egress-gateway" | head -1); grep -E "^(Uid|CapEff)" /proc/$p/status | tr "\n\t" "  "')"
say "capacity: $(api /v1/capacity | jq -c '{egress_gateway_ready}')"

id="$(api /v1/sandboxes -X POST -d '{"image":"alpine:3.20","runtime":"gvisor","network_allow_out":["example.com"]}' | jq -r '.id // empty')"
[[ -n "$id" ]] || { echo "c6: create failed" >&2; exit 1; }
say "sandbox $id allowed only example.com"
run() { api "/v1/sandboxes/$id/toolbox/process/execute" -X POST -d "{\"command\":\"$1\"}" | jq -r '"exit \(.exit_code): \(.stdout | gsub("\n"; " | ") | .[0:200])"'; }
say "example.com: $(run 'wget -q -T 10 -O- https://example.com | grep -o \"<title>[^<]*\"')"
say "www.google.com: $(run 'wget -q -T 10 -O /dev/null https://www.google.com; echo wget=$?')"
say "--- done; report in $report"

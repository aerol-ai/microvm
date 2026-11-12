#!/usr/bin/env bash
# chart-pod-templates.sh: print the pod-templates ConfigMap the chart
# renders in cluster mode (plans/kubernetes-v2-architecture.md P2), for the
# operator's TestRenderedChartTemplates (AEROLVM_POD_TEMPLATES), which
# parses each role's template strictly and stamps it. Needs helm.
#
#   scripts/chart-pod-templates.sh [extra helm --set flags...]
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
helm template t "$root/charts/aerolvm" --namespace aerolvm-system \
  --set mode=cluster --set 'cluster.zones={z-a,z-b,z-c}' \
  --set cluster.workerPools[0].name=general \
  --set cluster.workerPools[0].machine.cpu=8 --set cluster.workerPools[0].machine.memoryGiB=32 \
  --set cluster.workerPools[0].minWorkers=3 --set cluster.workerPools[0].maxWorkers=9 \
  --set edge.enabled=true --set edge.domain=aerolvm.test --set edge.certManager.issuerRef.name=ci \
  "$@" --show-only templates/cluster.yaml |
  python3 -c 'import sys
docs = sys.stdin.read().split("\n---\n")
hits = [d for d in docs if "kind: ConfigMap" in d and "-pod-templates" in d]
if len(hits) != 1:
    sys.exit("chart-pod-templates: want one pod-templates ConfigMap, got %d" % len(hits))
print(hits[0])'

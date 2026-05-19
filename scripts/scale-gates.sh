#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_BIN="${GO_BIN:-/opt/homebrew/bin/go}"

cd "$ROOT"

export AEROLVM_SCALE_GATES=1

"$GO_BIN" test -run 'TestScaleGate' ./internal/cluster ./internal/service
"$GO_BIN" test -run 'TestReconcileClusterIngressFailoverStormBoundedBurst|TestHashPlacementViewAt10K|TestRunIngressOpsAt10K' ./internal/service

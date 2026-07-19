package createtiming

import (
	"time"

	"github.com/aerol-ai/microvm/internal/scaleobs"
)

// createStageLatency is keyed by stage name (key) and le_* bucket (key2).
// Recorded from RecordStage/RecordStageDesc so every runtime driver gets
// export without per-call-site wiring.
var createStageLatency = scaleobs.NewNestedDurationBuckets("aerolvm_create_stage_latency_seconds_bucket")

func exportCreateStage(name string, d time.Duration) {
	createStageLatency.Observe(name, d)
}

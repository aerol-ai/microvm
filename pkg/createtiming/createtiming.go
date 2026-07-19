// Package createtiming carries a per-request create-latency recorder on
// the request context so runtime drivers can attribute where a sandbox
// create spent its time, and the API handler can surface that
// attribution as Server-Timing response entries.
//
// The recorder started life inside pkg/docker (runtime/toolbox wait
// attribution). Phase 0 of plans/firecracker-create-latency.md moved it
// here so the firecracker driver can record its boot stages without the
// runtime packages growing an import on each other; pkg/docker keeps
// thin aliases so its existing callers are untouched.
package createtiming

import (
	"context"
	"sync"
	"time"
)

type key struct{}

// Stage is one named Server-Timing entry. A duration stage renders as
// "name;dur=<ms>"; a marker stage (Desc set, no duration) renders as
// "name;desc=<desc>". Recorded stages are surfaced in record order.
type Stage struct {
	Name  string
	DurMS float64
	Desc  string
}

// CreateTiming captures per-phase create latency for Server-Timing
// attribution. The docker fields are populated by the docker runtime's
// readiness wait; Stages carries the firecracker driver's per-stage
// boot breakdown (fc_driver, fc_verify, …).
type CreateTiming struct {
	RuntimeWaitMS float64
	ToolboxWaitMS float64
	Source        string // "socket" or "health"; empty when not recorded

	// mu guards stages: the boot path records serially, but async
	// observers (and tests) may read while a late stage lands.
	mu     sync.Mutex
	stages []Stage
}

// With returns a child context that carries a CreateTiming recorder.
// Reuses an existing recorder so nested calls share one instance.
func With(parent context.Context) (context.Context, *CreateTiming) {
	if parent == nil {
		parent = context.Background()
	}
	if existing, ok := parent.Value(key{}).(*CreateTiming); ok && existing != nil {
		return parent, existing
	}
	timing := &CreateTiming{}
	return context.WithValue(parent, key{}, timing), timing
}

// From returns the recorder stashed on ctx, if any.
func From(ctx context.Context) *CreateTiming {
	if ctx == nil {
		return nil
	}
	timing, _ := ctx.Value(key{}).(*CreateTiming)
	return timing
}

// RecordReadinessWaits sets a runtime's readiness attribution: how long the
// container runtime and toolbox waits took, and which signal proved readiness
// ("socket" or "health"). Nil-safe so a driver can call it unconditionally.
// setCreateServerTiming renders Source as the "readiness;desc=" entry, so a
// driver that omits this leaves the create Server-Timing without a readiness
// source (the containerd UC-11 gap).
func (t *CreateTiming) RecordReadinessWaits(runtimeWait, toolboxWait time.Duration, source string) {
	if t == nil {
		return
	}
	t.RuntimeWaitMS = float64(runtimeWait.Microseconds()) / 1000
	t.ToolboxWaitMS = float64(toolboxWait.Microseconds()) / 1000
	t.Source = source
}

// RecordDockerWaits is the docker driver's original name for
// RecordReadinessWaits, kept so existing docker callers are untouched.
func (t *CreateTiming) RecordDockerWaits(runtimeWait, toolboxWait time.Duration, source string) {
	t.RecordReadinessWaits(runtimeWait, toolboxWait, source)
}

// RecordStage appends a duration stage. Nil-safe; negative durations
// clamp to zero so a stage is never rendered with a nonsense value.
func (t *CreateTiming) RecordStage(name string, d time.Duration) {
	if t == nil || name == "" {
		return
	}
	if d < 0 {
		d = 0
	}
	t.mu.Lock()
	t.stages = append(t.stages, Stage{Name: name, DurMS: float64(d.Microseconds()) / 1000})
	t.mu.Unlock()
	// Boot-path (pr-review §2): this runs on every create. Deliberately AFTER the
	// unlock — it's a lock-free expvar atomic increment (bounded static stage-name
	// set), not held under t.mu, so it adds ~150ns and no create serialization.
	exportCreateStage(name, d)
}

// RecordStageDesc appends a duration stage that also carries a desc
// attribute (e.g. "fc_warm;dur=42.0;desc=hit"). Nil-safe.
func (t *CreateTiming) RecordStageDesc(name string, d time.Duration, desc string) {
	if t == nil || name == "" {
		return
	}
	if d < 0 {
		d = 0
	}
	t.mu.Lock()
	t.stages = append(t.stages, Stage{Name: name, DurMS: float64(d.Microseconds()) / 1000, Desc: desc})
	t.mu.Unlock()
	// Boot-path (pr-review §2): same as RecordStage — post-unlock, lock-free atomic.
	exportCreateStage(name, d)
}

// Stages returns a copy of the recorded stages in record order.
// Nil-safe: a nil recorder has no stages.
func (t *CreateTiming) Stages() []Stage {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Stage, len(t.stages))
	copy(out, t.stages)
	return out
}

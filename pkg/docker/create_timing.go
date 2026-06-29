package docker

import (
	"context"
	"time"
)

type createTimingKey struct{}

// CreateTiming captures per-phase create latency for Server-Timing attribution.
type CreateTiming struct {
	RuntimeWaitMS float64
	ToolboxWaitMS float64
	Source        string // "socket" or "health"; empty when not recorded
}

// WithCreateTiming returns a child context that carries a CreateTiming recorder.
func WithCreateTiming(parent context.Context) (context.Context, *CreateTiming) {
	if parent == nil {
		parent = context.Background()
	}
	if existing, ok := parent.Value(createTimingKey{}).(*CreateTiming); ok && existing != nil {
		return parent, existing
	}
	timing := &CreateTiming{}
	return context.WithValue(parent, createTimingKey{}, timing), timing
}

// CreateTimingFrom returns the recorder stashed on ctx, if any.
func CreateTimingFrom(ctx context.Context) *CreateTiming {
	if ctx == nil {
		return nil
	}
	timing, _ := ctx.Value(createTimingKey{}).(*CreateTiming)
	return timing
}

func (t *CreateTiming) record(runtimeWait, toolboxWait time.Duration, source string) {
	if t == nil {
		return
	}
	t.RuntimeWaitMS = float64(runtimeWait.Microseconds()) / 1000
	t.ToolboxWaitMS = float64(toolboxWait.Microseconds()) / 1000
	t.Source = source
}

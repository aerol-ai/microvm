package docker

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/createtiming"
)

// CreateTiming moved to pkg/createtiming so the firecracker driver can
// record boot stages on the same recorder without importing pkg/docker
// (Phase 0, plans/firecracker-create-latency.md). These aliases keep the
// docker package's existing callers (v1 handlers, tests) source-stable;
// the context key lives in createtiming so both packages share one
// recorder per request.
type CreateTiming = createtiming.CreateTiming

// WithCreateTiming returns a child context that carries a CreateTiming recorder.
func WithCreateTiming(parent context.Context) (context.Context, *CreateTiming) {
	return createtiming.With(parent)
}

// CreateTimingFrom returns the recorder stashed on ctx, if any.
func CreateTimingFrom(ctx context.Context) *CreateTiming {
	return createtiming.From(ctx)
}

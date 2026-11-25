package scaleobs

import (
	"context"
	"sync/atomic"
)

// A create's warm/cold label (plans/agent-sandbox-feature-parity.md O1). The
// service starts a create with WithWarmStart; whichever runtime serves it
// from something already running (a warm pool slot, a parked container, a
// running isolate group) calls MarkWarmStart on the ctx it was handed. The
// marker rides the context so no runtime interface changes for one label.

type warmStartKey struct{}

// WithWarmStart returns ctx carrying a fresh warm marker, and the marker.
func WithWarmStart(ctx context.Context) (context.Context, *atomic.Bool) {
	marker := new(atomic.Bool)
	return context.WithValue(ctx, warmStartKey{}, marker), marker
}

// MarkWarmStart marks the create running under ctx as warm. A ctx without a
// marker (a create that is not measured) is left alone.
func MarkWarmStart(ctx context.Context) {
	if ctx == nil {
		return
	}
	if marker, ok := ctx.Value(warmStartKey{}).(*atomic.Bool); ok && marker != nil {
		marker.Store(true)
	}
}

// WarmStarted reports whether the create running under ctx was marked warm,
// and whether ctx carries a marker at all (measured is false for a ctx no
// create set up, such as a WASM migration's). One context lookup and an
// atomic load.
func WarmStarted(ctx context.Context) (warm, measured bool) {
	if ctx == nil {
		return false, false
	}
	marker, ok := ctx.Value(warmStartKey{}).(*atomic.Bool)
	if !ok || marker == nil {
		return false, false
	}
	return marker.Load(), true
}

package scaleobs

import (
	"context"
	"testing"
)

// TestWarmStartMarker: a create's marker is set only by MarkWarmStart on its
// own context (or a child of it); a context without one is left alone.
func TestWarmStartMarker(t *testing.T) {
	ctx, marker := WithWarmStart(context.Background())
	if marker.Load() {
		t.Fatal("a fresh marker is warm")
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	MarkWarmStart(child)
	if !marker.Load() {
		t.Fatal("MarkWarmStart on a child did not mark the create")
	}
	MarkWarmStart(context.Background())
	MarkWarmStart(nil) //nolint:staticcheck // a nil ctx must not panic
	_, other := WithWarmStart(context.Background())
	if other.Load() {
		t.Fatal("markers are shared between creates")
	}
}

// TestWarmStarted: the create sees its own marker, cold until marked; a
// context no create set up reports unmeasured.
func TestWarmStarted(t *testing.T) {
	ctx, _ := WithWarmStart(context.Background())
	if warm, measured := WarmStarted(ctx); warm || !measured {
		t.Fatalf("fresh marker = (%v, %v), want cold and measured", warm, measured)
	}
	MarkWarmStart(ctx)
	if warm, measured := WarmStarted(ctx); !warm || !measured {
		t.Fatalf("marked = (%v, %v), want warm and measured", warm, measured)
	}
	for _, c := range []context.Context{context.Background(), nil} {
		if warm, measured := WarmStarted(c); warm || measured {
			t.Fatalf("no marker = (%v, %v), want unmeasured", warm, measured)
		}
	}
}

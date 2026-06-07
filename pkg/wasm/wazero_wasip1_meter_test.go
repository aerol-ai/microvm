package wasm

import (
	"context"
	"testing"
)

func TestWasip1MeterFactory(t *testing.T) {
	meter := &NetByteCounter{}
	factory := newWasip1MeterFactory(meter)
	if factory == nil {
		t.Fatal("expected factory")
	}
	ctx := context.Background()
	e, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	defer func() { _ = e.Close(ctx) }()
	e.SetNetworkHook(&NetworkHook{Meter: meter})
	instCtx := withWasip1Meter(ctx, e.netHook)
	if instCtx == ctx {
		t.Fatal("expected meter listener factory in context")
	}
}

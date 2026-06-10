package wasm

import (
	"context"
	"testing"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type mockFuncDef struct {
	api.FunctionDefinition
	modName  string
	funcName string
}

func (m *mockFuncDef) ModuleName() string { return m.modName }
func (m *mockFuncDef) Name() string       { return m.funcName }

func TestWasip1MeterFactory(t *testing.T) {
	meter := &NetByteCounter{}
	factory := newWasip1MeterFactory(meter)
	if factory == nil {
		t.Fatal("expected factory")
	}

	// Test NewFunctionListener wrong module
	l := factory.NewFunctionListener(&mockFuncDef{modName: "wrong", funcName: "sock_recv"})
	if l != nil {
		t.Fatal("expected nil listener for wrong module")
	}

	// Test NewFunctionListener unknown function
	l = factory.NewFunctionListener(&mockFuncDef{modName: wasi_snapshot_preview1.ModuleName, funcName: "unknown"})
	if l != nil {
		t.Fatal("expected nil listener for unknown function")
	}

	ctx := context.Background()
	mod := &mockModule{mem: &mockMemory{buf: make([]byte, 100)}}

	// Test sock_recv
	l = factory.NewFunctionListener(&mockFuncDef{modName: wasi_snapshot_preview1.ModuleName, funcName: "sock_recv"})
	if l == nil {
		t.Fatal("expected listener")
	}
	// Before
	mod.mem.buf[10] = 50 // datalen = 50
	l.Before(ctx, mod, nil, []uint64{0, 0, 0, 0, 10}, nil)
	// After
	l.After(ctx, mod, nil, nil)
	if meter.In() != 50 {
		t.Fatalf("expected 50 bytes in, got %d", meter.In())
	}
	l.Abort(ctx, mod, nil, nil)

	// Test sock_send
	l = factory.NewFunctionListener(&mockFuncDef{modName: wasi_snapshot_preview1.ModuleName, funcName: "sock_send"})
	// Before
	mod.mem.buf[20] = 30 // datalen = 30
	l.Before(ctx, mod, nil, []uint64{0, 0, 0, 0, 20}, nil)
	// After
	l.After(ctx, mod, nil, nil)
	if meter.Out() != 30 {
		t.Fatalf("expected 30 bytes out, got %d", meter.Out())
	}
	l.Abort(ctx, mod, nil, nil)

	// Test sock_accept
	l = factory.NewFunctionListener(&mockFuncDef{modName: wasi_snapshot_preview1.ModuleName, funcName: "sock_accept"})
	// Before
	mod.mem.buf[30] = 5 // fd = 5
	l.Before(ctx, mod, nil, []uint64{0, 0, 30}, nil)
	// After
	l.After(ctx, mod, nil, nil)
	if meter.In() != 51 { // 50 + 1
		t.Fatalf("expected 51 bytes in, got %d", meter.In())
	}
	l.Abort(ctx, mod, nil, nil)
}

func TestWithWasip1Meter(t *testing.T) {
	ctx := context.Background()
	hook := &NetworkHook{Meter: &NetByteCounter{}}

	ctx2 := withWasip1Meter(ctx, hook)
	if ctx2 == ctx {
		t.Fatal("expected new context")
	}

	ctx3 := withWasip1Meter(ctx, nil)
	if ctx3 != ctx {
		t.Fatal("expected same context")
	}

	ctx4 := withWasip1Meter(ctx, &NetworkHook{})
	if ctx4 != ctx {
		t.Fatal("expected same context")
	}
}

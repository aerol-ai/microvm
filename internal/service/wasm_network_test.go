package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

type wasmNetCounterRuntime struct {
	wasmRecordingRuntime
	deltas map[string]struct{ BytesIn, BytesOut int64 }
}

func (r *wasmNetCounterRuntime) DrainNetworkByteCounters() map[string]struct{ BytesIn, BytesOut int64 } {
	return r.deltas
}

func TestDrainWasmNetworkCountersRecordsSamples(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:          "sb-net-1",
		Runtime:     models.RuntimeWasm,
		Status:      models.SandboxStatusStarted,
		ContainerID: "wasm:sb-net-1",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	svc := New(config.Config{EnableWasm: true}, nil, st, nil, nil, nil, nil, nil, nil)
	svc.SetWasmRuntime(&wasmNetCounterRuntime{
		deltas: map[string]struct{ BytesIn, BytesOut int64 }{
			"sb-net-1": {BytesIn: 11, BytesOut: 22},
		},
	})

	svc.drainWasmNetworkCounters(ctx)

	got, err := st.Get(ctx, "sb-net-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.NetworkBytesIn != 11 || got.NetworkBytesOut != 22 {
		t.Fatalf("counters = in:%d out:%d, want 11/22", got.NetworkBytesIn, got.NetworkBytesOut)
	}
}

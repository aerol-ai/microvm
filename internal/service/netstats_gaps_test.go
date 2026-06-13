package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker/netstats"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestApplyNetworkQuotaState_NilSandbox covers the nil guard.
func TestApplyNetworkQuotaState_NilSandbox(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	// Must not panic.
	svc.applyNetworkQuotaState(context.Background(), nil, false, false)
}

// TestApplyNetworkQuotaState_WasmSandboxOverQuota exercises the WASM branch
// where overIn || overOut is true.
func TestApplyNetworkQuotaState_WasmSandboxOverQuota(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(rt)

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:           "sb-wasm-quota",
		Image:        "wasm://my.module",
		Runtime:      models.RuntimeWasm,
		Status:       models.SandboxStatusStarted,
		CPU:          1,
		MemoryMB:     128,
		DiskGB:       5,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	// overIn=true should call MarkNetworkQuotaExceeded via the wasm branch.
	svc.applyNetworkQuotaState(ctx, sb, true, false)

	got, err := st.Get(ctx, "sb-wasm-quota")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if !got.NetworkQuotaExceeded {
		t.Fatal("expected NetworkQuotaExceeded to be set after WASM over-quota")
	}
}

// TestApplyNetworkQuotaState_WasmSandboxClearQuota exercises the WASM branch
// where the quota is already exceeded but should be cleared.
func TestApplyNetworkQuotaState_WasmSandboxClearQuota(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(rt)

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:                   "sb-wasm-clear",
		Image:                "wasm://my.module",
		Runtime:              models.RuntimeWasm,
		Status:               models.SandboxStatusStarted,
		NetworkQuotaExceeded: true,
		CPU:                  1,
		MemoryMB:             128,
		DiskGB:               5,
		CreatedAt:            now,
		UpdatedAt:            now,
		LastActiveAt:         now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	// Mark as exceeded first.
	if err := st.MarkNetworkQuotaExceeded(ctx, "sb-wasm-clear", now); err != nil {
		t.Fatalf("MarkNetworkQuotaExceeded: %v", err)
	}

	// overIn=false, overOut=false should clear the flag.
	svc.applyNetworkQuotaState(ctx, sb, false, false)

	got, err := st.Get(ctx, "sb-wasm-clear")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if got.NetworkQuotaExceeded {
		t.Fatal("expected NetworkQuotaExceeded to be cleared")
	}
}

// TestApplyNetworkQuotaState_DockerNoIP verifies the no-ContainerIP path
// skips iptables but still updates the store flag.
func TestApplyNetworkQuotaState_DockerNoIP(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:           "sb-docker-no-ip",
		Image:        "alpine:3.20",
		Runtime:      models.RuntimeDocker,
		Status:       models.SandboxStatusStopped,
		ContainerIP:  "", // no IP → iptables skipped
		CPU:          1,
		MemoryMB:     128,
		DiskGB:       5,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	svc.applyNetworkQuotaState(ctx, sb, true /* overIn */, false)

	got, err := st.Get(ctx, "sb-docker-no-ip")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if !got.NetworkQuotaExceeded {
		t.Fatal("expected NetworkQuotaExceeded to be set even when no ContainerIP")
	}
}

// TestHandleNetworkSamples_EmptyNoop verifies early return on empty slice.
func TestHandleNetworkSamples_EmptyNoop(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	sink := netstatsServiceSink{svc: svc}
	// Must not panic and must not update netstatsLastTick.
	sink.handleNetworkSamples(context.Background(), nil)
	if svc.netstatsLastTick.Load() != 0 {
		t.Fatal("expected netstatsLastTick to remain 0 for empty samples")
	}
}

// TestHandleNetworkSamples_ZeroByteSampleRecordsActivity exercises the path
// where BytesIn==0 && BytesOut==0 but ActiveTCP=true.
func TestHandleNetworkSamples_ZeroByteSampleRecordsActivity(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	now := time.Now().UTC()
	seedNetstatsSandbox(t, st, &models.Sandbox{
		ID:          "sb-zero-byte",
		Image:       "alpine:3.20",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-zero-byte",
		ContainerIP: "10.0.0.20",
		CPU:         1,
		MemoryMB:    256,
		DiskGB:      5,
		OSUser:      "root",
	})

	sink := netstatsServiceSink{svc: svc}
	svc.netstatsActivity = make(map[string]int64)
	sampleAt := now.Add(-5 * time.Second)
	sink.handleNetworkSamples(ctx, []netstats.Sample{
		{SandboxID: "sb-zero-byte", BytesIn: 0, BytesOut: 0, ActiveTCP: true, SampledAt: sampleAt},
	})

	svc.netstatsActivityMu.RLock()
	recorded := svc.netstatsActivity["sb-zero-byte"]
	svc.netstatsActivityMu.RUnlock()
	if recorded != sampleAt.UnixNano() {
		t.Fatalf("netstatsActivity = %d, want %d (active TCP with zero bytes should record activity)",
			recorded, sampleAt.UnixNano())
	}
}

// TestHandleNetworkSamples_NonZeroBytesUpdatesCounters exercises the store
// update path with real byte deltas and quota check.
func TestHandleNetworkSamples_NonZeroBytesUpdatesCounters(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	now := time.Now().UTC()
	seedNetstatsSandbox(t, st, &models.Sandbox{
		ID:                   "sb-bytes",
		Image:                "alpine:3.20",
		Status:               models.SandboxStatusStarted,
		ContainerID:          "ctr-bytes",
		ContainerIP:          "10.0.0.21",
		CPU:                  1,
		MemoryMB:             256,
		DiskGB:               5,
		OSUser:               "root",
		NetworkBytesOutLimit: 500, // low limit so overOut fires
	})

	sink := netstatsServiceSink{svc: svc}
	svc.netstatsActivity = make(map[string]int64)
	sampleAt := now
	sink.handleNetworkSamples(ctx, []netstats.Sample{
		{SandboxID: "sb-bytes", BytesIn: 100, BytesOut: 600, SampledAt: sampleAt},
	})

	// Verify netstatsLastTick was updated.
	if svc.netstatsLastTick.Load() != sampleAt.UnixNano() {
		t.Fatalf("netstatsLastTick = %d, want %d", svc.netstatsLastTick.Load(), sampleAt.UnixNano())
	}

	// Verify counters were persisted.
	got, err := st.Get(ctx, "sb-bytes")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if got.NetworkBytesIn < 100 || got.NetworkBytesOut < 600 {
		t.Fatalf("counters not updated: in=%d out=%d", got.NetworkBytesIn, got.NetworkBytesOut)
	}
}

// TestHandleNetworkSamples_NotFoundSandboxSkips verifies ErrNotFound doesn't panic.
func TestHandleNetworkSamples_NotFoundSandboxSkips(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.netstatsActivity = make(map[string]int64)
	sink := netstatsServiceSink{svc: svc}
	now := time.Now().UTC()
	// Should not panic when sandbox doesn't exist in store.
	sink.handleNetworkSamples(context.Background(), []netstats.Sample{
		{SandboxID: "nonexistent", BytesIn: 100, BytesOut: 100, SampledAt: now},
	})
}

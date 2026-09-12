package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker/netstats"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestNetstatsSinkClosedStoreWave15(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-ns", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	sink := netstatsServiceSink{svc: svc}
	sink.handleNetworkSamples(ctx, nil)
	sink.handleNetworkSamples(ctx, []netstats.Sample{{
		SandboxID: "sb-ns", BytesIn: 1, BytesOut: 2, SampledAt: now, ActiveTCP: true,
	}})
	_ = st.Close()
	sink.handleNetworkSamples(ctx, []netstats.Sample{{
		SandboxID: "sb-ns", BytesIn: 3, BytesOut: 4, SampledAt: now,
	}})
	sink.handleNetworkSamples(ctx, []netstats.Sample{{
		SandboxID: "missing", BytesIn: 1, BytesOut: 0, SampledAt: now,
	}})

	svc2, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.cfg.NetstatsPollInterval = 0
	if err := svc2.EnsureNetstatsReady(ctx); err == nil {
		t.Fatal("expected interval fail")
	}
	svc2.cfg.NetstatsPollInterval = time.Second
	svc2.events = nil
	if err := svc2.EnsureNetstatsReady(ctx); err == nil {
		t.Fatal("expected events fail")
	}
	svc2.netstatsReady.Store(true)
	if err := svc2.EnsureNetstatsReady(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureNetstatsReadyConcurrentWave17(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.NetstatsPollInterval = time.Second
	svc.events = nil
	done := make(chan struct{})
	go func() {
		_ = svc.EnsureNetstatsReady(context.Background())
		close(done)
	}()
	_ = svc.EnsureNetstatsReady(context.Background())
	<-done
}

func TestNetstatsRefetchWarnWave23(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	_ = st.Create(context.Background(), &models.Sandbox{
		ID: "sb-ns", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	sink := netstatsServiceSink{svc: svc}
	_ = st.UpdateSandboxNetCounters(context.Background(), "sb-ns", 10, 20)
	_ = st.Close()
	sink.handleNetworkSamples(context.Background(), []netstats.Sample{{
		SandboxID: "sb-ns", BytesIn: 1, BytesOut: 2, SampledAt: now,
	}})
	sink.handleNetworkSamples(context.Background(), []netstats.Sample{{
		SandboxID: "gone", BytesIn: 1, BytesOut: 2, SampledAt: now,
	}})
	sink.handleNetworkSamples(context.Background(), nil)
}

func TestNetstatsGetAfterUpdateFailWave24(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	_ = st.Create(context.Background(), &models.Sandbox{
		ID: "sb-ns24", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	svc.testAfterNetstatsUpdate = func() { _ = st.Close() }
	netstatsServiceSink{svc: svc}.handleNetworkSamples(context.Background(), []netstats.Sample{{
		SandboxID: "sb-ns24", BytesIn: 5, BytesOut: 6, SampledAt: now,
	}})
}

func TestNetstatsRefetchNotFoundAndWarnWave25(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	_ = st.Create(context.Background(), &models.Sandbox{
		ID: "sb-ns25", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	// Delete sandbox after update so Get returns NotFound (continue arm).
	svc.testAfterNetstatsUpdate = func() { _ = st.Delete(context.Background(), "sb-ns25") }
	netstatsServiceSink{svc: svc}.handleNetworkSamples(context.Background(), []netstats.Sample{{
		SandboxID: "sb-ns25", BytesIn: 1, BytesOut: 1, SampledAt: now, ActiveTCP: true,
	}})

	svc2, st2, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	_ = st2.Create(context.Background(), &models.Sandbox{
		ID: "sb-ns25b", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	svc2.testAfterNetstatsUpdate = func() { _ = st2.Close() }
	netstatsServiceSink{svc: svc2}.handleNetworkSamples(context.Background(), []netstats.Sample{{
		SandboxID: "sb-ns25b", BytesIn: 2, BytesOut: 2, SampledAt: now,
	}})
}

type quotaFailRuntime struct {
	*recordingRuntime
	blockAllErr     error
	blockIngressErr error
	clearEgressErr  error
	clearIngressErr error
}

func (r *quotaFailRuntime) ApplyNetworkBlockAll(string) error { return r.blockAllErr }

func (r *quotaFailRuntime) ApplyNetworkBlockIngress(string) error { return r.blockIngressErr }

func (r *quotaFailRuntime) ClearNetworkBlockEgress(string) error { return r.clearEgressErr }

func (r *quotaFailRuntime) ClearNetworkBlockIngress(string) error { return r.clearIngressErr }

func TestApplyNetworkQuotaStateArmsWave8(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.applyNetworkQuotaState(ctx, nil, true, false)

	now := time.Now().UTC()
	wasm := &models.Sandbox{
		ID: "sb-wq", Image: "m", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now, NetworkQuotaExceeded: true,
	}
	if err := st.Create(ctx, wasm); err != nil {
		t.Fatal(err)
	}
	svc.applyNetworkQuotaState(ctx, wasm, false, false) // clear
	svc.applyNetworkQuotaState(ctx, wasm, true, false)  // mark

	failRT := &quotaFailRuntime{
		recordingRuntime: &recordingRuntime{},
		blockAllErr:      errors.New("block all"),
		blockIngressErr:  errors.New("block in"),
		clearEgressErr:   errors.New("clear eg"),
		clearIngressErr:  errors.New("clear in"),
	}
	svc.docker = failRT
	dockerSB := &models.Sandbox{
		ID: "sb-dq", Image: "alpine", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.9",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now, NetworkQuotaExceeded: true,
	}
	if err := st.Create(ctx, dockerSB); err != nil {
		t.Fatal(err)
	}
	svc.applyNetworkQuotaState(ctx, dockerSB, true, true)
	svc.applyNetworkQuotaState(ctx, dockerSB, false, false)

	// No IP → skip iptables, still touch store flags.
	noIP := &models.Sandbox{ID: "sb-noip", Image: "alpine", Status: models.SandboxStatusStopped, NetworkQuotaExceeded: true}
	if err := st.Create(ctx, noIP); err != nil {
		t.Fatal(err)
	}
	svc.applyNetworkQuotaState(ctx, noIP, false, false)

	_ = st.Close()
	svc.applyNetworkQuotaState(ctx, dockerSB, true, false) // mark warn on closed store
}

func TestEnsureNetstatsReadyWave8(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.NetstatsPollInterval = 0
	if err := svc.EnsureNetstatsReady(ctx); err == nil || !strings.Contains(err.Error(), "poll interval") {
		t.Fatalf("interval = %v", err)
	}
	svc.cfg.NetstatsPollInterval = time.Hour
	svc.events = nil
	if err := svc.EnsureNetstatsReady(ctx); err == nil || !strings.Contains(err.Error(), "events client") {
		t.Fatalf("events = %v", err)
	}
	svc.SetEventsSource(stubEventsSource{})
	// Stub events StreamEvents fails; poller.Start may still succeed depending on impl.
	_ = svc.EnsureNetstatsReady(ctx)
	_ = svc.EnsureNetstatsReady(ctx) // latched / second call
}

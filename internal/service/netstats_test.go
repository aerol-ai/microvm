package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netstats"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestEnsureNetstatsReadyLatches(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.NetstatsPollInterval = time.Hour
	svc.events = &docker.Client{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := svc.EnsureNetstatsReady(ctx); err != nil {
		t.Fatalf("EnsureNetstatsReady() error = %v", err)
	}
	if !svc.netstatsReady.Load() {
		t.Fatal("netstats ready latch should be true after successful bootstrap")
	}
	poller := svc.netstatsPoller
	if poller == nil {
		t.Fatal("expected netstats poller to be stored")
	}
	if err := svc.EnsureNetstatsReady(ctx); err != nil {
		t.Fatalf("EnsureNetstatsReady() second call error = %v", err)
	}
	if svc.netstatsPoller != poller {
		t.Fatal("netstats poller should be reused after the latch flips")
	}
}

func TestGetNetworkUsageReturnsStoredCountersWhenBootstrapFails(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg = config.Config{}

	quotaAt := time.Now().UTC().Add(-time.Minute)
	sampleAt := time.Now().UTC()
	svc.netstatsLastTick.Store(sampleAt.UnixNano())
	seedNetstatsSandbox(t, st, &models.Sandbox{
		ID:                     "sb-usage",
		Image:                  "alpine:3.20",
		Status:                 models.SandboxStatusStarted,
		ContainerID:            "ctr-usage",
		ContainerIP:            "10.0.0.10",
		CPU:                    1,
		MemoryMB:               256,
		DiskGB:                 5,
		OSUser:                 "root",
		NetworkBytesIn:         123,
		NetworkBytesOut:        456,
		NetworkBytesInLimit:    1000,
		NetworkBytesOutLimit:   2000,
		NetworkQuotaExceeded:   true,
		NetworkQuotaExceededAt: &quotaAt,
	})

	usage, err := svc.GetNetworkUsage(ctx, "sb-usage")
	if err != nil {
		t.Fatalf("GetNetworkUsage() error = %v", err)
	}
	if usage.BytesIn != 123 || usage.BytesOut != 456 {
		t.Fatalf("usage counters = %+v, want 123/456", usage)
	}
	if usage.BytesInLimit != 1000 || usage.BytesOutLimit != 2000 {
		t.Fatalf("usage limits = %+v, want 1000/2000", usage)
	}
	if usage.LastSampledAt == nil || !usage.LastSampledAt.Equal(sampleAt) {
		t.Fatalf("last sampled at = %v, want %v", usage.LastSampledAt, sampleAt)
	}
	if svc.netstatsReady.Load() {
		t.Fatal("bootstrap failure should not flip the netstats ready latch")
	}
}

func TestSetNetworkLimitsAppliesAndClearsQuotaState(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	seedNetstatsSandbox(t, st, &models.Sandbox{
		ID:              "sb-limits",
		Image:           "alpine:3.20",
		Status:          models.SandboxStatusStarted,
		ContainerID:     "ctr-limits",
		ContainerIP:     "10.0.0.11",
		CPU:             1,
		MemoryMB:        256,
		DiskGB:          5,
		OSUser:          "root",
		NetworkBytesIn:  120,
		NetworkBytesOut: 220,
	})

	usage, err := svc.SetNetworkLimits(ctx, "sb-limits", 100, 200)
	if err != nil {
		t.Fatalf("SetNetworkLimits() apply error = %v", err)
	}
	if !usage.QuotaExceeded {
		t.Fatal("quota should be marked exceeded once counters are over the limits")
	}
	if got := len(rt.applyNetworkBlockAllCalls); got != 1 {
		t.Fatalf("egress block calls = %d, want 1", got)
	}
	if got := len(rt.applyNetworkBlockIngresses); got != 1 {
		t.Fatalf("ingress block calls = %d, want 1", got)
	}

	clearedUsage, err := svc.SetNetworkLimits(ctx, "sb-limits", 500, 500)
	if err != nil {
		t.Fatalf("SetNetworkLimits() clear error = %v", err)
	}
	if clearedUsage.QuotaExceeded {
		t.Fatal("quota should clear after the limits move above current usage")
	}
	if got := len(rt.clearNetworkBlockEgresses); got != 1 {
		t.Fatalf("egress clear calls = %d, want 1", got)
	}
	if got := len(rt.clearNetworkBlockIngresses); got != 1 {
		t.Fatalf("ingress clear calls = %d, want 1", got)
	}
	stored, err := st.Get(ctx, "sb-limits")
	if err != nil {
		t.Fatalf("store.Get() after limit clear error = %v", err)
	}
	if stored.NetworkQuotaExceeded {
		t.Fatal("store row still marked over quota after limits were raised")
	}
}

func TestNetstatsTargetsAndHandleSamples(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	seedNetstatsSandbox(t, st, &models.Sandbox{
		ID:                   "sb-sample",
		Image:                "alpine:3.20",
		Status:               models.SandboxStatusStarted,
		ContainerID:          "",
		ContainerIP:          "10.0.0.12",
		CPU:                  1,
		MemoryMB:             256,
		DiskGB:               5,
		OSUser:               "root",
		NetworkBytesInLimit:  50,
		NetworkBytesOutLimit: 70,
	})
	seedNetstatsSandbox(t, st, &models.Sandbox{
		ID:          "sb-stopped",
		Image:       "alpine:3.20",
		Status:      models.SandboxStatusStopped,
		ContainerID: "ctr-stopped",
		ContainerIP: "10.0.0.13",
		CPU:         1,
		MemoryMB:    256,
		DiskGB:      5,
		OSUser:      "root",
	})

	targets := netstatsServiceLister{svc: svc}.NetstatsTargets(ctx)
	if len(targets) != 1 {
		t.Fatalf("netstats targets = %v, want one started sandbox", targets)
	}
	if targets[0].SandboxID != "sb-sample" || targets[0].ContainerRef != "sb-sample" {
		t.Fatalf("netstats target = %+v, want sandbox id fallback container ref", targets[0])
	}

	sampledAt := time.Now().UTC()
	netstatsServiceSink{svc: svc}.HandleSamples(ctx, []netstats.Sample{
		{SandboxID: "sb-sample", BytesIn: 60, BytesOut: 80, SampledAt: sampledAt},
		{SandboxID: "sb-sample", BytesIn: 0, BytesOut: 0, SampledAt: sampledAt},
		{SandboxID: "sb-missing", BytesIn: 1, BytesOut: 1, SampledAt: sampledAt},
	})

	stored, err := st.Get(ctx, "sb-sample")
	if err != nil {
		t.Fatalf("store.Get() after samples error = %v", err)
	}
	if stored.NetworkBytesIn != 60 || stored.NetworkBytesOut != 80 {
		t.Fatalf("stored counters = in:%d out:%d, want 60/80", stored.NetworkBytesIn, stored.NetworkBytesOut)
	}
	if !stored.NetworkQuotaExceeded {
		t.Fatal("quota should be marked exceeded after over-limit sample")
	}
	if len(rt.applyNetworkBlockAllCalls) == 0 || len(rt.applyNetworkBlockIngresses) == 0 {
		t.Fatalf("quota block calls missing: all=%v ingress=%v", rt.applyNetworkBlockAllCalls, rt.applyNetworkBlockIngresses)
	}
	if got := svc.netstatsLastTick.Load(); got != sampledAt.UnixNano() {
		t.Fatalf("netstats last tick = %d, want %d", got, sampledAt.UnixNano())
	}
}

func TestNetstatsActivityIncludesOutboundAndActiveTCP(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	for _, id := range []string{"sb-outbound", "sb-active"} {
		seedNetstatsSandbox(t, st, &models.Sandbox{
			ID:          id,
			Image:       "alpine:3.20",
			Status:      models.SandboxStatusStarted,
			ContainerID: "ctr-" + id,
			ContainerIP: "10.0.0.20",
			CPU:         1,
			MemoryMB:    256,
			DiskGB:      5,
			OSUser:      "root",
		})
	}

	sampledAt := time.Now().UTC()
	netstatsServiceSink{svc: svc}.HandleSamples(ctx, []netstats.Sample{
		{SandboxID: "sb-outbound", BytesOut: 12, SampledAt: sampledAt},
		{SandboxID: "sb-active", ActiveTCP: true, SampledAt: sampledAt},
	})

	if got := svc.netstatsRecentActivityAt("sb-outbound"); !got.Equal(sampledAt) {
		t.Fatalf("outbound activity = %v, want %v", got, sampledAt)
	}
	if got := svc.netstatsRecentActivityAt("sb-active"); !got.Equal(sampledAt) {
		t.Fatalf("active TCP activity = %v, want %v", got, sampledAt)
	}
	active, err := st.Get(ctx, "sb-active")
	if err != nil {
		t.Fatalf("store.Get(active): %v", err)
	}
	if active.NetworkBytesIn != 0 || active.NetworkBytesOut != 0 {
		t.Fatalf("active TCP zero-byte sample changed counters: in=%d out=%d", active.NetworkBytesIn, active.NetworkBytesOut)
	}
}

func seedNetstatsSandbox(t *testing.T, st *storepkg.Store, sandbox *models.Sandbox) {
	t.Helper()
	now := time.Now().UTC()
	if sandbox.CreatedAt.IsZero() {
		sandbox.CreatedAt = now
	}
	if sandbox.UpdatedAt.IsZero() {
		sandbox.UpdatedAt = now
	}
	if sandbox.LastActiveAt.IsZero() {
		sandbox.LastActiveAt = now
	}
	if err := st.Create(context.Background(), sandbox); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
}

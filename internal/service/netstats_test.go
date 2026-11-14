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

func TestNetstatsErrorBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("bootstrap validation", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.NetstatsPollInterval = 0
		svc.events = &docker.Client{}
		if err := svc.EnsureNetstatsReady(ctx); err == nil {
			t.Fatal("EnsureNetstatsReady should reject zero interval")
		}

		svc.cfg.NetstatsPollInterval = time.Second
		svc.events = nil
		if err := svc.EnsureNetstatsReady(ctx); err == nil {
			t.Fatal("EnsureNetstatsReady should reject nil events client")
		}
	})

	t.Run("limit validation and unsupported runtime", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-fc",
			Image:        "alpine:3.20",
			Status:       models.SandboxStatusStarted,
			Runtime:      models.RuntimeFirecracker,
			ContainerID:  "ctr-fc",
			ContainerIP:  "10.0.0.11",
			CPU:          1,
			MemoryMB:     256,
			DiskGB:       5,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed firecracker sandbox: %v", err)
		}
		if _, err := svc.SetNetworkLimits(ctx, "sb-fc", -1, 1); err == nil {
			t.Fatal("SetNetworkLimits should reject negative limits")
		}
		if _, err := svc.SetNetworkLimits(ctx, "sb-fc", 1, 1); err == nil {
			t.Fatal("SetNetworkLimits should reject firecracker network limits")
		}
	})

	t.Run("quota state and target error paths", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		seedNetstatsSandbox(t, st, &models.Sandbox{
			ID:          "sb-quota",
			Image:       "alpine:3.20",
			Status:      models.SandboxStatusStarted,
			ContainerID: "ctr-quota",
			ContainerIP: "10.0.0.12",
			Runtime:     models.RuntimeDocker,
			CPU:         1,
			MemoryMB:    256,
			DiskGB:      5,
		})
		svc.docker = noContainerRuntime{}
		row, err := st.Get(ctx, "sb-quota")
		if err != nil {
			t.Fatalf("store.Get(): %v", err)
		}
		svc.applyNetworkQuotaState(ctx, row, true, true)
		row.NetworkQuotaExceeded = true
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		svc.applyNetworkQuotaState(ctx, row, false, false)
		if got := (netstatsServiceLister{svc: svc}).NetstatsTargets(ctx); got != nil {
			t.Fatalf("NetstatsTargets on closed store = %v, want nil", got)
		}
		(netstatsServiceSink{svc: svc}).handleNetworkSamples(ctx, []netstats.Sample{
			{SandboxID: "sb-quota", BytesIn: 1, BytesOut: 2, SampledAt: time.Now().UTC()},
		})
	})
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

// TestNetstatsBatchReReadsOnlyQuotaRows pins the batched sink: a sandbox under
// its caps is counted and billed from the counter UPDATE alone, while one
// still flagged over quota takes the re-read path and has the flag lifted
// once a raised cap puts it back under.
func TestNetstatsBatchReReadsOnlyQuotaRows(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	reporter := &captureReporter{}
	svc.usageReporter = reporter
	for _, id := range []string{"sb-under", "sb-lifted"} {
		seedNetstatsSandbox(t, st, &models.Sandbox{
			ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted,
			ContainerID: "ctr-" + id, ContainerIP: "10.0.0.30", Runtime: models.RuntimeDocker,
			CPU: 1, MemoryMB: 256, DiskGB: 5, OSUser: "root", OwnerRef: "acme",
		})
	}
	if err := st.SetNetworkLimits(ctx, "sb-under", 1000, 1000); err != nil {
		t.Fatalf("SetNetworkLimits(under): %v", err)
	}
	if err := st.MarkNetworkQuotaExceeded(ctx, "sb-lifted", time.Now().UTC()); err != nil {
		t.Fatalf("MarkNetworkQuotaExceeded: %v", err)
	}

	sampledAt := time.Now().UTC()
	netstatsServiceSink{svc: svc}.handleNetworkSamples(ctx, []netstats.Sample{
		{SandboxID: "sb-under", BytesIn: 10, BytesOut: 20, SampledAt: sampledAt},
		{SandboxID: "sb-lifted", BytesIn: 5, BytesOut: 5, SampledAt: sampledAt},
	})

	under, err := st.Get(ctx, "sb-under")
	if err != nil {
		t.Fatalf("Get(under): %v", err)
	}
	if under.NetworkBytesIn != 10 || under.NetworkBytesOut != 20 || under.NetworkQuotaExceeded {
		t.Fatalf("under = in:%d out:%d flagged:%v, want 10/20 unflagged", under.NetworkBytesIn, under.NetworkBytesOut, under.NetworkQuotaExceeded)
	}
	lifted, err := st.Get(ctx, "sb-lifted")
	if err != nil {
		t.Fatalf("Get(lifted): %v", err)
	}
	if lifted.NetworkQuotaExceeded {
		t.Fatal("flag should be lifted: no cap is set, so the sandbox is under quota")
	}
	if len(rt.applyNetworkBlockAllCalls) != 0 {
		t.Fatalf("no sandbox is over a cap, yet block calls = %v", rt.applyNetworkBlockAllCalls)
	}

	var ingress int
	for _, sample := range reporter.all() {
		if sample.Kind != usageKindIngress {
			continue
		}
		ingress++
		if sample.OwnerRef != "acme" {
			t.Fatalf("usage owner = %q, want the owner_ref read back by the UPDATE", sample.OwnerRef)
		}
	}
	if ingress != 2 {
		t.Fatalf("ingress usage samples = %d, want one per applied sandbox", ingress)
	}
}

// TestNetstatsBatchBillsEachSampleOnce covers one sandbox appearing twice in a
// call: both deltas are stored, and usage is billed per sample, not twice
// for the last one.
func TestNetstatsBatchBillsEachSampleOnce(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	reporter := &captureReporter{}
	svc.usageReporter = reporter
	seedNetstatsSandbox(t, st, &models.Sandbox{
		ID: "sb-twice", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-twice", ContainerIP: "10.0.0.31", Runtime: models.RuntimeDocker,
		CPU: 1, MemoryMB: 256, DiskGB: 5, OSUser: "root",
	})
	first := time.Now().UTC()
	netstatsServiceSink{svc: svc}.handleNetworkSamples(ctx, []netstats.Sample{
		{SandboxID: "sb-twice", BytesIn: 100, SampledAt: first},
		{SandboxID: "sb-twice", BytesIn: 7, SampledAt: first.Add(time.Second)},
	})

	got, err := st.Get(ctx, "sb-twice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.NetworkBytesIn != 107 {
		t.Fatalf("stored bytes in = %d, want 107", got.NetworkBytesIn)
	}
	var billed float64
	for _, sample := range reporter.all() {
		if sample.Kind == usageKindIngress {
			billed += sample.Value
		}
	}
	if billed != 107 {
		t.Fatalf("billed ingress = %v, want 107 (each sample once)", billed)
	}
}

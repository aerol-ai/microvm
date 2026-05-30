package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
)

// fakeStats returns a single scripted CPU/memory snapshot for any container ref
// (the harness's one running sandbox). Update cur between sweeps.
type fakeStats struct{ cur docker.ContainerStat }

func (f *fakeStats) fetch(_ context.Context, _ string) (docker.ContainerStat, error) {
	return f.cur, nil
}

func TestSampleLiveUsageEmitsDeltas(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	r := &captureReporter{}
	svc.SetUsageReporter(r)

	createOwned(t, svc, "acme", "sb-live")

	t1 := time.Unix(1_700_000_000, 0).UTC()
	t2 := t1.Add(10 * time.Second)

	// First reading: anchors the cursor, emits nothing (no window yet).
	stats := &fakeStats{cur: docker.ContainerStat{CPUTotalNanos: 1_000_000_000, MemBytes: 256 * 1024 * 1024}}
	svc.sampleLiveUsageOnce(context.Background(), t1, stats.fetch)
	if got := r.all(); len(got) != 0 {
		t.Fatalf("first reading should emit nothing, got %d", len(got))
	}

	// Second reading: +5s of CPU over a 10s window, 512 MiB resident.
	stats.cur = docker.ContainerStat{CPUTotalNanos: 6_000_000_000, MemBytes: 512 * 1024 * 1024}
	svc.sampleLiveUsageOnce(context.Background(), t2, stats.fetch)

	got := byKind(r.all())
	cpu, ok := got[usageKindCPULive]
	if !ok {
		t.Fatal("missing cpu_live sample")
	}
	if cpu.Value != 5 || cpu.Unit != usageUnitVCPUSecond {
		t.Fatalf("cpu_live = %v %s, want 5 vcpu-s", cpu.Value, cpu.Unit)
	}
	if cpu.WindowStart != t1 || cpu.WindowEnd != t2 {
		t.Fatalf("cpu_live window = [%v,%v], want [%v,%v]", cpu.WindowStart, cpu.WindowEnd, t1, t2)
	}
	if cpu.OwnerRef != "acme" {
		t.Fatalf("cpu_live owner = %q, want acme", cpu.OwnerRef)
	}
	mem, ok := got[usageKindMemLive]
	if !ok {
		t.Fatal("missing mem_live sample")
	}
	// 512 MiB * 10 s = 5120 mib-s.
	if mem.Value != 512*10 || mem.Unit != usageUnitMiBSecond {
		t.Fatalf("mem_live = %v %s, want 5120 mib-s", mem.Value, mem.Unit)
	}
}

func TestSampleLiveUsageCounterResetSkipsCPU(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	r := &captureReporter{}
	svc.SetUsageReporter(r)
	createOwned(t, svc, "acme", "sb-reset")

	stats := &fakeStats{cur: docker.ContainerStat{CPUTotalNanos: 9_000_000_000, MemBytes: 128 * 1024 * 1024}}
	base := time.Unix(1_700_000_000, 0).UTC()
	svc.sampleLiveUsageOnce(context.Background(), base, stats.fetch)
	// Counter went backwards (container restarted) → no cpu_live, but mem_live
	// still emits.
	stats.cur = docker.ContainerStat{CPUTotalNanos: 1_000_000_000, MemBytes: 128 * 1024 * 1024}
	svc.sampleLiveUsageOnce(context.Background(), base.Add(time.Second), stats.fetch)
	got := byKind(r.all())
	if _, ok := got[usageKindCPULive]; ok {
		t.Fatal("counter reset must not emit cpu_live")
	}
	if _, ok := got[usageKindMemLive]; !ok {
		t.Fatal("mem_live should still emit on counter reset")
	}
}

func TestSampleLiveUsagePrunesStoppedSandboxes(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	r := &captureReporter{}
	svc.SetUsageReporter(r)
	id := createOwned(t, svc, "acme", "sb-prune")

	stats := &fakeStats{cur: docker.ContainerStat{CPUTotalNanos: 1_000_000_000, MemBytes: 64 * 1024 * 1024}}
	svc.sampleLiveUsageOnce(context.Background(), time.Unix(1_700_000_000, 0).UTC(), stats.fetch)
	if _, ok := svc.liveCursorPoint(id); !ok {
		t.Fatal("cursor should be set after first reading")
	}

	// Stop it; the next sweep sees it not-Started and prunes the cursor.
	if _, err := svc.StopSandbox(context.Background(), id); err != nil {
		t.Fatalf("StopSandbox: %v", err)
	}
	svc.sampleLiveUsageOnce(context.Background(), time.Unix(1_700_000_010, 0).UTC(), stats.fetch)
	if _, ok := svc.liveCursorPoint(id); ok {
		t.Fatal("cursor should be pruned after the sandbox stopped")
	}
}

func TestStartLiveUsageSamplerDisabledByDefault(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.SetUsageReporter(&captureReporter{})
	// cfg.FleetLiveSampleInterval is 0 in the harness → no goroutine, returns at once.
	svc.StartLiveUsageSampler(context.Background())
	// Also a no-op when an interval is set but no reporter is wired.
	svc.usageReporter = nil
	svc.cfg.FleetLiveSampleInterval = time.Second
	svc.StartLiveUsageSampler(context.Background())
}

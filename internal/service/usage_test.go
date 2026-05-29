package service

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// captureReporter records every batch it receives.
type captureReporter struct {
	mu      sync.Mutex
	batches [][]controlplane.Sample
}

func (c *captureReporter) Report(_ context.Context, batch []controlplane.Sample) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]controlplane.Sample, len(batch))
	copy(cp, batch)
	c.batches = append(c.batches, cp)
	return nil
}

func (c *captureReporter) all() []controlplane.Sample {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []controlplane.Sample
	for _, b := range c.batches {
		out = append(out, b...)
	}
	return out
}

func newUsageService(r controlplane.Reporter) *Service {
	return &Service{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:           config.Config{ReconcileInterval: time.Minute, NetstatsPollInterval: 10 * time.Second},
		usageReporter: r,
	}
}

func byKind(samples []controlplane.Sample) map[string]controlplane.Sample {
	m := make(map[string]controlplane.Sample, len(samples))
	for _, s := range samples {
		m[s.Kind] = s
	}
	return m
}

func TestAppendReservedSamples(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC()
	end := start.Add(time.Minute) // 60s window
	started := &models.Sandbox{
		ID: "sb1", OwnerRef: "acme", Status: models.SandboxStatusStarted,
		CPU: 2, MemoryMB: 1024, DiskGB: 10,
		GPUs: &models.GPURequest{Vendor: "nvidia", Count: 2},
	}

	got := byKind(appendReservedSamples(nil, started, start, end))
	// Started → uptime + cpu + mem + disk + gpu.
	for _, k := range []string{usageKindUptime, usageKindCPUReserved, usageKindMemReserved, usageKindDiskReserved, usageKindGPU} {
		if _, ok := got[k]; !ok {
			t.Fatalf("started sandbox missing kind %q", k)
		}
	}
	if got[usageKindUptime].Value != 60 || got[usageKindUptime].Unit != usageUnitSeconds {
		t.Fatalf("uptime = %v %s, want 60 s", got[usageKindUptime].Value, got[usageKindUptime].Unit)
	}
	if got[usageKindCPUReserved].Value != 120 { // 2 vcpu * 60s
		t.Fatalf("cpu_reserved = %v, want 120", got[usageKindCPUReserved].Value)
	}
	if got[usageKindMemReserved].Value != 1024*60 {
		t.Fatalf("mem_reserved = %v, want %v", got[usageKindMemReserved].Value, 1024*60)
	}
	if got[usageKindGPU].Value != 120 { // 2 gpu * 60s
		t.Fatalf("gpu = %v, want 120", got[usageKindGPU].Value)
	}
	if got[usageKindUptime].OwnerRef != "acme" {
		t.Fatalf("owner_ref not propagated: %q", got[usageKindUptime].OwnerRef)
	}

	// Stopped → disk only (charged while parked); no compute/uptime.
	stopped := &models.Sandbox{ID: "sb2", Status: models.SandboxStatusStopped, CPU: 4, MemoryMB: 2048, DiskGB: 20}
	gotStopped := byKind(appendReservedSamples(nil, stopped, start, end))
	if _, ok := gotStopped[usageKindDiskReserved]; !ok {
		t.Fatalf("stopped sandbox should still emit disk_reserved")
	}
	for _, k := range []string{usageKindUptime, usageKindCPUReserved, usageKindMemReserved} {
		if _, ok := gotStopped[k]; ok {
			t.Fatalf("stopped sandbox must not emit %q", k)
		}
	}
}

func TestUsageEventIDStableAndDistinct(t *testing.T) {
	w := time.Unix(1_700_000_000, 0).UTC()
	a := usageEventID("sb1", usageKindUptime, w)
	if a != usageEventID("sb1", usageKindUptime, w) {
		t.Fatalf("event id not stable for identical inputs")
	}
	if a == usageEventID("sb1", usageKindCPUReserved, w) {
		t.Fatalf("event id collided across kinds")
	}
	if a == usageEventID("sb2", usageKindUptime, w) {
		t.Fatalf("event id collided across sandboxes")
	}
	if a == usageEventID("sb1", usageKindUptime, w.Add(time.Second)) {
		t.Fatalf("event id collided across windows")
	}
}

func TestEmitReservedUsageTilesWindows(t *testing.T) {
	r := &captureReporter{}
	s := newUsageService(r)
	t1 := time.Unix(1_700_000_000, 0).UTC()
	t2 := t1.Add(time.Minute)
	sandboxes := []*models.Sandbox{
		{ID: "sb1", OwnerRef: "acme", Status: models.SandboxStatusStarted, CPU: 1, MemoryMB: 512, DiskGB: 5, CreatedAt: t1.Add(-time.Hour)},
	}

	// First sweep ends at t1; cursor → t1.
	s.emitReservedUsageAt(context.Background(), sandboxes, t1)
	first := byKind(r.all())
	if len(first) == 0 || first[usageKindUptime].WindowEnd != t1 {
		t.Fatalf("first sweep windowEnd = %v, want %v", first[usageKindUptime].WindowEnd, t1)
	}

	// Second sweep ends at t2; its window must start exactly where the first
	// ended (contiguous tiling, no gap/overlap).
	r.batches = nil
	s.emitReservedUsageAt(context.Background(), sandboxes, t2)
	second := byKind(r.all())
	if second[usageKindUptime].WindowStart != t1 {
		t.Fatalf("second sweep windowStart = %v, want %v (contiguous with first)", second[usageKindUptime].WindowStart, t1)
	}
	if second[usageKindUptime].Value != 60 {
		t.Fatalf("second window uptime = %v, want 60", second[usageKindUptime].Value)
	}
}

func TestEmitReservedUsageNoReporterIsNoop(t *testing.T) {
	s := newUsageService(nil) // open-source posture
	// Must not panic and must allocate no cursor work.
	s.emitReservedUsage(context.Background(), []*models.Sandbox{{ID: "x", Status: models.SandboxStatusStarted}})
}

func TestEmitNetworkUsage(t *testing.T) {
	r := &captureReporter{}
	s := newUsageService(r)
	sb := &models.Sandbox{ID: "sb1", OwnerRef: "acme"}
	now := time.Unix(1_700_000_000, 0).UTC()

	s.emitNetworkUsage(context.Background(), sb, 1000, 2000, now)
	got := byKind(r.all())
	if got[usageKindIngress].Value != 1000 || got[usageKindIngress].Unit != usageUnitBytes {
		t.Fatalf("ingress = %v %s, want 1000 bytes", got[usageKindIngress].Value, got[usageKindIngress].Unit)
	}
	if got[usageKindEgress].Value != 2000 {
		t.Fatalf("egress = %v, want 2000", got[usageKindEgress].Value)
	}
	if got[usageKindEgress].OwnerRef != "acme" {
		t.Fatalf("owner_ref not propagated on egress")
	}

	// Zero deltas emit nothing.
	r.batches = nil
	s.emitNetworkUsage(context.Background(), sb, 0, 0, now)
	if len(r.all()) != 0 {
		t.Fatalf("zero-delta should emit nothing")
	}
}

func TestEmitLifecycleStopUsage(t *testing.T) {
	r := &captureReporter{}
	s := newUsageService(r)
	created := time.Now().Add(-2 * time.Minute)
	sb := &models.Sandbox{ID: "sb1", OwnerRef: "acme", Status: models.SandboxStatusStopped, CPU: 1, MemoryMB: 256, DiskGB: 5, CreatedAt: created}

	// Stop edge meters the running tail even though the row reads Stopped.
	edge := time.Now().UTC()
	s.emitLifecycleStopUsage(context.Background(), sb, edge, false)
	got := byKind(r.all())
	if _, ok := got[usageKindUptime]; !ok {
		t.Fatalf("stop edge should meter uptime tail")
	}
	if got[usageKindUptime].WindowEnd != edge {
		t.Fatalf("stop edge windowEnd = %v, want %v", got[usageKindUptime].WindowEnd, edge)
	}
	// Same-instant second edge has a zero-width window → emits nothing.
	r.batches = nil
	s.emitLifecycleStopUsage(context.Background(), sb, edge, true)
	if got := r.all(); len(got) != 0 {
		t.Fatalf("zero-width stop edge should emit nothing, got %d", len(got))
	}
	// drop=true forgot the cursor.
	s.usageMu.Lock()
	_, present := s.usageCursor[sb.ID]
	s.usageMu.Unlock()
	if present {
		t.Fatalf("destroy edge (drop=true) should forget the cursor")
	}
}

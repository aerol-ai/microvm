package netns

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/createtiming"
)

// slowRealizeHost makes the inline build measurably slow, so the test can tell
// a measured stage from a hard-coded zero.
type slowRealizeHost struct {
	*FakeHost
	delay time.Duration
}

func (s slowRealizeHost) Realize(ctx context.Context, slot Slot) (string, string, error) {
	time.Sleep(s.delay)
	return s.FakeHost.Realize(ctx, slot)
}

// Plan PR #1000 item L1: a containerd create's Server-Timing must say how long
// its network namespace took and whether the warm queue served it. Before,
// the driver recorded containerd_netns as a fixed 0 with desc "provisioned",
// and the docs published that 0 as "Network setup 0 ms".
func TestProvisionRecordsNetnsStageHitAndMiss(t *testing.T) {
	ctx := context.Background()
	p := testPool(t, 2)
	const delay = 20 * time.Millisecond
	host := slowRealizeHost{FakeHost: NewFakeHost(), delay: delay}
	h := NewRuntimeHandoff(p, host)

	// Miss: nothing is prewarmed, so Provision builds the namespace inline.
	missCtx, missTiming := createtiming.With(ctx)
	if _, _, err := h.Provision(missCtx, "sb-miss"); err != nil {
		t.Fatalf("provision (miss): %v", err)
	}
	miss := onlyNetnsStage(t, missTiming)
	if miss.Desc != "miss" {
		t.Fatalf("miss stage desc = %q, want miss", miss.Desc)
	}
	if miss.DurMS < float64(delay.Milliseconds()) {
		t.Fatalf("miss stage = %.1f ms, want at least the %v the build took", miss.DurMS, delay)
	}

	// Hit: a prewarmed slot is claimed, with no build on the create path.
	if err := p.Prewarm(ctx, host, time.Now().UTC()); err != nil {
		t.Fatalf("prewarm: %v", err)
	}
	realized := host.RealizedCount()
	hitCtx, hitTiming := createtiming.With(ctx)
	if _, _, err := h.Provision(hitCtx, "sb-hit"); err != nil {
		t.Fatalf("provision (hit): %v", err)
	}
	hit := onlyNetnsStage(t, hitTiming)
	if hit.Desc != "hit" {
		t.Fatalf("hit stage desc = %q, want hit", hit.Desc)
	}
	// A hit claims the prewarmed namespace; it must not build one. (Checked
	// by the build count, not by a time bound, which a busy CI host breaks.)
	if got := host.RealizedCount(); got != realized {
		t.Fatalf("hit ran a CNI build: realized namespaces %d → %d", realized, got)
	}
}

func onlyNetnsStage(t *testing.T, timing *createtiming.CreateTiming) createtiming.Stage {
	t.Helper()
	var found []createtiming.Stage
	for _, st := range timing.Stages() {
		if st.Name == "containerd_netns" {
			found = append(found, st)
		}
	}
	if len(found) != 1 {
		t.Fatalf("containerd_netns stages = %+v (all: %+v), want exactly one", found, timing.Stages())
	}
	return found[0]
}

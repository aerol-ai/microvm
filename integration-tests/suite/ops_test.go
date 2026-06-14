//go:build integration

package suite

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-61 — /v1/capacity reports host capacity.
func TestCapacityReported(t *testing.T) {
	harness.Require(t, sc, "UC-61")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var body map[string]any
	if err := c.GetJSON(ctx, "/v1/capacity", &body); err != nil {
		t.Fatalf("get capacity: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("capacity response was empty")
	}
}

// UC-62 — Admission rejects a request that exceeds host capacity. We ask for
// far more memory than any test box has; the admitter must refuse rather than
// accept-and-OOM. Deterministic and cheap (no resource is actually claimed).
func TestAdmissionRejectsOverCapacity(t *testing.T) {
	harness.Require(t, sc, "UC-62")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image:    harness.DefaultImage,
		Name:     harness.UniqueName(sc, t),
		MemoryMB: 1 << 30, // ~1 PiB — no host can satisfy this
	})
	if err == nil {
		_ = c.SDK().Destroy(ctx, sb.ID)
		t.Fatal("create with impossible memory succeeded; admission did not reject")
	}
}

// UC-63 — admin/reconcile runs clean.
func TestReconcileRunsClean(t *testing.T) {
	harness.Require(t, sc, "UC-63")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := c.SDK().Reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

// UC-64 — /v1/metrics scrape returns Prometheus-format output.
func TestMetricsScrape(t *testing.T) {
	harness.Require(t, sc, "UC-64")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	body, err := c.GetText(ctx, "/v1/metrics")
	if err != nil {
		t.Fatalf("get metrics: %v", err)
	}
	if strings.TrimSpace(body) == "" {
		t.Fatal("metrics body was empty")
	}
}

// UC-65 — Concurrent duplicate create (same name) must yield exactly one
// sandbox: the unique-name index is the idempotency backstop under a race.
func TestConcurrentDuplicateCreate(t *testing.T) {
	harness.Require(t, sc, "UC-65")
	c := client(t)
	name := harness.UniqueName(sc, t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	const n = 4
	var wg sync.WaitGroup
	results := make([]*microvm.Sandbox, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
				Image: harness.DefaultImage,
				Name:  name,
			})
		}(i)
	}
	wg.Wait()

	var created []string
	for i := 0; i < n; i++ {
		if errs[i] == nil && results[i] != nil {
			created = append(created, results[i].ID)
		}
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer ccancel()
		for _, id := range created {
			_ = c.SDK().Destroy(cctx, id)
		}
	})
	if len(created) != 1 {
		t.Fatalf("concurrent duplicate create produced %d sandboxes (%v), want exactly 1", len(created), created)
	}
}

// UC-66 — mounts list returns without error (empty is fine for a plain box).
func TestMountsList(t *testing.T) {
	harness.Require(t, sc, "UC-66")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.SDK().Mounts(ctx, sb.ID); err != nil {
		t.Fatalf("mounts: %v", err)
	}
}

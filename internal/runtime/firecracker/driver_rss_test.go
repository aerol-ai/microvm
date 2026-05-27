package firecracker

// driver_rss_test.go covers the PR 5-C wiring between Driver and
// RSSSampler. The sampler itself is exercised in rss_sampler_test.go;
// these tests only verify the lifecycle calls (Register on Create,
// Unregister on Destroy, re-key on warm acquire, slot Unregister on
// warmHandle.Shutdown) and that nil-sampler is a no-op.

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// fixedRSSPages stubs readRSSPagesFn to return mbToPages(perPidMB) for
// any pid. Callers restore the prior value via the returned cleanup.
// 1 MB = (1 << 20) / pageSize pages.
func fixedRSSPages(t *testing.T, perPidMB int64) func() {
	t.Helper()
	prior := readRSSPagesFn
	pages := (perPidMB << 20) / hostPageSizeBytes
	readRSSPagesFn = func(_ int) (int64, error) { return pages, nil }
	return func() { readRSSPagesFn = prior }
}

func TestDriver_NilSampler_CreateAndDestroyAreNoOp(t *testing.T) {
	// No SetRSSSampler — both helpers should short-circuit. The point
	// here is that the daemon must run cleanly when EnableFirecracker
	// is true but the sampler hasn't been wired (the wiring is what
	// PR 5-C adds; nothing else in the codebase requires it).
	f := newDriverFixture(t)
	f.vmm.pid = 4242

	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      1,
		MemoryMB: 128,
		DiskGB:   1,
	}, "sb-no-sampler", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-no-sampler"}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
}

func TestDriver_Create_RegistersSandboxPidWithSampler(t *testing.T) {
	restore := fixedRSSPages(t, 100) // each pid contributes 100 MB
	defer restore()

	f := newDriverFixture(t)
	f.vmm.pid = 5555
	sampler := NewRSSSampler(nil)
	f.driver.SetRSSSampler(sampler)

	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      1,
		MemoryMB: 128,
		DiskGB:   1,
	}, "sb-reg", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// One tick: should see 100 MB attributed to sb-reg.
	sampler.sampleOnce()
	if got := sampler.TotalRSSMB(); got != 100 {
		t.Fatalf("TotalRSSMB after Create = %d, want 100", got)
	}
}

func TestDriver_Destroy_UnregistersSandbox(t *testing.T) {
	restore := fixedRSSPages(t, 100)
	defer restore()

	f := newDriverFixture(t)
	f.vmm.pid = 5556
	sampler := NewRSSSampler(nil)
	f.driver.SetRSSSampler(sampler)

	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      1,
		MemoryMB: 128,
		DiskGB:   1,
	}, "sb-destroy", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	sampler.sampleOnce()
	if got := sampler.TotalRSSMB(); got != 100 {
		t.Fatalf("pre-Destroy TotalRSSMB = %d, want 100", got)
	}

	if err := f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-destroy"}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	// Unregister decrements synchronously — total drops without
	// needing a fresh sampleOnce.
	if got := sampler.TotalRSSMB(); got != 0 {
		t.Fatalf("post-Destroy TotalRSSMB = %d, want 0", got)
	}
}

func TestWarmHandle_Shutdown_UnregistersSlot(t *testing.T) {
	restore := fixedRSSPages(t, 200)
	defer restore()

	f := newDriverFixture(t)
	f.vmm.pid = 6000
	sampler := NewRSSSampler(nil)
	f.driver.SetRSSSampler(sampler)

	// Manually construct what WarmSpawn would have produced. (Wiring
	// WarmSpawn end-to-end needs a fake snapshot pipeline that the
	// pool's spawner tests already cover; here we want a focused
	// assertion on warmHandle.Shutdown's sampler call.)
	f.driver.rssRegister("slot-w1", 6000)
	sampler.sampleOnce()
	if got := sampler.TotalRSSMB(); got != 200 {
		t.Fatalf("pre-shutdown TotalRSSMB = %d, want 200", got)
	}

	wh := &warmHandle{handle: f.vmm, driver: f.driver, slotID: "slot-w1"}
	if err := wh.Shutdown(context.Background(), time.Second); err != nil {
		t.Fatalf("warmHandle.Shutdown: %v", err)
	}
	if got := sampler.TotalRSSMB(); got != 0 {
		t.Fatalf("post-shutdown TotalRSSMB = %d, want 0", got)
	}
}

func TestRSSRegister_GuardsAgainstNilSamplerAndBadInputs(t *testing.T) {
	// Direct unit coverage of the helpers' guards — these are the
	// invariants the call sites depend on (so Create / Destroy don't
	// need to gate on sampler==nil or pid<=0 themselves).
	d := New(Config{}, nil)
	d.rssRegister("id", 1234) // nil sampler — must not panic
	d.rssUnregister("id")     // nil sampler — must not panic

	d.SetRSSSampler(NewRSSSampler(nil))
	d.rssRegister("", 1234) // empty id — sampler rejects
	d.rssRegister("id", 0)  // zero pid — rssRegister rejects before sampler
	d.rssRegister("id", -1) // negative pid — rssRegister rejects

	// Nothing was registered, so a sampleOnce produces 0.
	restore := fixedRSSPages(t, 50)
	defer restore()
	d.sampler.sampleOnce()
	if got := d.sampler.TotalRSSMB(); got != 0 {
		t.Fatalf("TotalRSSMB with no valid registers = %d, want 0", got)
	}
}

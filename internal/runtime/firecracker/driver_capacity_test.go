package firecracker

// driver_capacity_test.go is the PR 5-C end-to-end test for the Phase 5
// memory-overcommit admission axis. It wires three pieces together —
// real RSSSampler, real Driver (with the sampler attached), real
// Admitter (constructed via NewWithRSSSource against the same sampler)
// — and drives a burst of Creates to prove rejection fires on the RSS
// watermark, not on nominal reservations.
//
// What this test guards against: a future refactor that breaks the
// sampler ↔ admitter seam (forgets to call SetRSSSampler, swallows the
// Ready() signal, mis-keys Register/Unregister) would still pass the
// per-package unit tests but silently fall back to nominal-only
// accounting in production. The whole point of Phase 5 is to safely
// raise MemoryOverProvisionFactor on the Firecracker path; that's only
// safe if the RSS axis is actually load-bearing.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestDriver_BurstyCreates_AdmissionTracksRSSNotNominal(t *testing.T) {
	// Each VMM "uses" 800 MB resident on the host once it's been
	// sampled — representative of a Firecracker that's booted and
	// touched its rootfs+overlay pages.
	const perVMMRSS int64 = 800
	restore := fixedRSSPages(t, perVMMRSS)
	defer restore()

	f := newDriverFixture(t)
	// Single fake handle; all Creates resolve to the same pid. The
	// sampler keys entries by sandboxID, so N registrations produce N
	// distinct entries — fixedRSSPages returns the same per-pid MB for
	// each lookup, so total = N * perVMMRSS as expected.
	f.vmm.pid = 12345

	sampler := NewRSSSampler(nil)
	f.driver.SetRSSSampler(sampler)

	// 16 GB host, RSS watermark = 20% = 3276 MB held in reserve. The
	// memory reservation axis is set generously (1.0 ratio × 4.0
	// overcommit = 65536 MB nominal budget) so it cannot be the cause
	// of any rejection in this test — the rejection MUST come from the
	// RSS axis.
	const hostMemMB = 16384
	admitter := capacity.NewWithRSSSource(
		capacity.HostInfo{CPUCores: 16, MemoryTotalMB: hostMemMB},
		capacity.Limits{
			CPUReservationRatio:       1.0,
			MemoryReservationRatio:    1.0,
			MemoryOverProvisionFactor: 4.0,
			RSSWatermarkRatio:         0.20,
		},
		nil, // no MemProbe — live MemAvailable floor is disabled
		sampler,
	)

	req := capacity.Request{CPU: 0.5, MemoryMB: 256}

	// Math:
	//   watermark = int(16384 * 0.20) = 3276 MB
	//   pre-admit RSS at iteration i = i * 800 (i sandboxes already
	//     created and sampled)
	//   effective - req < watermark
	//     ⇔ (16384 - i*800) - 256 < 3276
	//     ⇔ i*800 > 12852
	//     ⇔ i > 16.0...
	//   so i=16 still admits (effective-req = 3328 > 3276) and i=17
	//   rejects (effective-req = 2528 < 3276).
	// Expected admitted = 17, first reject at iteration 17.
	const wantAdmitted = 17
	const burstSize = 30

	var admitted int
	var firstReject error
	for i := range burstSize {
		sandboxID := fmt.Sprintf("sb-burst-%02d", i)
		if err := admitter.Admit(sandboxID, req); err != nil {
			firstReject = err
			break
		}
		admitted++
		if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image:    "alpine:3.20",
			CPU:      0.5,
			MemoryMB: 256,
			DiskGB:   1,
		}, sandboxID, "tok", nil); err != nil {
			t.Fatalf("Create %s: %v", sandboxID, err)
		}
		// Drive a sampler tick after every Create so the next Admit
		// sees the new VMM's RSS. In production this is the 1Hz Run
		// goroutine; here we drive it deterministically to keep the
		// boundary case (admit 17 vs. 18) reproducible.
		sampler.sampleOnce()
	}

	if admitted != wantAdmitted {
		t.Fatalf("admitted = %d, want %d (RSS watermark should fire on iteration %d)",
			admitted, wantAdmitted, wantAdmitted)
	}
	if firstReject == nil {
		t.Fatalf("expected a rejection within %d iterations, got none", burstSize)
	}
	if !errors.Is(firstReject, capacity.ErrCapacityExceeded) {
		t.Fatalf("first reject = %v, want wrapped ErrCapacityExceeded", firstReject)
	}
	// The reason string must mention the RSS watermark, not the
	// nominal reservation or live-memory floor. Without this check a
	// future change that broke the RSS axis but kept some other axis
	// active could still pass the "rejected within burst" assertion.
	if !strings.Contains(firstReject.Error(), "rss watermark") {
		t.Fatalf("first reject reason = %q, want 'rss watermark' substring (proves RSS axis fired, not nominal)",
			firstReject.Error())
	}

	// Sanity twin: the nominal memory budget would have admitted
	// thousands of these requests. Capturing this in the test keeps
	// the assertion above honest — if someone re-tunes the limits to
	// make nominal the dominant axis, this guard fires loudly.
	snap := admitter.Snapshot()
	const minHeadroom = 4 * wantAdmitted * 256 // 4x what we admitted
	if snap.MemoryBudgetMB < minHeadroom {
		t.Fatalf("nominal mem budget = %d MB, want >= %d MB to prove nominal wasn't the bottleneck",
			snap.MemoryBudgetMB, minHeadroom)
	}

	// Effective-memory floor should now show the headroom the sampler
	// reports as gone — proof the snapshot fields PR 5-B added are
	// being populated end-to-end.
	wantEffective := hostMemMB - wantAdmitted*int(perVMMRSS)
	if snap.EffectiveMemoryFreeMB != wantEffective {
		t.Fatalf("Snapshot.EffectiveMemoryFreeMB = %d, want %d (%d - %d × %d)",
			snap.EffectiveMemoryFreeMB, wantEffective,
			hostMemMB, wantAdmitted, perVMMRSS)
	}
}

func TestDriver_BurstyCreates_AdmissionFallsBackBeforeFirstSample(t *testing.T) {
	// Cold-start safety: the sampler reports Ready()=false until the
	// first sampleOnce, even with registered pids. Admission must
	// fall back to nominal accounting and NOT reject just because
	// TotalRSSMB() returns 0 (which, under a non-zero watermark,
	// would otherwise look like "host has all of RAM free, admit
	// everything" — wrong direction for a safety axis).
	const perVMMRSS int64 = 800
	restore := fixedRSSPages(t, perVMMRSS)
	defer restore()

	f := newDriverFixture(t)
	f.vmm.pid = 4242

	sampler := NewRSSSampler(nil)
	f.driver.SetRSSSampler(sampler)

	admitter := capacity.NewWithRSSSource(
		capacity.HostInfo{CPUCores: 16, MemoryTotalMB: 16384},
		capacity.Limits{
			MemoryReservationRatio:    1.0,
			MemoryOverProvisionFactor: 4.0,
			RSSWatermarkRatio:         0.20,
		},
		nil,
		sampler,
	)

	// Register a pid via a Create. Sampler stores the entry but
	// Ready()=false until sampleOnce runs. Admit MUST succeed because
	// the RSS axis is gated on Ready.
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      0.5,
		MemoryMB: 256,
		DiskGB:   1,
	}, "sb-pretick", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sampler.Ready() {
		t.Fatal("sampler.Ready() = true before sampleOnce; expected false")
	}

	// Pre-tick admit must succeed — the gating on Ready() is exactly
	// what protects this case.
	if err := admitter.Admit("sb-pretick-2", capacity.Request{CPU: 0.5, MemoryMB: 256}); err != nil {
		t.Fatalf("pre-tick Admit unexpectedly rejected: %v", err)
	}
}

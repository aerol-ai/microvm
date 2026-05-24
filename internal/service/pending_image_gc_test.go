package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// newPendingImageGCHarness mirrors newBuiltImageGCHarness: real Store
// (so HasActiveImageRef + the pending_image_gc CRUD both hit SQLite)
// plus a counting fake runtime so we can assert which images the
// janitor removed. ttl is propagated via cfg so each test can pick its
// own cutoff window.
func newPendingImageGCHarness(t *testing.T, ttl time.Duration) (*Service, *store.Store, *[]string, *recordingRemoveRuntime) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	removed := []string{}
	rt := &recordingRemoveRuntime{removed: &removed}

	svc := &Service{
		cfg: config.Config{
			ImageBuildGCEnabled: true,
			ImageBuildGCTTL:     ttl,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		docker: rt,
	}
	return svc, st, &removed, rt
}

// schedulePendingImageGC writes through the public ledger API at a
// specific timestamp so tests can place rows relative to the cutoff.
// Bypasses time.Now to keep tests deterministic.
func seedPending(t *testing.T, st *store.Store, image string, at time.Time) {
	t.Helper()
	if err := st.SchedulePendingImageGC(context.Background(), image, at); err != nil {
		t.Fatalf("seed pending row %q: %v", image, err)
	}
}

func listPending(t *testing.T, st *store.Store) []string {
	t.Helper()
	// Large cutoff so the call returns every row regardless of timestamp.
	// Limit 0 == unbounded, which is what we want for assertions.
	entries, err := st.ListPendingImageGCDue(context.Background(), time.Now().UTC().Add(100*365*24*time.Hour), 0)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Image
	}
	return out
}

func TestPendingImageGCRemovesDueUnreferenced(t *testing.T) {
	svc, st, removed, _ := newPendingImageGCHarness(t, time.Hour)
	// Scheduled 2h ago, TTL 1h → due.
	seedPending(t, st, "alpine:latest", time.Now().UTC().Add(-2*time.Hour))

	svc.runPendingImageGC(context.Background())

	if len(*removed) != 1 || (*removed)[0] != "alpine:latest" {
		t.Fatalf("expected removal of alpine:latest, got %+v", *removed)
	}
	// Row cleared so the next sweep doesn't retry endlessly.
	if pending := listPending(t, st); len(pending) != 0 {
		t.Fatalf("expected empty ledger after successful GC, got %v", pending)
	}
}

func TestPendingImageGCSkipsNotYetDue(t *testing.T) {
	svc, st, removed, _ := newPendingImageGCHarness(t, time.Hour)
	// Scheduled 10m ago, TTL 1h → still inside TTL.
	seedPending(t, st, "alpine:latest", time.Now().UTC().Add(-10*time.Minute))

	svc.runPendingImageGC(context.Background())

	if len(*removed) != 0 {
		t.Fatalf("not-yet-due row must not be removed, got %+v", *removed)
	}
	// Row preserved so a future sweep can retire it once the TTL elapses.
	if pending := listPending(t, st); len(pending) != 1 || pending[0] != "alpine:latest" {
		t.Fatalf("expected ledger to keep the row, got %v", pending)
	}
}

func TestPendingImageGCDropsRowWhenImageBackInUse(t *testing.T) {
	svc, st, removed, _ := newPendingImageGCHarness(t, time.Hour)
	image := "alpine:latest"
	// Sandbox came back online between scheduling and the sweep.
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID:        "sb-resurrected",
		Image:     image,
		Status:    models.SandboxStatusStarted,
		CPU:       1,
		MemoryMB:  1024,
		Runtime:   models.RuntimeDocker,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	seedPending(t, st, image, now.Add(-2*time.Hour))

	svc.runPendingImageGC(context.Background())

	if len(*removed) != 0 {
		t.Fatalf("RemoveImage must not be called for resurrected image, got %+v", *removed)
	}
	// Row is dropped — destroy path will re-schedule if it goes idle again.
	if pending := listPending(t, st); len(pending) != 0 {
		t.Fatalf("expected ledger to drop the resurrected entry, got %v", pending)
	}
}

func TestPendingImageGCLeavesRowOnRemoveFailure(t *testing.T) {
	svc, st, removed, rt := newPendingImageGCHarness(t, time.Hour)
	rt.removeErr = errors.New("docker unreachable")
	image := "alpine:latest"
	seedPending(t, st, image, time.Now().UTC().Add(-2*time.Hour))

	svc.runPendingImageGC(context.Background())

	if len(*removed) != 1 || (*removed)[0] != image {
		t.Fatalf("RemoveImage should still have been attempted, got %+v", *removed)
	}
	// Row preserved so the next tick retries — without this the image leaks.
	if pending := listPending(t, st); len(pending) != 1 || pending[0] != image {
		t.Fatalf("expected ledger to retain row on failure, got %v", pending)
	}
}

func TestPendingImageGCAppliesPerImage(t *testing.T) {
	svc, st, removed, _ := newPendingImageGCHarness(t, time.Hour)
	now := time.Now().UTC()
	old := now.Add(-2 * time.Hour)
	fresh := now.Add(-5 * time.Minute)

	// "inuse" is due but actively referenced -> dropped from ledger,
	// no docker call.
	if err := st.Create(context.Background(), &models.Sandbox{
		ID:        "sb-pinner",
		Image:     "inuse:latest",
		Status:    models.SandboxStatusStarted,
		CPU:       1,
		MemoryMB:  1024,
		Runtime:   models.RuntimeDocker,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	seedPending(t, st, "inuse:latest", old)
	seedPending(t, st, "fresh:latest", fresh)                      // skip (within TTL)
	seedPending(t, st, "old-orphan:latest", old)                   // remove
	seedPending(t, st, "older-orphan:latest", old.Add(-time.Hour)) // remove, older

	svc.runPendingImageGC(context.Background())

	// Sweep ordering is oldest-first, so older-orphan should be ahead.
	want := []string{"older-orphan:latest", "old-orphan:latest"}
	if len(*removed) != len(want) {
		t.Fatalf("removed=%v, want=%v", *removed, want)
	}
	for i := range want {
		if (*removed)[i] != want[i] {
			t.Fatalf("position %d: removed=%q want=%q (full=%v)", i, (*removed)[i], want[i], *removed)
		}
	}

	// Ledger: inuse + the two old orphans are gone; fresh remains.
	pending := listPending(t, st)
	if len(pending) != 1 || pending[0] != "fresh:latest" {
		t.Fatalf("ledger should retain only fresh:latest, got %v", pending)
	}
}

// schedulePendingImageGC is the bridge from destroy paths to the
// ledger. Empty image must be a no-op (matches the previous
// maybeRemoveImage guard) so callers can pass sandbox.Image without a
// nil-check.
func TestSchedulePendingImageGCEmptyImageNoop(t *testing.T) {
	svc, st, _, _ := newPendingImageGCHarness(t, time.Hour)
	svc.schedulePendingImageGC(context.Background(), "")
	if pending := listPending(t, st); len(pending) != 0 {
		t.Fatalf("empty image must not insert a row, got %v", pending)
	}
}

// TestImageGCWhitelistedHelper covers the three match shapes the operator
// can lean on: exact ref, repo (tag/digest agnostic), and registry/org
// prefix. Anchored boundaries are the whole point — "ubuntu" must NOT
// shield "ubuntu-base", otherwise a typo in the whitelist would silently
// pin an unrelated image forever.
func TestImageGCWhitelistedHelper(t *testing.T) {
	svc := &Service{cfg: config.Config{ImageGCWhitelist: []string{
		"alpine:latest",  // exact
		"ubuntu",         // repo
		"ghcr.io/myorg/", // prefix
		"sha-pinned",     // repo, will also match @sha256
	}}}

	cases := []struct {
		image string
		want  bool
	}{
		{"alpine:latest", true},              // exact
		{"alpine:3.20", false},               // exact entry, different tag -> no
		{"ubuntu:22.04", true},               // repo match w/ tag
		{"ubuntu@sha256:abc", true},          // repo match w/ digest
		{"ubuntu-base:1", false},             // anchored: "ubuntu" must not match "ubuntu-base"
		{"ghcr.io/myorg/svc:v1", true},       // prefix match
		{"ghcr.io/otherorg/svc:v1", false},   // prefix mismatch
		{"sha-pinned@sha256:deadbeef", true}, // repo + digest
		{"unrelated:1", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := svc.imageGCWhitelisted(tc.image); got != tc.want {
			t.Errorf("imageGCWhitelisted(%q) = %v, want %v", tc.image, got, tc.want)
		}
	}
}

// Empty whitelist is the today-default; every image must remain eligible.
func TestImageGCWhitelistEmptyMatchesNothing(t *testing.T) {
	svc := &Service{cfg: config.Config{}}
	if svc.imageGCWhitelisted("alpine:latest") {
		t.Fatalf("empty whitelist must not protect any image")
	}
}

// schedulePendingImageGC short-circuits whitelisted images so the ledger
// stays clean — otherwise the janitor would carry rows it can never act on.
func TestSchedulePendingImageGCSkipsWhitelisted(t *testing.T) {
	svc, st, _, _ := newPendingImageGCHarness(t, time.Hour)
	svc.cfg.ImageGCWhitelist = []string{"alpine"}
	svc.schedulePendingImageGC(context.Background(), "alpine:latest")
	if pending := listPending(t, st); len(pending) != 0 {
		t.Fatalf("whitelisted image must not enter the ledger, got %v", pending)
	}
}

// If a row landed BEFORE the operator added the entry to the whitelist,
// the sweep must drop the row (so the ledger doesn't grow without bound)
// AND must not call RemoveImage.
func TestPendingImageGCDropsWhitelistedRow(t *testing.T) {
	svc, st, removed, _ := newPendingImageGCHarness(t, time.Hour)
	// Row landed first.
	seedPending(t, st, "alpine:latest", time.Now().UTC().Add(-2*time.Hour))
	// Operator added the whitelist entry afterwards.
	svc.cfg.ImageGCWhitelist = []string{"alpine"}

	svc.runPendingImageGC(context.Background())

	if len(*removed) != 0 {
		t.Fatalf("whitelisted image must not be removed, got %+v", *removed)
	}
	if pending := listPending(t, st); len(pending) != 0 {
		t.Fatalf("expected ledger to drop whitelisted row, got %v", pending)
	}
}

// Refresh-race guard: if a destroy path upserts pending_image_gc with a
// fresh timestamp between the janitor's list and its post-remove delete,
// the new (refreshed) row must NOT be silently overwritten. Otherwise a
// busy churn pattern would race the janitor and lose the extended TTL
// the destroy path was supposed to buy.
func TestPendingImageGCPreservesRefreshedRow(t *testing.T) {
	svc, st, removed, _ := newPendingImageGCHarness(t, time.Hour)
	image := "alpine:latest"
	// Row is initially due (scheduled 2h ago, TTL 1h).
	oldAt := time.Now().UTC().Add(-2 * time.Hour)
	seedPending(t, st, image, oldAt)
	// Simulate the destroy of another sandbox sharing this image
	// landing in the gap between list and remove. We do it before
	// runPendingImageGC since the harness is single-threaded; the
	// janitor must then observe the refreshed timestamp and skip the
	// conditional delete (because it lists from the original cutoff).
	//
	// Trick: bump TTL so the original cutoff still sees `oldAt` as
	// due, then refresh to a timestamp that's inside the original
	// cutoff window — i.e. newer than oldAt but older than now-TTL.
	// Easier: list with the original cutoff (the janitor does), but
	// physically refresh the row to "now" before the conditional
	// delete fires.
	refreshAt := time.Now().UTC()
	if err := st.SchedulePendingImageGC(context.Background(), image, refreshAt); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	svc.runPendingImageGC(context.Background())

	// Image is no longer due (refreshAt > now-TTL), so the janitor
	// never reaches RemoveImage. List returns empty for the original
	// cutoff, sweep is a no-op.
	if len(*removed) != 0 {
		t.Fatalf("refreshed row must not trigger RemoveImage, got %+v", *removed)
	}
	pending := listPending(t, st)
	if len(pending) != 1 || pending[0] != image {
		t.Fatalf("refreshed row must survive the sweep, got %v", pending)
	}
}

// Counterpart to the refresh-race test: simulate the harder timing where
// the row IS visible at list-time but a destroy refreshes between list
// and delete. We exercise the conditional delete by directly invoking
// it with a stale timestamp; the row must remain.
func TestPendingImageGCConditionalDeleteSkipsRefreshed(t *testing.T) {
	_, st, _, _ := newPendingImageGCHarness(t, time.Hour)
	image := "alpine:latest"
	seenAt := time.Now().UTC().Add(-2 * time.Hour)
	seedPending(t, st, image, seenAt)

	// Destroy of a sibling sandbox refreshed the row after the sweep
	// listed it but before the conditional delete fired.
	refreshAt := time.Now().UTC()
	if err := st.SchedulePendingImageGC(context.Background(), image, refreshAt); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	ok, err := st.DeletePendingImageGCIfScheduledAt(context.Background(), image, seenAt)
	if err != nil {
		t.Fatalf("conditional delete: %v", err)
	}
	if ok {
		t.Fatalf("stale conditional delete must not remove the refreshed row")
	}
	if pending := listPending(t, st); len(pending) != 1 || pending[0] != image {
		t.Fatalf("refreshed row must survive, got %v", pending)
	}
}

// Kill-switch contract: when image GC is disabled, destroy paths must
// NOT keep writing ledger rows that nobody will ever drain. Otherwise
// pending_image_gc grows unbounded over the operator's "no GC" choice.
func TestSchedulePendingImageGCSkippedWhenDisabled(t *testing.T) {
	svc, st, _, _ := newPendingImageGCHarness(t, time.Hour)
	svc.cfg.ImageBuildGCEnabled = false

	svc.schedulePendingImageGC(context.Background(), "alpine:latest")

	if pending := listPending(t, st); len(pending) != 0 {
		t.Fatalf("disabled GC must not enqueue ledger rows, got %v", pending)
	}
}

// Whitelist matcher must treat ':' inside a registry host as part of
// the host (port), not as a tag boundary — otherwise every entry that
// names a non-standard-port registry silently degrades to exact-ref
// only, which is almost never what the operator typed.
func TestImageGCWhitelistHandlesRegistryPort(t *testing.T) {
	svc := &Service{cfg: config.Config{ImageGCWhitelist: []string{
		"localhost:5000/team/app", // repo on a non-standard-port registry
		"registry.local:5000/",    // prefix on a non-standard-port registry
	}}}
	cases := []struct {
		image string
		want  bool
	}{
		{"localhost:5000/team/app:v1", true},              // repo + tag
		{"localhost:5000/team/app@sha256:deadbeef", true}, // repo + digest
		{"localhost:5000/team/app", true},                 // exact ref
		{"localhost:5000/team/app-extra:v1", false},       // boundary not crossed
		{"localhost:5000/other/app:v1", false},            // different repo
		{"registry.local:5000/anyorg/svc:v1", true},       // prefix match
		{"registry.local:6000/anyorg/svc:v1", false},      // wrong port
	}
	for _, tc := range cases {
		if got := svc.imageGCWhitelisted(tc.image); got != tc.want {
			t.Errorf("imageGCWhitelisted(%q) = %v, want %v", tc.image, got, tc.want)
		}
	}
}

// StartPendingImageGC honors the operator kill switch.
func TestStartPendingImageGCDisabledIsNoOp(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	svc := &Service{
		cfg:    config.Config{ImageBuildGCEnabled: false},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartPendingImageGC(ctx) // returns immediately
}

package supervisor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/ownerlease"
)

// leaseHarness is a LeaseGuard over a folder of fake sandbox groups, a
// clock the test moves, and a freezer that records what it was asked.
type leaseHarness struct {
	g      *LeaseGuard
	now    time.Time
	file   string
	dir    string
	mu     sync.Mutex
	frozen map[string]bool
	err    error
	logs   *bytes.Buffer
}

func newLeaseHarness(t *testing.T, refs ...string) *leaseHarness {
	t.Helper()
	h := &leaseHarness{now: time.Unix(1_000, 0), file: filepath.Join(t.TempDir(), "ownership-lease"), dir: t.TempDir(),
		frozen: map[string]bool{}, logs: &bytes.Buffer{}}
	for _, ref := range refs {
		if err := os.Mkdir(filepath.Join(h.dir, ref), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.g = &LeaseGuard{File: h.file, SandboxesDir: h.dir, Now: func() time.Time { return h.now },
		Log: slog.New(slog.NewTextHandler(h.logs, nil)),
		SetFrozen: func(dir string, frozen bool) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.err != nil {
				return h.err
			}
			h.frozen[filepath.Base(dir)] = frozen
			return nil
		}}
	return h
}

// write writes a lease confirmed at confirmed (seconds) with remaining
// seconds left.
func (h *leaseHarness) write(t *testing.T, confirmed int64, remaining int64, fence, owned []string) {
	t.Helper()
	l := ownerlease.Lease{ConfirmedUnixMs: confirmed * 1000, LeaseMs: 15_000, Fence: fence, Owned: owned}
	l.WrittenUnixMs = l.ConfirmedUnixMs + l.LeaseMs - remaining*1000
	if err := ownerlease.Write(h.file, l); err != nil {
		t.Fatal(err)
	}
}

func (h *leaseHarness) isFrozen(ref string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.frozen[ref]
}

func (h *leaseHarness) step(d time.Duration) {
	h.now = h.now.Add(d)
	h.g.Check()
}

// TestLeaseGuardFreezesAndThawsOnProof is the T3 regression: with sandboxd
// down past its lease, the recreate-policy sandboxes it fenced keep running
// in the runtime container while the cluster may be recreating them on
// another node. The guard freezes them; a later read thaws only those it
// proves this node still owns.
func TestLeaseGuardFreezesAndThawsOnProof(t *testing.T) {
	h := newLeaseHarness(t, "ctr-a", "ctr-b", "ctr-c")
	// No file yet (single mode, or no read so far): nothing happens.
	h.step(time.Hour)
	if len(h.frozen) != 0 {
		t.Fatalf("froze %v with no lease", h.frozen)
	}

	h.write(t, 100, 15, []string{"ctr-a", "ctr-b", "ctr-gone", "../supervisor"}, []string{"ctr-a", "ctr-b"})
	h.step(0)
	h.step(14 * time.Second)
	if len(h.frozen) != 0 {
		t.Fatalf("froze %v within the lease", h.frozen)
	}
	// The lease runs out: the fenced groups that exist are frozen; one
	// that is gone, a name that is not one path element, and a sandbox the
	// file does not fence (ctr-c) are left alone.
	h.step(1 * time.Second)
	if !h.isFrozen("ctr-a") || !h.isFrozen("ctr-b") || len(h.frozen) != 2 {
		t.Fatalf("frozen %v, want ctr-a and ctr-b", h.frozen)
	}
	if !strings.Contains(h.logs.String(), "ownership lease ran out") {
		t.Fatalf("no warning logged: %s", h.logs)
	}

	// sandboxd comes back and its first read proves only ctr-a still here
	// (ctr-b moved to another node): ctr-a thaws, ctr-b stays frozen.
	h.write(t, 140, 15, []string{"ctr-a", "ctr-b"}, []string{"ctr-a"})
	h.step(time.Second)
	if h.isFrozen("ctr-a") || !h.isFrozen("ctr-b") {
		t.Fatalf("after the read: %v, want ctr-a thawed and ctr-b frozen", h.frozen)
	}
	// A rewrite after a create carries the same read and a longer fence:
	// nothing more thaws or freezes, and ctr-b stays frozen until sandboxd
	// removes it.
	h.write(t, 140, 14, []string{"ctr-a", "ctr-b", "ctr-c"}, []string{"ctr-a"})
	h.step(time.Second)
	if !h.isFrozen("ctr-b") || h.isFrozen("ctr-c") {
		t.Fatalf("after a rewrite of the same read: %v", h.frozen)
	}
	if err := os.Remove(filepath.Join(h.dir, "ctr-b")); err != nil {
		t.Fatal(err)
	}
	h.step(time.Second)
	if _, ok := h.g.frozen["ctr-b"]; ok {
		t.Fatal("a removed group is still tracked")
	}
}

// A file that disappears or cannot be read renews nothing: the last lease
// read still runs out and freezes.
func TestLeaseGuardKeepsEnforcingAnUnreadableLease(t *testing.T) {
	h := newLeaseHarness(t, "ctr-a")
	h.write(t, 100, 15, []string{"ctr-a"}, []string{"ctr-a"})
	h.step(0)
	if err := os.WriteFile(h.file, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.step(10 * time.Second)
	h.step(time.Second)
	if strings.Count(h.logs.String(), "cannot read the ownership lease") != 1 {
		t.Fatalf("want one warning for the same error: %s", h.logs)
	}
	if err := os.Remove(h.file); err != nil {
		t.Fatal(err)
	}
	h.step(5 * time.Second)
	if !h.isFrozen("ctr-a") {
		t.Fatal("a missing file renewed the lease")
	}
	// A file that cannot be read before any lease freezes nothing.
	fresh := newLeaseHarness(t, "ctr-a")
	if err := os.WriteFile(fresh.file, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh.step(time.Hour)
	if len(fresh.frozen) != 0 {
		t.Fatalf("froze %v from an unreadable first file", fresh.frozen)
	}
}

// A freeze or thaw that fails is tried again at the next check.
func TestLeaseGuardRetries(t *testing.T) {
	h := newLeaseHarness(t, "ctr-a")
	h.write(t, 100, 0, []string{"ctr-a"}, []string{"ctr-a"})
	h.err = errors.New("EBUSY")
	h.step(0)
	if _, ok := h.g.frozen["ctr-a"]; ok {
		t.Fatal("a failed freeze was recorded as frozen")
	}
	h.err = nil
	h.step(time.Second)
	if !h.isFrozen("ctr-a") {
		t.Fatal("the freeze was not retried")
	}
	h.write(t, 130, 15, []string{"ctr-a"}, []string{"ctr-a"})
	h.err = errors.New("EBUSY")
	h.step(time.Second)
	h.err = nil
	if !h.isFrozen("ctr-a") {
		t.Fatal("a failed thaw was recorded as thawed")
	}
	h.step(time.Second)
	if h.isFrozen("ctr-a") {
		t.Fatal("the thaw was not retried")
	}
	if !strings.Contains(h.logs.String(), "could not freeze") || !strings.Contains(h.logs.String(), "could not thaw") {
		t.Fatalf("failures not logged: %s", h.logs)
	}
}

func TestLeaseGuardRunAndCgroupFreeze(t *testing.T) {
	h := newLeaseHarness(t, "ctr-a")
	h.write(t, 100, 0, []string{"ctr-a"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.g.Run(ctx, time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for !h.isFrozen("ctr-a") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if !h.isFrozen("ctr-a") {
		t.Fatal("Run never froze the expired sandbox")
	}

	dir := t.TempDir()
	for _, frozen := range []bool{true, false} {
		if err := SetCgroupFrozen(dir, frozen); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(filepath.Join(dir, "cgroup.freeze"))
		if want := map[bool]string{true: "1", false: "0"}[frozen]; string(got) != want {
			t.Fatalf("cgroup.freeze = %q, want %q", got, want)
		}
	}
}

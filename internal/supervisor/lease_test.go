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
		if err := os.MkdirAll(filepath.Join(h.dir, ref), 0o755); err != nil {
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
			// By the group's path under the sandboxes' parent: a VM's is
			// aerolvm-vmm/<sandbox>.
			rel, err := filepath.Rel(h.dir, dir)
			if err != nil {
				return err
			}
			h.frozen[rel] = frozen
			return nil
		}}
	return h
}

// write writes a lease confirmed at confirmed (seconds) with remaining
// seconds left.
// write is sandboxd writing the file now, on the clock the guard shares,
// with remaining seconds of the lease left: the read it carries was
// confirmed 15 - remaining seconds ago.
func (h *leaseHarness) write(t *testing.T, remaining int64, fence, owned []string) {
	t.Helper()
	l := ownerlease.Lease{WrittenUnixMs: h.now.UnixMilli(), LeaseMs: 15_000, Fence: fence, Owned: owned}
	l.ConfirmedUnixMs = l.WrittenUnixMs - l.LeaseMs + remaining*1000
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

	h.write(t, 15, []string{"ctr-a", "ctr-b", "ctr-gone", "../supervisor"}, []string{"ctr-a", "ctr-b"})
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
	h.write(t, 15, []string{"ctr-a", "ctr-b"}, []string{"ctr-a"})
	h.step(time.Second)
	if h.isFrozen("ctr-a") || !h.isFrozen("ctr-b") {
		t.Fatalf("after the read: %v, want ctr-a thawed and ctr-b frozen", h.frozen)
	}
	// A rewrite after a create carries the same read and a longer fence:
	// nothing more thaws or freezes, and ctr-b stays frozen until sandboxd
	// removes it.
	h.write(t, 14, []string{"ctr-a", "ctr-b", "ctr-c"}, []string{"ctr-a"})
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

// A file read for the first time after it was written counts its age: the
// guard starting long after sandboxd stopped, or a slow check, never gives
// a lease fresh time. A write time ahead of the clock adds nothing.
func TestLeaseGuardCountsALeaseFromItsWrite(t *testing.T) {
	for _, tc := range []struct {
		name      string
		readAfter time.Duration // from the write to the first check
		end       time.Duration // the freeze, from the write; 0: at the first check
	}{
		{"read on time", 0, 15 * time.Second},
		// Before the fix it ran to 20 s: 15 s counted from the late read.
		{"read 5 s late", 5 * time.Second, 15 * time.Second},
		{"read after it ran out", time.Minute, 0},
		// The clock reads 3 s before the write time: the guard grants what
		// the file says was left, from its read, and nothing for the gap.
		{"written 3 s in the future", -3 * time.Second, 12 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLeaseHarness(t, "ctr-a")
			h.write(t, 15, []string{"ctr-a"}, []string{"ctr-a"})
			written := h.now
			h.step(tc.readAfter)
			if tc.end == 0 {
				if !h.isFrozen("ctr-a") {
					t.Fatal("a lease that ran out before its first read was not enforced")
				}
				return
			}
			h.step(written.Add(tc.end - time.Millisecond).Sub(h.now))
			if h.isFrozen("ctr-a") {
				t.Fatal("frozen before the lease's end")
			}
			h.step(time.Millisecond)
			if !h.isFrozen("ctr-a") {
				t.Fatal("not frozen at the lease's end")
			}
		})
	}
}

// A file that disappears or cannot be read renews nothing: the last lease
// read still runs out and freezes.
func TestLeaseGuardKeepsEnforcingAnUnreadableLease(t *testing.T) {
	h := newLeaseHarness(t, "ctr-a")
	h.write(t, 15, []string{"ctr-a"}, []string{"ctr-a"})
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
	h.write(t, 0, []string{"ctr-a"}, []string{"ctr-a"})
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
	h.write(t, 15, []string{"ctr-a"}, []string{"ctr-a"})
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
	h.write(t, 0, []string{"ctr-a"}, nil)
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

// Two fence publications can share a millisecond (one per recreate-policy
// create). The second one's fence is enforced: before, the guard took new
// contents only when the write time changed, so a sandbox whose create was
// acknowledged ran on past the lease (review N1). Re-reading the same
// lease never renews its deadline.
func TestLeaseGuardTakesASecondPublicationInTheSameMillisecond(t *testing.T) {
	h := newLeaseHarness(t, "ctr-old", "ctr-new")
	h.write(t, 15, []string{"ctr-old"}, []string{"ctr-old"})
	h.step(0)
	h.write(t, 15, []string{"ctr-old", "ctr-new"}, []string{"ctr-old"})
	h.step(0)
	// Read again and again within the lease: still the first deadline.
	for range 10 {
		h.step(time.Second)
	}
	if h.isFrozen("ctr-old") || h.isFrozen("ctr-new") {
		t.Fatalf("frozen = %v within the lease", h.frozen)
	}
	h.step(6 * time.Second)
	if !h.isFrozen("ctr-old") || !h.isFrozen("ctr-new") {
		t.Fatalf("frozen = %v, want both sandboxes of the second publication", h.frozen)
	}
}

// A Firecracker VM runs in its own group under the VMs' group
// (aerolvm-vmm/<sandbox>), and the file names that group. The guard freezes
// it, and never the VMs' group itself or another VM's: before, the file
// named the sandbox ID, the guard looked for <parent>/<sandbox-id>, found
// nothing, and the VM ran on past the lease (review N2).
func TestLeaseGuardFreezesAFirecrackerVMsOwnGroup(t *testing.T) {
	h := newLeaseHarness(t, "aerolvm-vmm/sb-vm", "aerolvm-vmm/sb-other")
	h.write(t, 15, []string{"aerolvm-vmm/sb-vm"}, []string{"aerolvm-vmm/sb-vm"})
	h.step(0)
	h.step(16 * time.Second)
	if !h.isFrozen("aerolvm-vmm/sb-vm") {
		t.Fatalf("frozen = %v, want the VM's own group", h.frozen)
	}
	if h.isFrozen("aerolvm-vmm") || h.isFrozen("aerolvm-vmm/sb-other") {
		t.Fatalf("frozen = %v: the VMs' group or another VM was frozen", h.frozen)
	}
	// A later read that proves ownership thaws it.
	h.write(t, 15, []string{"aerolvm-vmm/sb-vm"}, []string{"aerolvm-vmm/sb-vm"})
	h.step(0)
	if h.isFrozen("aerolvm-vmm/sb-vm") {
		t.Fatal("a proven VM stayed frozen")
	}
	// A ref outside the host groups is never followed.
	h2 := newLeaseHarness(t, "aerolvm-wasm/sb-w")
	h2.write(t, 15, []string{"aerolvm-wasm/sb-w"}, nil)
	h2.step(0)
	h2.step(16 * time.Second)
	if len(h2.frozen) != 0 {
		t.Fatalf("froze %v from a ref outside the host groups", h2.frozen)
	}
}

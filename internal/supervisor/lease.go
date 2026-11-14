package supervisor

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/aerol-ai/microvm/internal/ownerlease"
)

// LeaseGuard enforces sandboxd's ownership lease where the sandboxes live
// (C7, T3; internal/ownerlease says why). Once the lease in File runs out
// without a newer one, it freezes the group of every sandbox the file
// fences, so a sandbox the cluster may be recreating elsewhere stops
// running here even with sandboxd down. It thaws a group it froze only when
// a later lease proves this node still owns that sandbox; it never thaws
// anything it did not freeze, and never thaws on a missing or unreadable
// file.
//
// The end is measured on this process's own monotonic clock: the file says
// how much of the lease was left when it was written, and the guard counts
// that down from when it first read it, less the file's age by the wall
// clock sandboxd and this process share. So a file first read late (this
// process starting long after sandboxd stopped, or a slow check) is never
// given fresh time: the freeze lands at the lease's own end after the last
// read sandboxd sent, against the leader's grace of twice the lease before
// it may recreate the sandbox (the margin sandboxd's own fence relies on).
// A write time ahead of the wall clock (a stepped clock) adds nothing.
type LeaseGuard struct {
	// File is SB_OWNERSHIP_LEASE_FILE, written by sandboxd.
	File string
	// SandboxesDir is the sandboxes' cgroup parent as a folder; a
	// sandbox's group is SandboxesDir/<ref>.
	SandboxesDir string
	// SetFrozen writes a group's cgroup.freeze.
	SetFrozen func(dir string, frozen bool) error
	// Now is the clock (time.Now, monotonic).
	Now func() time.Time
	Log *slog.Logger

	end   time.Time // when the lease last read runs out, on Now's clock
	lease ownerlease.Lease
	have  bool
	// frozen is every ref this guard froze, with the ConfirmedUnixMs of the
	// lease that ran out: a lease confirmed later may thaw it.
	frozen   map[string]int64
	readErr  string
	expiryAt int64 // ConfirmedUnixMs of the lease whose expiry was logged
}

// SetCgroupFrozen freezes or thaws the cgroup v2 group dir.
func SetCgroupFrozen(dir string, frozen bool) error {
	v := "0"
	if frozen {
		v = "1"
	}
	return os.WriteFile(filepath.Join(dir, "cgroup.freeze"), []byte(v), 0o644)
}

// Run checks every interval until ctx ends.
func (g *LeaseGuard) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		g.Check()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Check is one pass: read the file, then thaw or freeze.
func (g *LeaseGuard) Check() {
	now := g.Now()
	l, err := ownerlease.Read(g.File)
	switch {
	case err == nil:
		g.readErr = ""
		if !g.have || !sameLease(l, g.lease) {
			g.lease, g.have = l, true
			g.end = now.Add(l.Remaining() - fileAge(now, l))
		} else {
			// The same lease written again: sandboxd publishes the fence
			// on every recreate-policy create, and two writes can share a
			// millisecond. The lists are taken (an acknowledged create
			// must be fenced); the deadline is not renewed.
			g.lease.Fence, g.lease.Owned = l.Fence, l.Owned
		}
	case errors.Is(err, os.ErrNotExist) && !g.have:
		// No lease written yet: single mode, or no read has succeeded.
		return
	default:
		// Keep enforcing the last lease read: a file that cannot be read
		// renews nothing.
		if msg := err.Error(); msg != g.readErr {
			g.readErr = msg
			g.Log.Warn("supervisor: cannot read the ownership lease; enforcing the last one read", "file", g.File, "error", err)
		}
		if !g.have {
			return
		}
	}
	g.forgetGone()
	if now.Before(g.end) {
		g.thawOwned()
		return
	}
	g.freezeFenced(now)
}

// sameLease reports whether a and b are one lease: the same read, written
// at the same time. Comparing only the write time missed a second write in
// the same millisecond, with a new sandbox in its fence: that sandbox ran
// on past the lease (review N1).
func sameLease(a, b ownerlease.Lease) bool {
	return a.WrittenUnixMs == b.WrittenUnixMs && a.ConfirmedUnixMs == b.ConfirmedUnixMs && a.LeaseMs == b.LeaseMs
}

// fileAge is how long before now, by the wall clock, l was written: never
// less than zero, so a file that seems to come from the future renews
// nothing. sandboxd writes the file on the same machine, so both read the
// same wall clock; a clock stepped forward between the write and the read
// only makes the freeze come sooner, the safe side.
func fileAge(now time.Time, l ownerlease.Lease) time.Duration {
	if age := time.Duration(now.UnixMilli()-l.WrittenUnixMs) * time.Millisecond; age > 0 {
		return age
	}
	return 0
}

// thawOwned thaws each group this guard froze that a lease confirmed after
// the freeze proves still owned. One that moved stays frozen.
func (g *LeaseGuard) thawOwned() {
	if len(g.frozen) == 0 {
		return
	}
	owned := make(map[string]bool, len(g.lease.Owned))
	for _, ref := range g.lease.Owned {
		owned[ref] = true
	}
	for ref, at := range g.frozen {
		if !owned[ref] || g.lease.ConfirmedUnixMs <= at {
			continue
		}
		if err := g.SetFrozen(filepath.Join(g.SandboxesDir, ref), false); err != nil {
			g.Log.Warn("supervisor: could not thaw a sandbox after its ownership was confirmed; will retry", "sandbox", ref, "error", err)
			continue
		}
		delete(g.frozen, ref)
		g.Log.Info("supervisor: ownership confirmed; sandbox thawed", "sandbox", ref)
	}
}

// freezeFenced freezes every fenced sandbox not frozen yet.
func (g *LeaseGuard) freezeFenced(now time.Time) {
	if g.frozen == nil {
		g.frozen = map[string]int64{}
	}
	n := 0
	for _, ref := range g.lease.Fence {
		if _, done := g.frozen[ref]; done || !ownerlease.ValidRef(ref) {
			continue
		}
		dir := filepath.Join(g.SandboxesDir, ref)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		if err := g.SetFrozen(dir, true); err != nil {
			g.Log.Warn("supervisor: could not freeze a sandbox past its ownership lease; will retry", "sandbox", ref, "error", err)
			continue
		}
		g.frozen[ref] = g.lease.ConfirmedUnixMs
		n++
	}
	if g.expiryAt != g.lease.ConfirmedUnixMs {
		g.expiryAt = g.lease.ConfirmedUnixMs
		g.Log.Warn("supervisor: sandboxd's ownership lease ran out; failover.policy=recreate sandboxes are frozen until it proves this node still owns them",
			"since_last_read", now.Sub(g.end)+time.Duration(g.lease.LeaseMs)*time.Millisecond, "frozen", n)
	}
}

// forgetGone drops a frozen group that no longer exists (sandboxd removed
// the sandbox).
func (g *LeaseGuard) forgetGone() {
	for ref := range g.frozen {
		if _, err := os.Stat(filepath.Join(g.SandboxesDir, ref)); errors.Is(err, os.ErrNotExist) {
			delete(g.frozen, ref)
		}
	}
}

package service

import (
	"context"
	"expvar"
	"fmt"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/ownerlease"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The ownership lease as a file (T3, internal/ownerlease): after each
// authoritative read that succeeds, this worker writes what it fences and
// what the read proved it still owns, so the runtime supervisor can freeze
// the fenced sandboxes when the lease runs out with sandboxd down, and thaw
// only the owned ones after a later read. Off unless SB_OWNERSHIP_LEASE_FILE
// is set, and only where the lease applies (cluster mode).
//
// Only a read sent by this process renews the file. A restarted sandboxd
// gets one lease from its own start (beginOwnershipLease) before it fences
// itself, but writes nothing until a read succeeds, so the file still
// counts from the last read any process proved: a crash loop never extends
// the lease the supervisor enforces.

// ownershipLeaseFileWriteErrors counts lease-file writes that failed. A
// file that is not renewed makes the supervisor freeze every
// recreate-policy sandbox on this node, so a rising count needs a look.
var ownershipLeaseFileWriteErrors = expvar.NewInt("aerolvm_ownership_lease_file_write_errors_total")

type ownershipLeaseFile struct {
	// mu covers the fields and each write, with the listing of the rows the
	// write fences: writes go out in the order they listed, so one that
	// listed the sandboxes earlier can never put back a fence without a
	// sandbox a later write added.
	mu sync.Mutex
	// confirmed is when this process's last successful read was sent;
	// zero until one has.
	confirmed time.Time
	// owned names the instances that read proved still owned.
	owned []string
}

// ownershipLeaseFileOn reports whether this node writes the lease file.
func (s *Service) ownershipLeaseFileOn() bool {
	return s != nil && s.cfg.OwnershipLeaseFile != "" && s.ownershipLeaseApplies()
}

// recordOwnershipRead takes the read sent at sent: rows are the local
// recreate-policy sandboxes the read asked about, placements what the
// leader answered for them. It writes the file before confirmOwnership
// thaws anything.
func (s *Service) recordOwnershipRead(ctx context.Context, sent time.Time, rows []*models.Sandbox, placements map[string]cluster.Placement, self string) {
	if !s.ownershipLeaseFileOn() {
		return
	}
	owned := make([]string, 0, len(rows))
	for _, sb := range rows {
		if p, ok := placements[sb.ID]; ownershipProven(p, ok, self, sb) {
			owned = append(owned, s.fenceRef(sb))
		}
	}
	f := &s.ownershipFile
	f.mu.Lock()
	defer f.mu.Unlock()
	if !sent.After(f.confirmed) {
		return
	}
	f.confirmed, f.owned = sent, owned
	// The fence comes from a fresh listing, not rows: rows were listed
	// before the read went out, and a sandbox created since is already in
	// the file (publishOwnershipFence).
	_ = s.writeOwnershipLeaseFileLocked(ctx)
}

// publishOwnershipFence writes the file with every local recreate-policy
// sandbox in the fence, the one whose row was just written included, before
// that create is answered (R9). The answer is what lets its placement be
// placed, and so recreated elsewhere if this node dies: a fence that only
// reached the file later could be lost with sandboxd, leaving a running task
// the supervisor never freezes. A process that has not confirmed its lease
// yet confirms it first (the first such create after a start only): it
// writes nothing before a read succeeds, so a crash loop never extends the
// lease the supervisor enforces.
func (s *Service) publishOwnershipFence(ctx context.Context) error {
	if !s.ownershipLeaseFileOn() {
		return nil
	}
	f := &s.ownershipFile
	f.mu.Lock()
	confirmed := !f.confirmed.IsZero()
	f.mu.Unlock()
	if !confirmed {
		if err := s.confirmOwnership(ctx, time.Now()); err != nil {
			return fmt.Errorf("fence the new sandbox: this node's first ownership read failed (%v): %w", err, ErrOwnershipFenced)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return s.writeOwnershipLeaseFileLocked(ctx)
}

// writeOwnershipLeaseFileLocked writes the file under the last read, with
// every local recreate-policy sandbox, listed now, as the fence. It refuses
// before this process's first successful read: a lease no read proved must
// never reach the supervisor (both callers have one by then).
func (s *Service) writeOwnershipLeaseFileLocked(ctx context.Context) error {
	f := &s.ownershipFile
	if f.confirmed.IsZero() {
		return fmt.Errorf("fence the new sandbox: no ownership read has succeeded: %w", ErrOwnershipFenced)
	}
	rows, err := s.localRecreateSandboxes(ctx)
	if err == nil {
		fence := make([]string, 0, len(rows))
		for _, sb := range rows {
			// The group the supervisor freezes: a container's, or a
			// Firecracker VM's own (ownership_lease_runtimes.go).
			fence = append(fence, s.fenceRef(sb))
		}
		confirmed := f.confirmed.UnixMilli()
		err = ownerlease.Write(s.cfg.OwnershipLeaseFile, ownerlease.Lease{
			ConfirmedUnixMs: confirmed,
			// On the read's own timeline through the monotonic clock, so a
			// wall-clock step since the read cannot shorten or stretch what
			// the supervisor counts down.
			WrittenUnixMs: confirmed + time.Since(f.confirmed).Milliseconds(),
			LeaseMs:       cluster.OwnershipLease(s.cfg).Milliseconds(),
			Fence:         fence,
			Owned:         f.owned,
		})
	}
	if err != nil {
		ownershipLeaseFileWriteErrors.Add(1)
		if s.logger != nil {
			s.logger.Error("ownership lease file: write failed; the runtime supervisor freezes failover.policy=recreate sandboxes when the last written lease runs out",
				"file", s.cfg.OwnershipLeaseFile, "error", err)
		}
		return fmt.Errorf("ownership lease file %s: %w", s.cfg.OwnershipLeaseFile, err)
	}
	return nil
}

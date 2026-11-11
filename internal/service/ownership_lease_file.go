package service

import (
	"context"
	"expvar"
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
	// mu covers the fields and each write, so a write from the create
	// path's kick can never put an older read back over a newer one.
	mu sync.Mutex
	// confirmed is when this process's last successful read was sent;
	// zero until one has.
	confirmed time.Time
	// owned names the instances that read proved still owned.
	owned []string

	kickOnce sync.Once
	kick     chan struct{}
}

func (f *ownershipLeaseFile) kicks() chan struct{} {
	f.kickOnce.Do(func() { f.kick = make(chan struct{}, 1) })
	return f.kick
}

// ownershipLeaseFileOn reports whether this node writes the lease file.
func (s *Service) ownershipLeaseFileOn() bool {
	return s != nil && s.cfg.OwnershipLeaseFile != "" && s.ownershipLeaseApplies()
}

// recordOwnershipRead takes the read sent at sent: rows are the local
// recreate-policy sandboxes, placements what the leader answered for them.
// It writes the file before confirmOwnership thaws anything.
func (s *Service) recordOwnershipRead(ctx context.Context, sent time.Time, rows []*models.Sandbox, placements map[string]cluster.Placement, self string) {
	if !s.ownershipLeaseFileOn() {
		return
	}
	owned := make([]string, 0, len(rows))
	for _, sb := range rows {
		if p, ok := placements[sb.ID]; ownershipProven(p, ok, self, sb) {
			owned = append(owned, s.runtimeRef(sb))
		}
	}
	f := &s.ownershipFile
	f.mu.Lock()
	defer f.mu.Unlock()
	if !sent.After(f.confirmed) {
		return
	}
	f.confirmed, f.owned = sent, owned
	s.writeOwnershipLeaseFileLocked(rows)
}

// kickOwnershipLeaseFile asks the writer to rewrite the file with the
// current fence. It never blocks: a kick already waiting covers this one.
func (s *Service) kickOwnershipLeaseFile() {
	if !s.ownershipLeaseFileOn() {
		return
	}
	select {
	case s.ownershipFile.kicks() <- struct{}{}:
	default:
	}
}

// runOwnershipLeaseFileWriter rewrites the file for each kick until ctx
// ends: the same read, a fence that includes the sandboxes created since.
func (s *Service) runOwnershipLeaseFileWriter(ctx context.Context) {
	kicks := s.ownershipFile.kicks()
	for {
		select {
		case <-ctx.Done():
			return
		case <-kicks:
		}
		rows, err := s.localRecreateSandboxes(ctx)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("ownership lease file: cannot list the sandboxes to fence", "error", err)
			}
			continue
		}
		s.ownershipFile.mu.Lock()
		s.writeOwnershipLeaseFileLocked(rows)
		s.ownershipFile.mu.Unlock()
	}
}

// writeOwnershipLeaseFileLocked writes the file with rows as the fence.
// Nothing before this process's first successful read.
func (s *Service) writeOwnershipLeaseFileLocked(rows []*models.Sandbox) {
	f := &s.ownershipFile
	if f.confirmed.IsZero() {
		return
	}
	fence := make([]string, 0, len(rows))
	for _, sb := range rows {
		fence = append(fence, s.runtimeRef(sb))
	}
	confirmed := f.confirmed.UnixMilli()
	l := ownerlease.Lease{
		ConfirmedUnixMs: confirmed,
		// On the read's own timeline through the monotonic clock, so a
		// wall-clock step since the read cannot shorten or stretch what
		// the supervisor counts down.
		WrittenUnixMs: confirmed + time.Since(f.confirmed).Milliseconds(),
		LeaseMs:       cluster.OwnershipLease(s.cfg).Milliseconds(),
		Fence:         fence,
		Owned:         f.owned,
	}
	if err := ownerlease.Write(s.cfg.OwnershipLeaseFile, l); err != nil {
		ownershipLeaseFileWriteErrors.Add(1)
		if s.logger != nil {
			s.logger.Error("ownership lease file: write failed; the runtime supervisor freezes failover.policy=recreate sandboxes when the last written lease runs out",
				"file", s.cfg.OwnershipLeaseFile, "error", err)
		}
	}
}

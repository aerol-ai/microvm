package service

import (
	"context"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// storageObligationReportRefresh mirrors the cluster heartbeat: an unchanged
// report is re-sent this often so the leader can tell a quiet owner from a
// silent one.
const storageObligationReportRefresh = 5 * time.Minute

// storageObligationReporterState remembers the last report this owner sent.
type storageObligationReporterState struct {
	mu         sync.Mutex
	lastOwed   map[string]int
	lastSentAt time.Time
	sent       bool
	seq        uint64
}

// reportStorageObligations sends this owner's CURRENT snapshot of the deletes
// its outbox still owes, per peer (UC-160). The leader replaces the previous
// report with it — a total, never a delta — so a retry cannot double-count.
//
// Every sandbox-owning node reports, including an empty set: that heartbeat
// is what lets the operator view tell "owes nothing" from "stopped checking
// in". Sent only when the snapshot changed or the refresh is due, so a quiet
// fleet adds no raft writes.
func (s *Service) reportStorageObligations(ctx context.Context, now time.Time) {
	if s == nil || s.store == nil || !s.cfg.EnableCluster {
		return
	}
	if !cluster.CanOwnSandboxRole(s.cfg.NodeRole) {
		return
	}
	c := s.Cluster()
	reporter, ok := c.(cluster.StorageObligationReporterClient)
	if !ok {
		return
	}
	self := s.selfNodeID()
	if self == "" {
		return
	}
	owed, err := s.store.SecretDeleteOwedByRecipient(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: could not count owed secret deletes for the storage-obligation report", "err", err)
		}
		return
	}
	st := &s.storageObligationReport
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.sent && owedMapsEqual(owed, st.lastOwed) && now.Sub(st.lastSentAt) < storageObligationReportRefresh {
		return
	}
	// Seq only has to increase for this reporter. Seeding from the clock
	// keeps it increasing across a restart without persisting a counter; a
	// clock stepped backwards only delays acceptance until it passes the old
	// value, and the report is a snapshot, so nothing is lost meanwhile.
	next := uint64(now.UnixNano())
	if next <= st.seq {
		next = st.seq + 1
	}
	report := cluster.StorageObligationReport{Reporter: self, Seq: next, ObservedUnixNano: now.UnixNano(), Owed: owed}
	if err := reporter.ReportStorageObligations(ctx, report); err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: storage-obligation report failed; retrying next tick", "err", err)
		}
		return
	}
	st.seq = next
	st.lastOwed = owed
	st.lastSentAt = now
	st.sent = true
}

func owedMapsEqual(a, b map[string]int) bool {
	count := func(m map[string]int) int {
		n := 0
		for _, v := range m {
			if v > 0 {
				n++
			}
		}
		return n
	}
	if count(a) != count(b) {
		return false
	}
	for k, v := range a {
		if v > 0 && b[k] != v {
			return false
		}
	}
	return true
}

// StorageObligations is the operator view of open decommission jobs. Served
// from the local FSM on a server, or by one call to a server from an agent —
// never by asking the owners.
func (s *Service) StorageObligations(ctx context.Context) ([]cluster.StorageObligationView, error) {
	if s == nil || !s.cfg.EnableCluster {
		return nil, nil
	}
	reader, ok := s.Cluster().(cluster.StorageObligationsReader)
	if !ok {
		return nil, nil
	}
	return reader.StorageObligations(ctx)
}

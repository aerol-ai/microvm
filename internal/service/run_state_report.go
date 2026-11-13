package service

import (
	"context"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Run-state reports (plans/kubernetes-v2-architecture.md §16, C17). The
// agent-sandbox API on the gateways shows whether each sandbox runs, from
// the run state its owner records in Raft (cluster opSetRunStates). This
// owner side compares its rows with what Raft holds and sends the
// difference, batched:
//
//	every runStateReportInterval: local rows ──▶ runStateOf ──▶ differs from known? ──▶ batch ──▶ SetRunStates
//	every runStateResyncInterval: page this node's placements ──▶ known = what Raft holds now
//
// Comparing rows rather than hooking each transition catches every path that
// changes a status (stop, start, crash, idle stop, restore) and adds nothing
// to CreateSandbox. A report is sent only for a real change, never as a
// keep-alive. A lost batch, or a row Raft got wrong (a failover, a restore),
// is put right by the next resync: known then says what Raft holds, and the
// next tick sends the difference.

// runStateReportInterval is a var so tests can run the loop quickly.
var runStateReportInterval = 2 * time.Second

const (
	runStateResyncInterval = time.Minute
	// runStateBatch is cluster.maxRunStateReports: one Raft entry each.
	runStateBatch = 500
	// runStateReasonMax bounds the error text one report carries into Raft.
	runStateReasonMax = 200
	runStatePageLimit = 1000
)

// knownRunState is a sandbox's run state as this node believes Raft holds
// it, with the lifetime a report must name.
type knownRunState struct {
	incarnation string
	state       cluster.RunState
	reason      string
}

// runStateOf maps a row's status to the run state the API shows; ok is
// false while it is being made or after it is gone.
func runStateOf(sb *models.Sandbox) (cluster.RunState, string, bool) {
	switch sb.Status {
	case models.SandboxStatusStarted:
		return cluster.RunStateRunning, "", true
	case models.SandboxStatusStopped, models.SandboxStatusPassivated, models.SandboxStatusAwaitingRuntime:
		return cluster.RunStateSuspended, "", true
	case models.SandboxStatusError, models.SandboxStatusPassivateFailed:
		reason := sb.LastError
		if len(reason) > runStateReasonMax {
			reason = reason[:runStateReasonMax]
		}
		return cluster.RunStateFailed, reason, true
	}
	return "", "", false
}

// runStateReporter holds what one node believes Raft holds for its sandboxes.
type runStateReporter struct {
	svc   *Service
	pub   cluster.RunStatePublisher
	pager interface {
		PlacementPage(cluster.PlacementPageRequest) cluster.PlacementPageResponse
	}
	self     string
	known    map[string]knownRunState
	resynced time.Time
	now      func() time.Time
}

// StartRunStateReports runs the reporter while ctx lives. It is a no-op
// unless the agent-sandbox API is on and this node is in a cluster whose
// client can carry reports.
func (s *Service) StartRunStateReports(ctx context.Context) {
	r := s.newRunStateReporter()
	if r == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(runStateReportInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := r.tick(ctx); err != nil {
					s.logger.Debug("run-state report failed; the next tick retries", "error", err)
				}
			}
		}
	}()
}

func (s *Service) newRunStateReporter() *runStateReporter {
	if s == nil || !s.cfg.AgentSandboxAPI || !s.ClusterEnabled() {
		return nil
	}
	c := s.Cluster()
	pub, ok := c.(cluster.RunStatePublisher)
	if !ok {
		return nil
	}
	return &runStateReporter{svc: s, pub: pub, pager: c, self: c.SelfNodeID(), now: time.Now}
}

// tick sends every difference between this node's rows and known.
func (r *runStateReporter) tick(ctx context.Context) error {
	if r.resynced.IsZero() || r.now().Sub(r.resynced) >= runStateResyncInterval {
		r.resync()
	}
	if r.resynced.IsZero() {
		// Nothing read yet: without what Raft holds, every row would cost
		// a point read each tick.
		return nil
	}
	rows, err := r.svc.store.List(ctx)
	if err != nil {
		return err
	}
	live := make(map[string]bool, len(rows))
	var batch []cluster.RunStateReport
	for _, sb := range rows {
		live[sb.ID] = true
		state, reason, ok := runStateOf(sb)
		if !ok {
			continue
		}
		k, have := r.known[sb.ID]
		if !have {
			// Made since the last resync: Raft's row names its lifetime.
			p, found := r.svc.Cluster().PlacementOf(sb.ID)
			if !found || p.OwnerNodeID != r.self || p.State != "" {
				continue
			}
			k = knownRunState{incarnation: p.IncarnationID, state: p.RunState, reason: p.RunStateReason}
			r.known[sb.ID] = k
		}
		if k.state == state && k.reason == reason {
			continue
		}
		batch = append(batch, cluster.RunStateReport{SandboxID: sb.ID, IncarnationID: k.incarnation, OwnerNodeID: r.self, State: state, Reason: reason})
	}
	for id := range r.known {
		if !live[id] {
			delete(r.known, id)
		}
	}
	for len(batch) > 0 {
		n := min(len(batch), runStateBatch)
		if _, err := r.pub.SetRunStates(ctx, batch[:n]); err != nil {
			return err
		}
		for _, rep := range batch[:n] {
			k := r.known[rep.SandboxID]
			k.state, k.reason = rep.State, rep.Reason
			r.known[rep.SandboxID] = k
		}
		batch = batch[n:]
	}
	return nil
}

// resync reads every placement this node owns, so known says what Raft
// holds now. A read the server tier could not answer for sure leaves known
// as it was, and the next tick tries again.
func (r *runStateReporter) resync() {
	next := map[string]knownRunState{}
	token := ""
	for {
		page := r.pager.PlacementPage(cluster.PlacementPageRequest{OwnerNodeID: r.self, Limit: runStatePageLimit, PageToken: token})
		if !page.Authoritative {
			return
		}
		for _, p := range page.Placements {
			if p.State == "" && p.OwnerNodeID == r.self {
				next[p.SandboxID] = knownRunState{incarnation: p.IncarnationID, state: p.RunState, reason: p.RunStateReason}
			}
		}
		if page.NextPageToken == "" {
			break
		}
		token = page.NextPageToken
	}
	r.known, r.resynced = next, r.now()
}

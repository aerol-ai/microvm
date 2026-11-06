package cluster

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// Per-team quotas over the cluster (plan item P2). Writes go through a
// dedicated internal endpoint, like egress profiles: the caller needs the
// stored record back, and only a leader that has checked every Raft
// server's build may apply one.
const (
	PublicInternalTeamQuotaWritePath = "/v1/cluster/internal/team-quotas/write"
	PublicInternalTeamQuotaReadPath  = "/v1/cluster/internal/team-quotas/read"
)

type teamQuotaAdmissionKey struct{}

// WithTeamQuotaAdmission marks ctx so the next opPlace or opUpsertSpec it
// carries is admitted against the sandbox's team quota (QuotaAdmit). The
// create path sets it for a promote that had no reservation, and resize for
// the spec write that grows a sandbox. The flag rides the command, so it
// reaches the leader through any number of forwards.
func WithTeamQuotaAdmission(ctx context.Context) context.Context {
	return context.WithValue(ctx, teamQuotaAdmissionKey{}, true)
}

func teamQuotaAdmission(ctx context.Context) bool {
	v, _ := ctx.Value(teamQuotaAdmissionKey{}).(bool)
	return v
}

// markQuotaAdmit copies the context mark onto the command types it applies
// to; every other command is left exactly as it was.
func markQuotaAdmit(ctx context.Context, cmd command) command {
	if (cmd.Op == opPlace || cmd.Op == opUpsertSpec) && teamQuotaAdmission(ctx) {
		cmd.QuotaAdmit = true
	}
	return cmd
}

// needsTeamQuotaAdmission reports whether a command must take the leader's
// admission path for team quotas (reservations always take it already).
func needsTeamQuotaAdmission(cmd command) bool {
	return cmd.QuotaAdmit && (cmd.Op == opPlace || cmd.Op == opUpsertSpec)
}

// admitTeamQuotaCommand is the leader's quota answer for cmd. It runs under
// reservationAdmissionMu with the reservation admission, so two creates for a
// team's last slot are decided one after the other against usage that
// includes the first: the second sees the first's row, and is refused.
//
// Exactness across a leader change: a new leader's FSM may not yet have
// applied entries an old leader committed. Before its first quota decision in
// a term the leader runs a Raft barrier, which returns once every entry
// before it is applied, so no admitted reservation is missing from the usage
// it reads. The barrier runs once per term, and only for a team with a quota.
func (c *Cluster) admitTeamQuotaCommand(cmd command) error {
	if c == nil || c.fsm == nil {
		return nil
	}
	asks := teamQuotaAsks(cmd)
	if len(asks) == 0 || !c.fsm.anyTeamQuotaFor(asks) {
		return nil
	}
	if err := c.teamQuotaBarrier(); err != nil {
		return err
	}
	return c.fsm.admitTeamQuotas(asks)
}

// teamQuotaBarrier applies a Raft barrier once per leadership term.
func (c *Cluster) teamQuotaBarrier() error {
	if c.raft == nil || c.raft.raft == nil {
		return nil
	}
	term := c.raft.raft.CurrentTerm()
	if c.quotaBarrierTerm.Load() == term {
		return nil
	}
	if err := c.raft.raft.Barrier(c.commitTimeout).Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost) {
			return ErrNotLeader
		}
		return fmt.Errorf("cluster: team quota barrier: %w", err)
	}
	c.quotaBarrierTerm.Store(term)
	return nil
}

// applyQuotaAdmittedEncodedLocal is applyReservationEncodedLocal for a
// promote or spec write that can grow a team: the same queue, the same
// leader check, then the quota check, then the append.
func (c *Cluster) applyQuotaAdmittedEncodedLocal(ctx context.Context, payload []byte, cmd command) error {
	c.reservationAdmissionMu.Lock()
	defer c.reservationAdmissionMu.Unlock()
	if c.raft.raft.State() != raft.Leader {
		return ErrNotLeader
	}
	if err := c.admitTeamQuotaCommand(cmd); err != nil {
		return err
	}
	return c.applyEncodedLocal(ctx, payload)
}

// teamQuotaWritesAllowed is the rolling-upgrade gate for quota ops.
func (c *Cluster) teamQuotaWritesAllowed() error {
	return c.raftServersSupport(teamQuotaFSMOpsVersion, "team quotas")
}

// WriteTeamQuota puts or deletes a team's quota. The leader checks the
// upgrade gate and applies; a follower forwards one hop to the leader.
func (c *Cluster) WriteTeamQuota(ctx context.Context, req TeamQuotaWriteRequest) (TeamQuotaWriteResponse, error) {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return TeamQuotaWriteResponse{}, fmt.Errorf("cluster: node holds no placement state")
	}
	if c.raft.raft.State() != raft.Leader {
		var out TeamQuotaWriteResponse
		if err := c.forwardToLeaderJSON(ctx, "team quota write", PublicInternalTeamQuotaWritePath, req, &out); err != nil {
			return TeamQuotaWriteResponse{}, err
		}
		return out, out.err()
	}
	if err := c.teamQuotaWritesAllowed(); err != nil {
		return TeamQuotaWriteResponse{}, err
	}
	op := opPutTeamQuota
	if req.Delete {
		op = opDeleteTeamQuota
	}
	quota := req.Quota
	payload, err := encodeCommand(command{Op: op, TeamQuota: &quota, StampUnixNano: time.Now().UnixNano()})
	if err != nil {
		return TeamQuotaWriteResponse{}, fmt.Errorf("cluster: encode command: %w", err)
	}
	result, err := c.applyEncodedLocalResult(ctx, payload)
	if err != nil {
		return TeamQuotaWriteResponse{}, err
	}
	if applied, ok := result.(teamQuotaApplyResult); ok {
		return TeamQuotaWriteResponse{Quota: applied.Quota, Changed: applied.Changed}, nil
	}
	return TeamQuotaWriteResponse{}, nil
}

// ReadTeamQuota answers from this server's FSM. A follower's answer can
// trail the leader by an apply; the decisions that must be exact (create and
// resize) are made on the leader, so a read only informs.
func (c *Cluster) ReadTeamQuota(_ context.Context, req TeamQuotaReadRequest) (TeamQuotaReadResponse, error) {
	if c == nil || c.fsm == nil {
		return TeamQuotaReadResponse{}, fmt.Errorf("cluster: node holds no placement state")
	}
	rec, usage, found := c.fsm.teamQuota(strings.TrimSpace(req.Team))
	return TeamQuotaReadResponse{Quota: rec, Found: found, Usage: usage, Authoritative: true}, nil
}

// WriteTeamQuota sends a quota write to the server tier; any server takes it
// and forwards it to the leader.
func (a *Agent) WriteTeamQuota(ctx context.Context, req TeamQuotaWriteRequest) (TeamQuotaWriteResponse, error) {
	if a == nil {
		return TeamQuotaWriteResponse{}, fmt.Errorf("cluster: agent is not configured")
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var out TeamQuotaWriteResponse
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalTeamQuotaWritePath, PublicInternalTeamQuotaWritePath, req, &out); err != nil {
		return TeamQuotaWriteResponse{}, fmt.Errorf("cluster: write team quota: %w", err)
	}
	a.teamQuotas.forget(req.Quota.Team)
	return out, out.err()
}

// ReadTeamQuota reads a team's quota and usage from the server tier. A
// worker holds no FSM, so a start check (the hot caller) is answered from a
// short cache; the decisions that must be exact are the leader's.
func (a *Agent) ReadTeamQuota(ctx context.Context, req TeamQuotaReadRequest) (TeamQuotaReadResponse, error) {
	if a == nil {
		return TeamQuotaReadResponse{}, fmt.Errorf("cluster: agent is not configured")
	}
	return a.teamQuotas.read(ctx, req, func(ctx context.Context, req TeamQuotaReadRequest) (TeamQuotaReadResponse, error) {
		reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
		defer cancel()
		var out TeamQuotaReadResponse
		if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalTeamQuotaReadPath, PublicInternalTeamQuotaReadPath, req, &out); err != nil {
			return TeamQuotaReadResponse{}, fmt.Errorf("cluster: read team quota: %w", err)
		}
		if !out.Authoritative {
			return TeamQuotaReadResponse{}, fmt.Errorf("cluster: team quota read was not authoritative")
		}
		return out, nil
	})
}

// teamQuotaCacheTTL bounds how stale a worker's quota read may be. It only
// serves the start check, which refuses a team already over a lowered quota;
// a few seconds of lag there admits nothing a create could not.
const teamQuotaCacheTTL = 5 * time.Second

type teamQuotaCache struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]teamQuotaCacheEntry
}

type teamQuotaCacheEntry struct {
	resp TeamQuotaReadResponse
	at   time.Time
}

func (c *teamQuotaCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *teamQuotaCache) forget(team string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, team)
}

func (c *teamQuotaCache) read(ctx context.Context, req TeamQuotaReadRequest, fetch func(context.Context, TeamQuotaReadRequest) (TeamQuotaReadResponse, error)) (TeamQuotaReadResponse, error) {
	now := c.clock()
	c.mu.Lock()
	if e, ok := c.entries[req.Team]; ok && now.Sub(e.at) < teamQuotaCacheTTL {
		c.mu.Unlock()
		return e.resp, nil
	}
	c.mu.Unlock()
	resp, err := fetch(ctx, req)
	if err != nil {
		return TeamQuotaReadResponse{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]teamQuotaCacheEntry)
	}
	c.entries[req.Team] = teamQuotaCacheEntry{resp: resp, at: now}
	return resp, nil
}

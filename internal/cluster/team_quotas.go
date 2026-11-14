package cluster

import (
	"context"
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

type teamQuotaReplayKey struct{}

// WithTeamQuotaAdmission marks ctx so the next opPlace it carries is
// admitted against the sandbox's team quota (QuotaAdmit): the create path
// sets it for a promote that had no reservation. The flag rides the command,
// so it reaches the leader through any number of forwards. A spec write is
// checked without it; the resize path still sets it, which changes nothing.
func WithTeamQuotaAdmission(ctx context.Context) context.Context {
	return context.WithValue(ctx, teamQuotaAdmissionKey{}, true)
}

func teamQuotaAdmission(ctx context.Context) bool {
	v, _ := ctx.Value(teamQuotaAdmissionKey{}).(bool)
	return v
}

// withTeamQuotaReplay marks ctx so the next opUpsertSpec it carries is the
// boot backfill of what a sandbox already is (QuotaReplay), never refused.
func withTeamQuotaReplay(ctx context.Context) context.Context {
	return context.WithValue(ctx, teamQuotaReplayKey{}, true)
}

func teamQuotaReplay(ctx context.Context) bool {
	v, _ := ctx.Value(teamQuotaReplayKey{}).(bool)
	return v
}

// markQuotaAdmit copies the context marks onto the command types they apply
// to; every other command is left exactly as it was.
func markQuotaAdmit(ctx context.Context, cmd command) command {
	if (cmd.Op == opPlace || cmd.Op == opUpsertSpec) && teamQuotaAdmission(ctx) {
		cmd.QuotaAdmit = true
	}
	if cmd.Op == opUpsertSpec && teamQuotaReplay(ctx) {
		cmd.QuotaReplay = true
	}
	return cmd
}

// needsTeamQuotaAdmission reports whether a command can grow a team's usage
// beyond a reservation (reservations always take the admission path): a
// marked promote, or any spec write that is not a replay. It reads only the
// command, so a leader decides the same for a command any build sent.
func needsTeamQuotaAdmission(cmd command) bool {
	switch cmd.Op {
	case opPlace:
		return cmd.QuotaAdmit
	case opUpsertSpec:
		return cmd.Spec != nil && !cmd.QuotaReplay
	}
	return false
}

// takesTeamQuotaAdmission reports whether the leader must admit cmd under
// its admission queue: it can grow a team, and that team has a quota. A spec
// write of a sandbox no limited team owns (most of them) keeps the plain
// apply path, so lifecycle and policy write-throughs do not queue behind
// creates. A quota put that lands between this read and the append only
// orders the write before the quota, the same as a reservation admitted
// just before it.
func (c *Cluster) takesTeamQuotaAdmission(cmd command) bool {
	if !needsTeamQuotaAdmission(cmd) || c.fsm == nil {
		return false
	}
	return c.fsm.anyTeamQuotaFor(teamQuotaAsks(cmd))
}

// admitTeamQuotaCommand is the leader's quota answer for cmd. It runs under
// reservationAdmissionMu with the reservation admission, so two creates for a
// team's last slot are decided one after the other, and against usage plus
// the leader's in-flight holds: the second counts the first whether or not it
// has committed yet, and is refused.
//
// Exactness across a leader change: a new leader's FSM may not yet have
// applied entries an old leader committed. Before its first admission in a
// term the leader runs a Raft barrier (admitHold), which returns once every
// entry before it is applied, so no admitted reservation is missing from the
// usage it reads.
func (c *Cluster) admitTeamQuotaCommand(cmd command) error {
	if c == nil || c.fsm == nil {
		return nil
	}
	asks := teamQuotaAsks(cmd)
	if len(asks) == 0 || !c.fsm.anyTeamQuotaFor(asks) {
		return nil
	}
	return c.fsm.admitTeamQuotasOver(c.admission.heldAsks(), asks)
}

// applyQuotaAdmittedEncodedLocal is applyReservationEncodedLocal for a
// promote or spec write that can grow a team: the same admission lock and
// ledger, the quota check, then the append.
func (c *Cluster) applyQuotaAdmittedEncodedLocal(ctx context.Context, payload []byte, cmd command) error {
	return c.applyAdmittedEncodedLocal(ctx, payload, cmd, func() error {
		return c.admitTeamQuotaCommand(cmd)
	})
}

// teamQuotaWritesAllowed is the rolling-upgrade gate for quota ops. Every
// Raft server must apply them. A put also waits for every live member, any
// role: until then a node on an older build could grow a team's sandbox the
// leader never hears about first (a worker resizes, then writes the spec),
// so setting a quota would promise a limit the cluster cannot keep. A delete
// only loosens, so the Raft gate is enough for it. The boot-window rule of
// liveMembersAtLeast applies: a leader that has just restarted and knows
// only itself refuses a put until it has rejoined.
func (c *Cluster) teamQuotaWritesAllowed(req TeamQuotaWriteRequest) error {
	if err := c.raftServersSupport(teamQuotaFSMOpsVersion, "team quotas"); err != nil {
		return err
	}
	if !req.Delete && !c.gossip.liveMembersAtLeast(teamQuotaFSMOpsVersion) {
		return fmt.Errorf("%w: a live node runs a build that does not enforce team quotas; set the quota once every node is upgraded", ErrClusterVersion)
	}
	return nil
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
	if err := c.teamQuotaWritesAllowed(req); err != nil {
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

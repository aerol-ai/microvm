package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Per-team quotas (plan item P2). An admin caps how many sandboxes a team may
// hold and how much CPU and memory they may ask for in total.
//
// What counts: every sandbox the team holds that is not deleted, running or
// stopped, at the CPU and memory it asked for. A stopped sandbox counts
// because it can be started at any time; counting only running ones would
// need every stop and start to pass through one serializing point, which a
// cluster does not have for stops.
//
// Where it is decided, so two creates for a team's last slot never both pass:
//   - One node: an in-memory ledger under one mutex (teamQuotaLedger). The
//     check and the claim are one step; a create that fails gives its claim
//     back. No store write on the create path.
//   - A cluster: the Raft leader, under the same queue it admits capacity
//     with, against usage derived from the placement rows the quorum
//     serializes (internal/cluster/fsm_team_quotas.go). Every node's creates
//     go through it, so the answer is the same from every node.

// ErrTeamQuotaExceeded is a create, resize or start a team quota refuses (429).
var ErrTeamQuotaExceeded = models.ErrTeamQuotaExceeded

// ErrTeamQuotaNotFound is a read of a team with no quota (404).
var ErrTeamQuotaNotFound = models.ErrTeamQuotaNotFound

// ErrTeamQuotaUnavailable means the quota store could not be reached (503).
var ErrTeamQuotaUnavailable = errors.New("team quotas are unavailable")

// teamQuotaCluster is the replicated quota store a cluster node offers.
type teamQuotaCluster interface {
	WriteTeamQuota(context.Context, cluster.TeamQuotaWriteRequest) (cluster.TeamQuotaWriteResponse, error)
	ReadTeamQuota(context.Context, cluster.TeamQuotaReadRequest) (cluster.TeamQuotaReadResponse, error)
}

func validateQuotaTeam(team string) error {
	if !identitywire.ValidTeamName(team) {
		return fmt.Errorf("%w: team %q: want 1 to 63 characters of a-z, 0-9 and -", models.ErrInvalidTeamQuota, team)
	}
	return nil
}

func (s *Service) quotaCluster() (teamQuotaCluster, error) {
	if qc, ok := s.Cluster().(teamQuotaCluster); ok {
		return qc, nil
	}
	return nil, fmt.Errorf("%w: this cluster has no replicated quota store", ErrTeamQuotaUnavailable)
}

func teamQuotaFromRecord(rec cluster.TeamQuotaRecord) models.TeamQuota {
	return models.TeamQuota{
		Team:         rec.Team,
		MaxSandboxes: rec.MaxSandboxes,
		MaxCPU:       rec.MaxCPU,
		MaxMemoryMB:  rec.MaxMemoryMB,
		Generation:   rec.Generation,
		CreatedAt:    time.Unix(0, rec.CreatedUnixNano).UTC(),
		UpdatedAt:    time.Unix(0, rec.UpdatedUnixNano).UTC(),
	}
}

// PutTeamQuota creates or replaces a team's quota. The same body twice is a
// no-op (same generation). Lowering a quota below what the team holds
// removes nothing: it stops the team from growing until it is back under.
func (s *Service) PutTeamQuota(ctx context.Context, team string, req models.TeamQuotaRequest) (*models.TeamQuota, error) {
	if err := validateQuotaTeam(team); err != nil {
		return nil, err
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var out models.TeamQuota
	if s.ClusterEnabled() {
		qc, err := s.quotaCluster()
		if err != nil {
			return nil, err
		}
		resp, err := qc.WriteTeamQuota(ctx, cluster.TeamQuotaWriteRequest{Quota: cluster.TeamQuotaRecord{
			Team: team, MaxSandboxes: req.MaxSandboxes, MaxCPU: req.MaxCPU, MaxMemoryMB: req.MaxMemoryMB,
		}})
		if err != nil {
			return nil, quotaClusterError(err)
		}
		out = teamQuotaFromRecord(resp.Quota)
	} else {
		q, _, err := s.store.PutTeamQuota(ctx, team, req, time.Now())
		if err != nil {
			return nil, err
		}
		s.teamQuotas.setQuota(team, q.Limits())
		out = q
	}
	return s.withTeamUsage(ctx, out)
}

// GetTeamQuota returns a team's quota and what the team holds now.
func (s *Service) GetTeamQuota(ctx context.Context, team string) (*models.TeamQuota, error) {
	if err := validateQuotaTeam(team); err != nil {
		return nil, err
	}
	if s.ClusterEnabled() {
		qc, err := s.quotaCluster()
		if err != nil {
			return nil, err
		}
		resp, err := qc.ReadTeamQuota(ctx, cluster.TeamQuotaReadRequest{Team: team})
		if err != nil {
			return nil, quotaClusterError(err)
		}
		if !resp.Found {
			return nil, ErrTeamQuotaNotFound
		}
		q := teamQuotaFromRecord(resp.Quota)
		usage := resp.Usage
		q.Usage = &usage
		return &q, nil
	}
	q, err := s.store.GetTeamQuota(ctx, team)
	if err != nil {
		return nil, err
	}
	return s.withTeamUsage(ctx, q)
}

// DeleteTeamQuota removes a team's quota. Removing one that is already gone
// succeeds, so a retried DELETE converges.
func (s *Service) DeleteTeamQuota(ctx context.Context, team string) error {
	if err := validateQuotaTeam(team); err != nil {
		return err
	}
	if s.ClusterEnabled() {
		qc, err := s.quotaCluster()
		if err != nil {
			return err
		}
		if _, err := qc.WriteTeamQuota(ctx, cluster.TeamQuotaWriteRequest{Delete: true, Quota: cluster.TeamQuotaRecord{Team: team}}); err != nil {
			return quotaClusterError(err)
		}
		return nil
	}
	if err := s.store.DeleteTeamQuota(ctx, team); err != nil {
		return err
	}
	s.teamQuotas.dropQuota(team)
	return nil
}

// withTeamUsage fills a quota's usage: the replicated index in a cluster,
// the ledger on one node.
func (s *Service) withTeamUsage(ctx context.Context, q models.TeamQuota) (*models.TeamQuota, error) {
	if s.ClusterEnabled() {
		qc, err := s.quotaCluster()
		if err != nil {
			return nil, err
		}
		resp, err := qc.ReadTeamQuota(ctx, cluster.TeamQuotaReadRequest{Team: q.Team})
		if err != nil {
			return nil, quotaClusterError(err)
		}
		usage := resp.Usage
		q.Usage = &usage
		return &q, nil
	}
	usage, err := s.teamQuotas.usage(ctx, s.store, q.Team)
	if err != nil {
		return nil, err
	}
	q.Usage = &usage
	return &q, nil
}

// quotaClusterError keeps the sentinels a client acts on and turns anything
// else (no leader, a forward that failed) into a retryable 503.
func quotaClusterError(err error) error {
	switch {
	case errors.Is(err, cluster.ErrClusterVersion):
		return fmt.Errorf("%w: %v", ErrTeamQuotaUnavailable, err)
	case errors.Is(err, ErrTeamQuotaExceeded), errors.Is(err, models.ErrInvalidTeamQuota):
		return err
	}
	return fmt.Errorf("%w: %v", ErrTeamQuotaUnavailable, err)
}

// teamQuotaTicket is a create's claim on its team's quota, settled when the
// create ends: kept under the sandbox's id on success, given back on failure.
type teamQuotaTicket struct {
	ledger *teamQuotaLedger
	team   string
	key    string
}

func (t *teamQuotaTicket) settle(resp *models.CreateSandboxResponse, err error) {
	if t == nil {
		return
	}
	id := ""
	if err == nil && resp != nil {
		id = resp.Sandbox.ID
	}
	t.ledger.settle(t.team, t.key, id)
}

// admitTeamQuotaCreate claims room in the creating team's quota on one node.
// A cluster node returns no ticket: its leader admitted the reservation (or
// admits the promote) already, against the whole cluster's usage.
func (s *Service) admitTeamQuotaCreate(ctx context.Context, ownerRef string, req models.CreateSandboxRequest) (*teamQuotaTicket, error) {
	team := models.TeamOfOwnerRef(ownerRef)
	if team == "" || s.ClusterEnabled() || s.store == nil {
		return nil, nil
	}
	cpu, mem := models.QuotaSize(req.CPU, req.MemoryMB)
	return s.teamQuotas.admit(ctx, s.store, team, cpu, mem)
}

// releaseTeamQuota gives a destroyed sandbox's share back on one node.
func (s *Service) releaseTeamQuota(sandbox *models.Sandbox) {
	if sandbox == nil || s.ClusterEnabled() {
		return
	}
	if team := models.TeamOfOwnerRef(sandbox.OwnerRef); team != "" {
		s.teamQuotas.release(team, sandbox.ID)
	}
}

// admitTeamQuotaResize checks a resize that grows a team's sandbox before
// anything changes, and returns how to undo the claim if the resize then
// fails. One node: the ledger. A cluster: the spec write that records the
// new size goes first, admitted by the leader (QuotaAdmit); undo writes the
// old size back. A sandbox no team owns, or a resize that does not grow,
// takes the old path unchanged.
func (s *Service) admitTeamQuotaResize(ctx context.Context, sandbox *models.Sandbox, cpu float64, memoryMB int) (undo func(), wroteSpec bool, err error) {
	noop := func() {}
	team := models.TeamOfOwnerRef(sandbox.OwnerRef)
	if team == "" || (cpu <= sandbox.CPU && memoryMB <= sandbox.MemoryMB) {
		return noop, false, nil
	}
	if !s.ClusterEnabled() {
		if s.store == nil {
			return noop, false, nil
		}
		undo, err := s.teamQuotas.resize(ctx, s.store, team, sandbox.ID, cpu, memoryMB)
		return undo, false, err
	}
	c := s.Cluster()
	if c == nil {
		return noop, false, nil
	}
	spec := c.SpecOf(sandbox.ID)
	if spec == nil {
		// No replicated spec to grow: nothing records the new size, so the
		// leader has nothing to admit. The post-resize write-through stays
		// best effort, exactly as before quotas.
		return noop, false, nil
	}
	old := *spec
	spec.CPU, spec.MemoryMB = cpu, memoryMB
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.UpsertSpec(cluster.WithTeamQuotaAdmission(commitCtx), sandbox.ID, spec, cluster.PlacementSecrets{}); err != nil {
		if errors.Is(err, ErrTeamQuotaExceeded) {
			return noop, false, err
		}
		// The size could not be recorded, so it could not be admitted: a
		// growth the quota never saw must not happen.
		return noop, false, fmt.Errorf("%w: record the new size: %v", ErrTeamQuotaUnavailable, err)
	}
	return func() {
		rbCtx, rbCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer rbCancel()
		if err := c.UpsertSpec(rbCtx, sandbox.ID, &old, cluster.PlacementSecrets{}); err != nil && s.logger != nil {
			s.logger.Warn("team quota: could not write back the old size after a failed resize; the team counts the larger size until the next spec write",
				"sandbox_id", sandbox.ID, "err", err)
		}
	}, true, nil
}

// checkTeamQuotaForStart refuses to start a stopped sandbox of a team that
// is over its quota. A start adds nothing to usage (a stopped sandbox
// already counts), so this only bites after an admin lowered the quota: the
// team cannot bring stopped sandboxes back until it is under again. A failed
// read lets the start through, since it cannot grow the team.
func (s *Service) checkTeamQuotaForStart(ctx context.Context, sandbox *models.Sandbox) error {
	team := models.TeamOfOwnerRef(sandbox.OwnerRef)
	if team == "" {
		return nil
	}
	var limits models.TeamQuotaRequest
	var usage models.TeamQuotaUsage
	if s.ClusterEnabled() {
		qc, err := s.quotaCluster()
		if err != nil {
			return nil
		}
		resp, err := qc.ReadTeamQuota(ctx, cluster.TeamQuotaReadRequest{Team: team})
		if err != nil || !resp.Found {
			if err != nil && s.logger != nil {
				s.logger.Warn("team quota: start check could not read the quota; starting", "team", team, "err", err)
			}
			return nil
		}
		limits, usage = teamQuotaFromRecord(resp.Quota).Limits(), resp.Usage
	} else {
		if s.store == nil {
			return nil
		}
		var found bool
		var err error
		limits, usage, found, err = s.teamQuotas.status(ctx, s.store, team)
		if err != nil || !found {
			return nil
		}
	}
	return models.CheckTeamQuota(team, limits, usage, models.TeamQuotaUsage{})
}

// teamQuotaLedger is one node's count of what each limited team holds. It
// tracks only teams that have a quota; a team's count is loaded from the
// store the first time it is needed (and again when a refusal looks wrong,
// so a destroy the ledger missed cannot block a team forever). A create's
// claim is keyed by a pending key until it settles under the sandbox id.
type teamQuotaLedger struct {
	mu     sync.Mutex
	loaded bool
	quotas map[string]models.TeamQuotaRequest
	teams  map[string]*teamLedger
	seq    uint64
}

type teamLedger struct {
	usage   models.TeamQuotaUsage
	entries map[string]teamLedgerEntry
}

type teamLedgerEntry struct {
	cpu      float64
	memoryMB int
	pending  bool
}

func (l *teamLedger) add(key string, e teamLedgerEntry) {
	if old, ok := l.entries[key]; ok {
		l.remove(key, old)
	}
	l.entries[key] = e
	l.usage.Sandboxes++
	l.usage.CPU += e.cpu
	l.usage.MemoryMB += e.memoryMB
}

func (l *teamLedger) remove(key string, e teamLedgerEntry) {
	delete(l.entries, key)
	l.usage.Sandboxes--
	l.usage.CPU -= e.cpu
	l.usage.MemoryMB -= e.memoryMB
}

// loadLocked reads the quota table once.
func (q *teamQuotaLedger) loadLocked(ctx context.Context, st *store.Store) error {
	if q.loaded {
		return nil
	}
	all, err := st.ListTeamQuotas(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTeamQuotaUnavailable, err)
	}
	q.quotas = make(map[string]models.TeamQuotaRequest, len(all))
	for _, rec := range all {
		q.quotas[rec.Team] = rec.Limits()
	}
	if q.teams == nil {
		q.teams = make(map[string]*teamLedger)
	}
	q.loaded = true
	return nil
}

// teamLocked returns a limited team's count, loading it from the store the
// first time; nil for a team with no quota.
func (q *teamQuotaLedger) teamLocked(ctx context.Context, st *store.Store, team string) (*teamLedger, models.TeamQuotaRequest, error) {
	if err := q.loadLocked(ctx, st); err != nil {
		return nil, models.TeamQuotaRequest{}, err
	}
	limits, ok := q.quotas[team]
	if !ok {
		return nil, limits, nil
	}
	if tl := q.teams[team]; tl != nil {
		return tl, limits, nil
	}
	tl, err := q.rebuildLocked(ctx, st, team, nil)
	return tl, limits, err
}

// rebuildLocked counts a team from the store, keeping the pending claims of
// creates still running (their rows may not exist yet).
func (q *teamQuotaLedger) rebuildLocked(ctx context.Context, st *store.Store, team string, prev *teamLedger) (*teamLedger, error) {
	rows, err := st.TeamQuotaSandboxes(ctx, models.TeamOwnerPrefix+team)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTeamQuotaUnavailable, err)
	}
	tl := &teamLedger{entries: make(map[string]teamLedgerEntry, len(rows))}
	for _, r := range rows {
		cpu, mem := models.QuotaSize(r.CPU, r.MemoryMB)
		tl.add(r.ID, teamLedgerEntry{cpu: cpu, memoryMB: mem})
	}
	if prev != nil {
		for key, e := range prev.entries {
			if e.pending {
				tl.add(key, e)
			}
		}
	}
	q.teams[team] = tl
	return tl, nil
}

// admit claims one sandbox of size cpu/mem for team, or refuses.
func (q *teamQuotaLedger) admit(ctx context.Context, st *store.Store, team string, cpu float64, mem int) (*teamQuotaTicket, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	tl, limits, err := q.teamLocked(ctx, st, team)
	if err != nil || tl == nil {
		return nil, err
	}
	ask := models.TeamQuotaUsage{Sandboxes: 1, CPU: cpu, MemoryMB: mem}
	if err := models.CheckTeamQuota(team, limits, tl.usage, ask); err != nil {
		// Before refusing, recount from the store: a destroy on a path that
		// did not tell the ledger would otherwise hold the slot forever.
		fresh, rerr := q.rebuildLocked(ctx, st, team, tl)
		if rerr != nil {
			return nil, rerr
		}
		if err := models.CheckTeamQuota(team, limits, fresh.usage, ask); err != nil {
			return nil, err
		}
		tl = fresh
	}
	q.seq++
	key := fmt.Sprintf("pending:%d", q.seq)
	tl.add(key, teamLedgerEntry{cpu: cpu, memoryMB: mem, pending: true})
	return &teamQuotaTicket{ledger: q, team: team, key: key}, nil
}

// settle ends a create's claim: kept under id when the create succeeded,
// given back otherwise.
func (q *teamQuotaLedger) settle(team, key, id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	tl := q.teams[team]
	if tl == nil {
		return
	}
	e, ok := tl.entries[key]
	if !ok {
		return
	}
	tl.remove(key, e)
	if id != "" {
		e.pending = false
		tl.add(id, e)
	}
}

// release gives a destroyed sandbox's share back.
func (q *teamQuotaLedger) release(team, id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if tl := q.teams[team]; tl != nil {
		if e, ok := tl.entries[id]; ok {
			tl.remove(id, e)
		}
	}
}

// resize re-sizes a sandbox's share, refusing growth past the quota.
func (q *teamQuotaLedger) resize(ctx context.Context, st *store.Store, team, id string, cpu float64, mem int) (func(), error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	noop := func() {}
	tl, limits, err := q.teamLocked(ctx, st, team)
	if err != nil || tl == nil {
		return noop, err
	}
	old, had := tl.entries[id]
	grow := models.TeamQuotaUsage{CPU: max(cpu-old.cpu, 0), MemoryMB: max(mem-old.memoryMB, 0)}
	if !had {
		grow = models.TeamQuotaUsage{Sandboxes: 1, CPU: cpu, MemoryMB: mem}
	}
	if err := models.CheckTeamQuota(team, limits, tl.usage, grow); err != nil {
		return noop, err
	}
	tl.add(id, teamLedgerEntry{cpu: cpu, memoryMB: mem})
	return func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		cur := q.teams[team]
		if cur == nil {
			return
		}
		if had {
			cur.add(id, old)
		} else if e, ok := cur.entries[id]; ok {
			cur.remove(id, e)
		}
	}, nil
}

// status returns a team's limits and usage.
func (q *teamQuotaLedger) status(ctx context.Context, st *store.Store, team string) (models.TeamQuotaRequest, models.TeamQuotaUsage, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	tl, limits, err := q.teamLocked(ctx, st, team)
	if err != nil || tl == nil {
		return limits, models.TeamQuotaUsage{}, false, err
	}
	return limits, tl.usage, true, nil
}

// usage returns what a team holds, counted from the store when the team has
// no quota (the ledger only tracks limited teams).
func (q *teamQuotaLedger) usage(ctx context.Context, st *store.Store, team string) (models.TeamQuotaUsage, error) {
	_, usage, found, err := q.status(ctx, st, team)
	if err != nil || found {
		return usage, err
	}
	rows, err := st.TeamQuotaSandboxes(ctx, models.TeamOwnerPrefix+team)
	if err != nil {
		return models.TeamQuotaUsage{}, fmt.Errorf("%w: %v", ErrTeamQuotaUnavailable, err)
	}
	for _, r := range rows {
		cpu, mem := models.QuotaSize(r.CPU, r.MemoryMB)
		usage.Sandboxes++
		usage.CPU += cpu
		usage.MemoryMB += mem
	}
	return usage, nil
}

// setQuota records a new or changed quota. A team newly limited is counted
// from the store at its next admission.
func (q *teamQuotaLedger) setQuota(team string, limits models.TeamQuotaRequest) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.loaded {
		return
	}
	q.quotas[team] = limits
}

// dropQuota stops tracking a team whose quota was deleted.
func (q *teamQuotaLedger) dropQuota(team string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.loaded {
		return
	}
	delete(q.quotas, team)
	delete(q.teams, strings.TrimSpace(team))
}

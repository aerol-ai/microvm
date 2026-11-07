package cluster

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Per-team quotas in the Raft FSM (plan item P2). The quota records are
// replicated objects, like named egress profiles. A team's usage is NOT a
// counter anyone increments: it is derived from the placement rows (every
// reserved or placed sandbox the team owns, at its requested size), kept in
// step by storePlacementLocked and the delete paths, and rebuilt on Restore.
// The quorum already serializes those rows, so the usage the leader reads is
// exactly what the log has committed.
//
// Admission is a leader-side check, like capacity admission (placement.go):
// it runs under reservationAdmissionMu before the entry is appended, never in
// Apply. A replica on an older build therefore applies exactly the entries
// the leader admitted and cannot diverge from one that refuses.
const (
	opPutTeamQuota    opCode = 38 // create or replace one team's quota
	opDeleteTeamQuota opCode = 39 // remove one team's quota
)

// teamQuotaFSMOpsVersion: opPutTeamQuota, opDeleteTeamQuota. A leader writes
// a quota only once every Raft server reports it, so no replica ever skips a
// quota op, and once quotas exist every possible leader enforces them. It
// sets one only once every live member, any role, reports it too
// (teamQuotaWritesAllowed): a worker on an older build grows a sandbox
// before it tells the leader, and a node on one reserves a facade create
// without the caller's owner, so the leader could stop neither.
const teamQuotaFSMOpsVersion = 9

// ErrTeamQuotaExceeded is a reservation, promote or spec change the leader
// refused because it would take a team past its quota.
var ErrTeamQuotaExceeded = models.ErrTeamQuotaExceeded

// TeamQuotaRecord is one replicated team quota.
type TeamQuotaRecord struct {
	Team            string  `json:"team"`
	MaxSandboxes    int     `json:"max_sandboxes,omitempty"`
	MaxCPU          float64 `json:"max_cpu,omitempty"`
	MaxMemoryMB     int     `json:"max_memory_mb,omitempty"`
	Generation      int64   `json:"generation"`
	CreatedUnixNano int64   `json:"created_unix_nano"`
	UpdatedUnixNano int64   `json:"updated_unix_nano"`
}

func (r TeamQuotaRecord) limits() models.TeamQuotaRequest {
	return models.TeamQuotaRequest{MaxSandboxes: r.MaxSandboxes, MaxCPU: r.MaxCPU, MaxMemoryMB: r.MaxMemoryMB}
}

// teamUsageEntry is one sandbox's share of its team's usage.
type teamUsageEntry struct {
	team     string
	cpu      float64
	memoryMB int
}

// teamQuotaApplyResult is the leader FSM's answer to opPutTeamQuota.
type teamQuotaApplyResult struct {
	Quota   TeamQuotaRecord
	Changed bool
}

// quotaTeamOf is the team a placement row counts against, "" for none. Only
// team owners are counted: operator and managed-account sandboxes are never
// limited by a team quota.
func quotaTeamOf(p *Placement) string {
	if p == nil {
		return ""
	}
	return models.TeamOfOwnerRef(p.OwnerRef)
}

// quotaSizeOf is the size a placement row counts for. The hot row's mirror
// is set from the spec on every write that has one; a row whose spec was not
// at hand keeps the size its previous write recorded, and a row written by a
// build before quotas (no mirror at all) counts at the default size.
func quotaSizeOf(p *Placement, prev *teamUsageEntry) (float64, int) {
	if p.QuotaCPU > 0 || p.QuotaMemoryMB > 0 {
		return models.QuotaSize(p.QuotaCPU, p.QuotaMemoryMB)
	}
	if prev != nil {
		return prev.cpu, prev.memoryMB
	}
	return models.QuotaSize(0, 0)
}

// reindexTeamUsageLocked moves sandbox id's share from its old row to its
// new one (nil removes it). Every write and delete of f.placements passes
// through here, so usage cannot drift from the rows it is derived from.
func (f *placementFSM) reindexTeamUsageLocked(id string, nu *Placement) {
	if f.teamUsage == nil {
		f.teamUsage = make(map[string]*models.TeamQuotaUsage)
	}
	if f.teamUsageEntries == nil {
		f.teamUsageEntries = make(map[string]teamUsageEntry)
	}
	prev, had := f.teamUsageEntries[id]
	if had {
		if u := f.teamUsage[prev.team]; u != nil {
			u.Sandboxes--
			u.CPU -= prev.cpu
			u.MemoryMB -= prev.memoryMB
			if u.Sandboxes <= 0 {
				delete(f.teamUsage, prev.team)
			}
		}
		delete(f.teamUsageEntries, id)
	}
	team := quotaTeamOf(nu)
	if team == "" {
		return
	}
	var prevPtr *teamUsageEntry
	if had {
		prevPtr = &prev
	}
	cpu, mem := quotaSizeOf(nu, prevPtr)
	f.teamUsageEntries[id] = teamUsageEntry{team: team, cpu: cpu, memoryMB: mem}
	u := f.teamUsage[team]
	if u == nil {
		u = &models.TeamQuotaUsage{}
		f.teamUsage[team] = u
	}
	u.Sandboxes++
	u.CPU += cpu
	u.MemoryMB += mem
}

func (f *placementFSM) applyPutTeamQuotaLocked(cmd command) (any, error) {
	in := cmd.TeamQuota
	if in == nil || strings.TrimSpace(in.Team) == "" {
		return nil, fmt.Errorf("placementFSM: opPutTeamQuota requires a quota")
	}
	if f.teamQuotas == nil {
		f.teamQuotas = make(map[string]*TeamQuotaRecord)
	}
	old, exists := f.teamQuotas[in.Team]
	if exists && old.limits() == in.limits() {
		return teamQuotaApplyResult{Quota: *old}, nil
	}
	rec := *in
	rec.Generation, rec.CreatedUnixNano = 1, cmd.StampUnixNano
	if exists {
		rec.Generation, rec.CreatedUnixNano = old.Generation+1, old.CreatedUnixNano
	}
	rec.UpdatedUnixNano = cmd.StampUnixNano
	f.teamQuotas[in.Team] = &rec
	return teamQuotaApplyResult{Quota: rec, Changed: true}, nil
}

func (f *placementFSM) applyDeleteTeamQuotaLocked(cmd command) error {
	in := cmd.TeamQuota
	if in == nil || strings.TrimSpace(in.Team) == "" {
		return fmt.Errorf("placementFSM: opDeleteTeamQuota requires a team")
	}
	delete(f.teamQuotas, in.Team)
	return nil
}

// teamQuota returns a team's quota and its usage.
func (f *placementFSM) teamQuota(team string) (TeamQuotaRecord, models.TeamQuotaUsage, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var usage models.TeamQuotaUsage
	if u := f.teamUsage[team]; u != nil {
		usage = *u
	}
	rec, ok := f.teamQuotas[team]
	if !ok {
		return TeamQuotaRecord{}, usage, false
	}
	return *rec, usage, true
}

// teamQuotaAsk is one sandbox a command would add or resize.
type teamQuotaAsk struct {
	sandboxID string
	team      string
	cpu       float64
	memoryMB  int
}

// teamQuotaAsks lists what a command would add to team usage. Only the
// commands that can grow a team are admitted: reservations, a promote the
// caller marked (QuotaAdmit) because it is a create, and every spec write.
// A spec write is checked whatever its sender says, because a worker on a
// build before quotas resizes with an unmarked one; one that does not grow
// the sandbox passes (checkTeamQuotasLocked checks growth only). Boot replay
// (an unmarked promote, or a spec backfill marked QuotaReplay), orphan claims
// and failover moves are never refused: they move or describe a sandbox the
// team already holds.
func teamQuotaAsks(cmd command) []teamQuotaAsk {
	ask := func(id, ownerRef string, spec *models.CreateSandboxRequest) (teamQuotaAsk, bool) {
		if spec == nil {
			return teamQuotaAsk{}, false
		}
		cpu, mem := models.QuotaSize(spec.CPU, spec.MemoryMB)
		return teamQuotaAsk{sandboxID: id, team: models.TeamOfOwnerRef(ownerRef), cpu: cpu, memoryMB: mem}, true
	}
	var out []teamQuotaAsk
	switch cmd.Op {
	case opReserve:
		if a, ok := ask(cmd.SandboxID, cmd.OwnerRef, cmd.Spec); ok {
			out = append(out, a)
		}
	case opReserveBatch:
		for _, r := range cmd.Reservations {
			if a, ok := ask(r.SandboxID, r.OwnerRef, r.Spec); ok {
				out = append(out, a)
			}
		}
	case opPlace:
		if cmd.QuotaAdmit {
			if a, ok := ask(cmd.SandboxID, cmd.OwnerRef, cmd.Spec); ok {
				out = append(out, a)
			}
		}
	case opUpsertSpec:
		if !cmd.QuotaReplay {
			if a, ok := ask(cmd.SandboxID, cmd.OwnerRef, cmd.Spec); ok {
				out = append(out, a)
			}
		}
	}
	return out
}

// checkTeamQuotasLocked is the admission answer for asks, counted against
// the committed usage plus every earlier ask in the same command. A sandbox
// already in the index counts as a change of size, not a new sandbox, so a
// retried reservation or a promote never counts twice. f.mu must be held.
func (f *placementFSM) checkTeamQuotasLocked(asks []teamQuotaAsk) error {
	added := make(map[string]models.TeamQuotaUsage)
	for _, a := range asks {
		team := a.team
		prev, had := f.teamUsageEntries[a.sandboxID]
		if team == "" && had {
			// A spec change carries no owner; the row it changes does.
			team = prev.team
		}
		if team == "" {
			continue
		}
		delta := models.TeamQuotaUsage{Sandboxes: 1, CPU: a.cpu, MemoryMB: a.memoryMB}
		if had && prev.team == team {
			delta = models.TeamQuotaUsage{CPU: a.cpu - prev.cpu, MemoryMB: a.memoryMB - prev.memoryMB}
		}
		rec, ok := f.teamQuotas[team]
		if !ok {
			continue
		}
		var usage models.TeamQuotaUsage
		if u := f.teamUsage[team]; u != nil {
			usage = *u
		}
		sum := added[team]
		usage.Sandboxes += sum.Sandboxes
		usage.CPU += sum.CPU
		usage.MemoryMB += sum.MemoryMB
		// Only growth is checked: shrinking a sandbox of a team that is over
		// a lowered quota must still be allowed, or the team could never
		// get back under it.
		grow := models.TeamQuotaUsage{Sandboxes: max(delta.Sandboxes, 0), CPU: max(delta.CPU, 0), MemoryMB: max(delta.MemoryMB, 0)}
		if grow != (models.TeamQuotaUsage{}) {
			if err := models.CheckTeamQuota(team, rec.limits(), usage, grow); err != nil {
				return err
			}
		}
		sum.Sandboxes += delta.Sandboxes
		sum.CPU += delta.CPU
		sum.MemoryMB += delta.MemoryMB
		added[team] = sum
	}
	return nil
}

// admitTeamQuotas reports whether asks fit their teams' quotas.
func (f *placementFSM) admitTeamQuotas(asks []teamQuotaAsk) error {
	if len(asks) == 0 {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.checkTeamQuotasLocked(asks)
}

// anyTeamQuotaFor reports whether any ask's team (or the team of the row it
// changes) has a quota: the leader's barrier is paid only then.
func (f *placementFSM) anyTeamQuotaFor(asks []teamQuotaAsk) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, a := range asks {
		team := a.team
		if team == "" {
			team = f.teamUsageEntries[a.sandboxID].team
		}
		if _, ok := f.teamQuotas[team]; ok && team != "" {
			return true
		}
	}
	return false
}

func (f *placementFSM) teamQuotasSnapshotLocked() []TeamQuotaRecord {
	out := make([]TeamQuotaRecord, 0, len(f.teamQuotas))
	for _, rec := range f.teamQuotas {
		out = append(out, *rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Team < out[j].Team })
	return out
}

func (f *placementFSM) restoreTeamQuotasLocked(records []TeamQuotaRecord) {
	f.teamQuotas = make(map[string]*TeamQuotaRecord, len(records))
	for _, r := range records {
		rec := r
		if strings.TrimSpace(rec.Team) == "" {
			continue
		}
		f.teamQuotas[rec.Team] = &rec
	}
}

// Outcome codes of a quota write, carried in a 200 body so they survive any
// number of forwarding hops (the egress-profile pattern).
const teamQuotaCodeClusterVersion = "cluster_version"

// TeamQuotaWriteRequest puts (Delete false) or deletes one team's quota.
type TeamQuotaWriteRequest struct {
	Delete bool            `json:"delete,omitempty"`
	Quota  TeamQuotaRecord `json:"quota"`
}

// TeamQuotaWriteResponse is the outcome of a write.
type TeamQuotaWriteResponse struct {
	Quota   TeamQuotaRecord `json:"quota"`
	Changed bool            `json:"changed"`
	Code    string          `json:"code,omitempty"`
	Message string          `json:"message,omitempty"`
}

// TeamQuotaWriteOutcome turns a write error into the body a peer gets.
func TeamQuotaWriteOutcome(err error) TeamQuotaWriteResponse {
	if errors.Is(err, ErrClusterVersion) {
		return TeamQuotaWriteResponse{Code: teamQuotaCodeClusterVersion, Message: err.Error()}
	}
	return TeamQuotaWriteResponse{}
}

func (r TeamQuotaWriteResponse) err() error {
	switch r.Code {
	case "":
		return nil
	case teamQuotaCodeClusterVersion:
		return fmt.Errorf("%w (%s)", ErrClusterVersion, r.Message)
	default:
		return fmt.Errorf("cluster: team quota write: %s: %s", r.Code, r.Message)
	}
}

// TeamQuotaReadRequest reads one team's quota and usage.
type TeamQuotaReadRequest struct {
	Team string `json:"team"`
}

// TeamQuotaReadResponse answers from a server's FSM. Found is false when the
// team has no quota; Usage is filled either way.
type TeamQuotaReadResponse struct {
	Quota         TeamQuotaRecord       `json:"quota"`
	Found         bool                  `json:"found"`
	Usage         models.TeamQuotaUsage `json:"usage"`
	Authoritative bool                  `json:"authoritative"`
}

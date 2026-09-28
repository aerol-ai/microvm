package cluster

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// Storage-retirement obligations (UC-160).
//
// Draining a node that holds sealed secret material must leave one visible,
// fleet-wide record that the node still owes a wipe. Two patterns, both from
// systems that solved this at scale:
//
//   - One job per leaving node on the shared board (Cassandra decommission,
//     CockroachDB node decommission, Nomad drain). The job is opened by the
//     drain itself and closes only when the node is uncordoned (it is staying)
//     or an operator attests its storage destroyed. A delete ACK never closes
//     it: an ACK of the current copies is not proof the disk holds no older
//     ciphertext.
//
//   - Owners report a CURRENT total on a timer (Kubernetes node status, Ceph
//     recovery). Pending deletes live in each owner's private SQLite outbox;
//     every owner periodically reports "the set of nodes I still owe deletes
//     to, and how many rows each", and the leader REPLACES that owner's
//     previous report. A retried report cannot double-count, and a reporter
//     that stops checking in is shown stale — silence is never "nothing owed".
//
// Refused, as those systems refuse them: fanning out to every owner when the
// screen is read, a +1/-1 tally, and a raft write per secret copy.
//
// Current holders need no reporting at all: the placement FSM already stores
// every placement's SecretRecipients, so the job's "still a holder" count is
// read straight from it.

// opReportStorageObligations carries a batch of owner reports, folded by the
// leader into one raft entry.
const opReportStorageObligations opCode = 26

const (
	// obligationReportInterval is how often an owner recomputes its report.
	// It sends only when the report changed or obligationReportRefresh has
	// passed, so a quiet fleet costs no raft writes.
	obligationReportInterval = 30 * time.Second
	// obligationReportRefresh is the heartbeat for an unchanged report. It
	// is deliberately coarse: freshness rides raft, and a 30s heartbeat from
	// 2,000 owners would be a permanent write stream of "still nothing".
	obligationReportRefresh = 5 * time.Minute
	// obligationStaleAfter is three missed refreshes. A reporter older than
	// this is listed stale and the job is not complete.
	obligationStaleAfter = 3 * obligationReportRefresh
	// obligationBatchWindow is how long the leader gathers reports before
	// folding them into one raft entry.
	obligationBatchWindow = time.Second
	// obligationIdleReportTTL prunes the report of an owner that owes nothing
	// and has not reported for a day, so the table tracks the live fleet
	// rather than every node that ever existed. An owner that still owes a
	// delete is never pruned: that is exactly the silent disk that must stay
	// visible.
	obligationIdleReportTTL = 24 * time.Hour
)

// StorageObligationReport is one owner's current snapshot of the deletes it
// still owes. It REPLACES that owner's previous report.
type StorageObligationReport struct {
	Reporter string `json:"reporter"`
	// Seq increases on every report from this owner. The FSM ignores a report
	// whose Seq is not newer than the one it holds, so a retried or
	// out-of-order delivery can never resurrect an outbox row the owner has
	// already cleared.
	Seq uint64 `json:"seq"`
	// ObservedUnixNano is the owner's own clock when it took the snapshot.
	// Informational only: staleness is judged on ReceivedUnixNano.
	ObservedUnixNano int64 `json:"observed_unix_nano,omitempty"`
	// Owed maps node id -> number of outbox rows still owing that node a
	// delete. Empty is a real report ("I owe nothing"), not an absent one.
	Owed map[string]int `json:"owed,omitempty"`
	// ReceivedUnixNano is stamped by the leader when the batch is proposed,
	// never by Apply: every replica must reach the same state from the log.
	ReceivedUnixNano int64 `json:"received_unix_nano,omitempty"`
}

// StorageObligation is the open job for one draining node.
type StorageObligation struct {
	NodeID         string `json:"node_id"`
	OpenedUnixNano int64  `json:"opened_unix_nano,omitempty"`
}

// StorageObligationReporter is one owner's contribution to a job, as the
// operator sees it.
type StorageObligationReporter struct {
	NodeID     string    `json:"node_id"`
	Owed       int       `json:"owed"`
	ReportedAt time.Time `json:"reported_at,omitempty"`
	Stale      bool      `json:"stale"`
}

// StorageObligationView is what GET /v1/cluster/storage-retirements shows for
// an open job.
type StorageObligationView struct {
	NodeID   string    `json:"node_id"`
	OpenedAt time.Time `json:"opened_at,omitempty"`
	// Holders is how many placements still list the node as a secret
	// recipient — copies the reseal has not moved yet.
	Holders int `json:"holders"`
	// PendingDeletes sums the owners' reported outbox rows owed to the node.
	PendingDeletes int `json:"pending_deletes"`
	// Reporters are the owners that report owing this node something.
	Reporters []StorageObligationReporter `json:"reporters,omitempty"`
	// StaleReporters are owners expected to report whose last report is too
	// old (or absent). Their outbox is unknown, so PendingDeletes may be low.
	StaleReporters []StorageObligationReporter `json:"stale_reporters,omitempty"`
	// Complete is false whenever a reporter is stale: the counts are then a
	// floor, never an all-clear.
	Complete bool `json:"complete"`
	// ReadyForAttestation: no copies left, no deletes owed, every reporter
	// fresh. The job still stays open until an operator attests.
	ReadyForAttestation bool `json:"ready_for_attestation"`
}

// StorageObligationsResponse is the internal wire shape agents read.
type StorageObligationsResponse struct {
	Obligations []StorageObligationView `json:"obligations"`
}

// PublicInternalStorageObligationsPath serves the job view to agents (an
// ingress or worker has no FSM). One call to a server — never a fan-out.
const PublicInternalStorageObligationsPath = "/v1/cluster/internal/storage-obligations"

// StorageObligationReporterClient is implemented by clients that can submit
// an owner report. Optional (type-asserted) so no test double must grow it.
type StorageObligationReporterClient interface {
	ReportStorageObligations(ctx context.Context, report StorageObligationReport) error
}

// StorageObligationsReader is implemented by clients that can serve the job
// view.
type StorageObligationsReader interface {
	StorageObligations(ctx context.Context) ([]StorageObligationView, error)
}

// normalizeOwed drops non-positive and blank entries so equal reports compare
// equal and an "owes 0" entry never reads as a debt.
func normalizeOwed(in map[string]int) map[string]int {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int, len(in))
	for id, n := range in {
		if id = strings.TrimSpace(id); id != "" && n > 0 {
			out[id] = n
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func owedEqual(a, b map[string]int) bool {
	a, b = normalizeOwed(a), normalizeOwed(b)
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// --- FSM rules (all under f.mu; deterministic: time comes from the command) ---

// nodeHoldsSecretCopyLocked reports whether any placement lists nodeID as a
// secret recipient. O(placements) with early exit; it runs once per drain, an
// operator action, never on the create path.
func (f *placementFSM) nodeHoldsSecretCopyLocked(nodeID string) bool {
	for _, p := range f.placements {
		for _, r := range p.SecretRecipients {
			if r == nodeID {
				return true
			}
		}
	}
	return false
}

func (f *placementFSM) nodeOwedByReportsLocked(nodeID string) bool {
	for _, r := range f.obligationReports {
		if r.Owed[nodeID] > 0 {
			return true
		}
	}
	return false
}

// applyDrainObligationLocked opens a job when a node that owes a wipe is
// drained, and withdraws it when the node is uncordoned (it is staying, so
// there is nothing to wipe). Idempotent on both edges.
func (f *placementFSM) applyDrainObligationLocked(nodeID string, drained bool, stamp int64) {
	if !drained {
		delete(f.storageObligations, nodeID)
		return
	}
	if _, open := f.storageObligations[nodeID]; open {
		return
	}
	if !f.nodeHoldsSecretCopyLocked(nodeID) && !f.nodeOwedByReportsLocked(nodeID) {
		return
	}
	if f.storageObligations == nil {
		f.storageObligations = make(map[string]StorageObligation)
	}
	f.storageObligations[nodeID] = StorageObligation{NodeID: nodeID, OpenedUnixNano: stamp}
}

// closeObligationLocked discharges a job — an operator attested the node's
// storage destroyed. The attestation itself stays in storageRetirements.
func (f *placementFSM) closeObligationLocked(nodeID string) {
	delete(f.storageObligations, nodeID)
}

// applyObligationReportsLocked replaces each reporter's snapshot with a newer
// one. A report whose Seq is not newer is ignored — that is the whole
// retry/reordering guarantee. A report naming a drained node that has no job
// yet opens one: the debt was created after the drain (e.g. by the reseal it
// triggered) and must still be visible.
func (f *placementFSM) applyObligationReportsLocked(reports []StorageObligationReport, stamp int64) {
	if f.obligationReports == nil {
		f.obligationReports = make(map[string]StorageObligationReport)
	}
	for _, r := range reports {
		reporter := strings.TrimSpace(r.Reporter)
		if reporter == "" {
			continue
		}
		if prev, ok := f.obligationReports[reporter]; ok && r.Seq <= prev.Seq {
			continue
		}
		r.Reporter = reporter
		r.Owed = normalizeOwed(r.Owed)
		r.ReceivedUnixNano = stamp
		f.obligationReports[reporter] = r
		for nodeID := range r.Owed {
			if !f.drainedNodes[nodeID] {
				continue
			}
			if _, open := f.storageObligations[nodeID]; open {
				continue
			}
			if f.storageObligations == nil {
				f.storageObligations = make(map[string]StorageObligation)
			}
			f.storageObligations[nodeID] = StorageObligation{NodeID: nodeID, OpenedUnixNano: stamp}
		}
	}
	// Prune idle reporters by log time, never wall time, so replicas agree.
	if stamp > 0 {
		cutoff := stamp - int64(obligationIdleReportTTL)
		for id, r := range f.obligationReports {
			if len(r.Owed) == 0 && r.ReceivedUnixNano < cutoff {
				delete(f.obligationReports, id)
			}
		}
	}
}

// obligationReport returns the FSM's current report for one owner.
func (f *placementFSM) obligationReport(reporter string) (StorageObligationReport, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	r, ok := f.obligationReports[reporter]
	return r, ok
}

// storageObligationViews builds the operator view. expectedReporters are the
// live members that can own sandboxes (every one of them reports, even with
// nothing owed); one that has no fresh report makes every job incomplete.
func (f *placementFSM) storageObligationViews(expectedReporters []string, now time.Time) []StorageObligationView {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.storageObligations) == 0 {
		return nil
	}
	fresh := func(r StorageObligationReport) bool {
		return r.ReceivedUnixNano > 0 && now.Sub(time.Unix(0, r.ReceivedUnixNano)) <= obligationStaleAfter
	}
	var stale []StorageObligationReporter
	for _, id := range expectedReporters {
		r, ok := f.obligationReports[id]
		if ok && fresh(r) {
			continue
		}
		entry := StorageObligationReporter{NodeID: id, Stale: true}
		if ok {
			entry.ReportedAt = time.Unix(0, r.ReceivedUnixNano).UTC()
		}
		stale = append(stale, entry)
	}
	holders := make(map[string]int, len(f.storageObligations))
	for _, p := range f.placements {
		for _, r := range p.SecretRecipients {
			if _, open := f.storageObligations[r]; open {
				holders[r]++
			}
		}
	}
	views := make([]StorageObligationView, 0, len(f.storageObligations))
	for nodeID, job := range f.storageObligations {
		v := StorageObligationView{NodeID: nodeID, Holders: holders[nodeID]}
		if job.OpenedUnixNano > 0 {
			v.OpenedAt = time.Unix(0, job.OpenedUnixNano).UTC()
		}
		staleForJob := append([]StorageObligationReporter(nil), stale...)
		for id, r := range f.obligationReports {
			owed := r.Owed[nodeID]
			if owed <= 0 {
				continue
			}
			isFresh := fresh(r)
			entry := StorageObligationReporter{NodeID: id, Owed: owed, ReportedAt: time.Unix(0, r.ReceivedUnixNano).UTC(), Stale: !isFresh}
			v.Reporters = append(v.Reporters, entry)
			v.PendingDeletes += owed
			if !isFresh && !containsReporter(staleForJob, id) {
				// A reporter that owes this node and has gone silent — dead
				// or partitioned — keeps its last count AND is flagged.
				staleForJob = append(staleForJob, entry)
			}
		}
		sort.Slice(v.Reporters, func(i, j int) bool { return v.Reporters[i].NodeID < v.Reporters[j].NodeID })
		sort.Slice(staleForJob, func(i, j int) bool { return staleForJob[i].NodeID < staleForJob[j].NodeID })
		v.StaleReporters = staleForJob
		v.Complete = len(staleForJob) == 0
		v.ReadyForAttestation = v.Complete && v.Holders == 0 && v.PendingDeletes == 0
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].NodeID < views[j].NodeID })
	return views
}

func containsReporter(list []StorageObligationReporter, id string) bool {
	for _, r := range list {
		if r.NodeID == id {
			return true
		}
	}
	return false
}

// --- Leader batcher ---

// obligationBatcher gathers owner reports on the leader and folds them into
// one raft entry per window. Reports are idempotent snapshots, so anything
// lost to a leader change is simply re-sent on the owner's next tick.
type obligationBatcher struct {
	mu      sync.Mutex
	pending map[string]StorageObligationReport
}

func (b *obligationBatcher) add(reports []StorageObligationReport) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pending == nil {
		b.pending = make(map[string]StorageObligationReport)
	}
	for _, r := range reports {
		id := strings.TrimSpace(r.Reporter)
		if id == "" {
			continue
		}
		// Keep only the newest per reporter: a burst of retries folds to one.
		if prev, ok := b.pending[id]; ok && prev.Seq >= r.Seq {
			continue
		}
		r.Reporter = id
		b.pending[id] = r
	}
}

func (b *obligationBatcher) take() []StorageObligationReport {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.pending) == 0 {
		return nil
	}
	out := make([]StorageObligationReport, 0, len(b.pending))
	for _, r := range b.pending {
		out = append(out, r)
	}
	b.pending = nil
	sort.Slice(out, func(i, j int) bool { return out[i].Reporter < out[j].Reporter })
	return out
}

// worthApplying drops a report the FSM already reflects and refreshed
// recently. Without it every owner's 5-minute heartbeat of an unchanged
// report would still be a raft write; with it, only changes and genuinely
// due refreshes reach the log.
func worthApplying(r StorageObligationReport, current StorageObligationReport, have bool, now time.Time) bool {
	if !have {
		return true
	}
	if r.Seq <= current.Seq {
		return false
	}
	if !owedEqual(r.Owed, current.Owed) {
		return true
	}
	return now.Sub(time.Unix(0, current.ReceivedUnixNano)) >= obligationReportRefresh-obligationReportInterval
}

// isRawObligationReport is a report proposed by an owner, which the leader
// batches. The folded batch the leader itself applies carries a stamp.
func isRawObligationReport(cmd command) bool {
	return cmd.Op == opReportStorageObligations && cmd.StampUnixNano == 0
}

// flushObligationReports folds the pending reports into one entry. Runs on
// the leader only.
func (c *Cluster) flushObligationReports(ctx context.Context, now time.Time) error {
	reports := c.obligations.take()
	if len(reports) == 0 {
		return nil
	}
	keep := reports[:0]
	for _, r := range reports {
		current, have := c.fsm.obligationReport(r.Reporter)
		if worthApplying(r, current, have, now) {
			keep = append(keep, r)
		}
	}
	if len(keep) == 0 {
		return nil
	}
	payload, err := encodeCommand(command{Op: opReportStorageObligations, ObligationReports: keep, StampUnixNano: now.UnixNano()})
	if err != nil {
		return err
	}
	return c.applyEncodedLocal(ctx, payload)
}

func (c *Cluster) startObligationBatcher() {
	ctx, cancel := context.WithCancel(context.Background())
	c.obligationBatcherStop = cancel
	go func() {
		t := time.NewTicker(obligationBatchWindow)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				if c.raft == nil || c.raft.raft.State() != raft.Leader {
					// Followers never apply; drop anything queued before a
					// leadership loss. Owners re-send on their next tick.
					c.obligations.take()
					continue
				}
				if err := c.flushObligationReports(ctx, now); err != nil && c.logger != nil {
					c.logger.Warn("cluster: storage obligation batch apply failed; owners re-send on their next tick", "err", err)
				}
			}
		}
	}()
}

// ReportStorageObligations submits one owner report. On the leader it is
// queued for the next batch; elsewhere it is forwarded to the leader, which
// queues it there.
func (c *Cluster) ReportStorageObligations(ctx context.Context, report StorageObligationReport) error {
	report.Owed = normalizeOwed(report.Owed)
	return c.applyCommand(ctx, command{Op: opReportStorageObligations, ObligationReports: []StorageObligationReport{report}})
}

// StorageObligations serves the job view from the local FSM. The expected
// reporters are the members gossip reports alive that can own sandboxes.
func (c *Cluster) StorageObligations(context.Context) ([]StorageObligationView, error) {
	if c == nil || c.fsm == nil {
		return nil, nil
	}
	var expected []string
	if c.gossip != nil {
		for _, m := range c.gossip.members() {
			if m.Alive && m.NodeID != "" && CanOwnSandboxRole(m.Role) {
				expected = append(expected, m.NodeID)
			}
		}
	}
	sort.Strings(expected)
	return c.fsm.storageObligationViews(expected, time.Now()), nil
}

// ReportStorageObligations submits one owner report through the control plane.
func (a *Agent) ReportStorageObligations(ctx context.Context, report StorageObligationReport) error {
	report.Owed = normalizeOwed(report.Owed)
	return a.applyCommand(ctx, command{Op: opReportStorageObligations, ObligationReports: []StorageObligationReport{report}})
}

// StorageObligations asks one control-plane server for the view.
func (a *Agent) StorageObligations(ctx context.Context) ([]StorageObligationView, error) {
	var resp StorageObligationsResponse
	if err := a.doControlPlaneJSON(ctx, http.MethodGet, PublicInternalStorageObligationsPath, PublicInternalStorageObligationsPath, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Obligations, nil
}

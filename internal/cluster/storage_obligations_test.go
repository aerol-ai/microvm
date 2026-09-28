package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

func applyObligationCmd(t *testing.T, f *placementFSM, cmd command) {
	t.Helper()
	payload, err := encodeCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if res := f.Apply(&raft.Log{Data: payload}); res != nil {
		if err, ok := res.(error); ok && err != nil {
			t.Fatalf("apply op %v: %v", cmd.Op, err)
		}
	}
}

// placeHolding places a sandbox whose secret recipient set includes holders.
func placeHolding(t *testing.T, f *placementFSM, id string, holders ...string) {
	t.Helper()
	applyObligationCmd(t, f, command{
		Op: opPlace, SandboxID: id, OwnerNodeID: holders[0], IncarnationID: "inc-" + id,
		Spec:             &models.CreateSandboxRequest{Image: "alpine"},
		SecretRecipients: holders,
	})
}

func drain(t *testing.T, f *placementFSM, node string, drained bool, stamp int64) {
	t.Helper()
	applyObligationCmd(t, f, command{Op: opSetNodeDrainState, NodeID: node, Drained: drained, StampUnixNano: stamp})
}

func report(t *testing.T, f *placementFSM, stamp int64, reports ...StorageObligationReport) {
	t.Helper()
	applyObligationCmd(t, f, command{Op: opReportStorageObligations, ObligationReports: reports, StampUnixNano: stamp})
}

func jobs(f *placementFSM) map[string]StorageObligation {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[string]StorageObligation, len(f.storageObligations))
	for k, v := range f.storageObligations {
		out[k] = v
	}
	return out
}

// The drain is the job's trigger, and only for a node that owes a wipe.
func TestDrainOpensAnObligationOnlyForAHolder(t *testing.T) {
	f := newPlacementFSM()
	placeHolding(t, f, "sb-1", "owner-a", "worker-x", "worker-y")

	drain(t, f, "worker-x", true, 1000)
	drain(t, f, "worker-z", true, 1000) // holds nothing, owed nothing
	got := jobs(f)
	if j, ok := got["worker-x"]; !ok || j.OpenedUnixNano != 1000 {
		t.Fatalf("draining a holder opened %+v, want a job stamped 1000", got)
	}
	if _, ok := got["worker-z"]; ok {
		t.Fatal("draining a node that holds nothing opened a job")
	}
	// Idempotent: a repeated drain keeps the original opening time.
	drain(t, f, "worker-x", true, 2000)
	if jobs(f)["worker-x"].OpenedUnixNano != 1000 {
		t.Fatal("a repeated drain reset the job")
	}
	// Uncordon: the node is staying, nothing to wipe.
	drain(t, f, "worker-x", false, 3000)
	if _, ok := jobs(f)["worker-x"]; ok {
		t.Fatal("uncordon left the job open")
	}
}

// An attestation discharges the job; the attestation stays as the proof.
func TestAttestationClosesTheJobAndStaysListed(t *testing.T) {
	f := newPlacementFSM()
	placeHolding(t, f, "sb-1", "owner-a", "worker-x")
	drain(t, f, "worker-x", true, 1000)
	applyObligationCmd(t, f, command{Op: opRetireNodeStorage, NodeID: "worker-x",
		StorageRetirement: &NodeStorageRetirement{NodeID: "worker-x", AttestedUnixNano: 5000, Reason: "wiped"}})
	if _, ok := jobs(f)["worker-x"]; ok {
		t.Fatal("attestation left the job open")
	}
	found := false
	for _, r := range f.nodeStorageRetirementsSnapshot() {
		found = found || r.NodeID == "worker-x"
	}
	if !found {
		t.Fatal("the attestation is not listed after discharging the job")
	}
}

// Reports REPLACE by Seq. A retry (same Seq) and an out-of-order older report
// change nothing; only a newer one does. This is the no-double-count rule.
func TestObligationReportsReplaceBySeq(t *testing.T) {
	f := newPlacementFSM()
	report(t, f, 100, StorageObligationReport{Reporter: "owner-a", Seq: 5, Owed: map[string]int{"worker-x": 3}})
	report(t, f, 200, StorageObligationReport{Reporter: "owner-a", Seq: 5, Owed: map[string]int{"worker-x": 3}})
	report(t, f, 300, StorageObligationReport{Reporter: "owner-a", Seq: 4, Owed: map[string]int{"worker-x": 9}})
	got, _ := f.obligationReport("owner-a")
	if got.Owed["worker-x"] != 3 || got.ReceivedUnixNano != 100 {
		t.Fatalf("retry/older report changed state: %+v", got)
	}
	report(t, f, 400, StorageObligationReport{Reporter: "owner-a", Seq: 6, Owed: map[string]int{"worker-x": 1, "worker-y": 0, "": 4}})
	got, _ = f.obligationReport("owner-a")
	if len(got.Owed) != 1 || got.Owed["worker-x"] != 1 || got.ReceivedUnixNano != 400 {
		t.Fatalf("newer report did not replace (and normalize): %+v", got)
	}
	// Blank reporters are ignored.
	report(t, f, 500, StorageObligationReport{Reporter: " ", Seq: 9, Owed: map[string]int{"worker-x": 1}})
	if _, ok := f.obligationReport(""); ok {
		t.Fatal("a blank reporter was stored")
	}
}

// A debt created after the drain (the reseal the drain triggered) still opens
// the job, even though the node no longer appears in any recipient set.
func TestReportOfADebtToADrainedNodeOpensTheJob(t *testing.T) {
	f := newPlacementFSM()
	drain(t, f, "worker-x", true, 1000) // held nothing at drain time
	if len(jobs(f)) != 0 {
		t.Fatal("unexpected job")
	}
	report(t, f, 2000, StorageObligationReport{Reporter: "owner-a", Seq: 1, Owed: map[string]int{"worker-x": 2, "worker-live": 1}})
	got := jobs(f)
	if j, ok := got["worker-x"]; !ok || j.OpenedUnixNano != 2000 {
		t.Fatalf("a debt to a drained node opened %+v", got)
	}
	if _, ok := got["worker-live"]; ok {
		t.Fatal("a debt to a node that is not drained opened a job")
	}
	// And draining a node already owed opens its job at drain time.
	drain(t, f, "worker-live", true, 3000)
	if jobs(f)["worker-live"].OpenedUnixNano != 3000 {
		t.Fatal("draining a node owed by a report did not open a job")
	}
}

// Idle reporters age out by LOG time; a reporter that still owes never does.
func TestIdleObligationReportsAgeOutByLogTime(t *testing.T) {
	f := newPlacementFSM()
	day := int64(obligationIdleReportTTL)
	report(t, f, 1, StorageObligationReport{Reporter: "idle", Seq: 1})
	report(t, f, 1, StorageObligationReport{Reporter: "owing", Seq: 1, Owed: map[string]int{"worker-x": 1}})
	report(t, f, 1+day+1, StorageObligationReport{Reporter: "fresh", Seq: 1})
	if _, ok := f.obligationReport("idle"); ok {
		t.Fatal("an idle reporter older than the TTL was kept")
	}
	if _, ok := f.obligationReport("owing"); !ok {
		t.Fatal("a reporter that still owes was pruned — the silent disk must stay visible")
	}
}

func TestStorageObligationsSurviveSnapshotRestore(t *testing.T) {
	src := newPlacementFSM()
	placeHolding(t, src, "sb-1", "owner-a", "worker-x")
	drain(t, src, "worker-x", true, 1000)
	report(t, src, 2000, StorageObligationReport{Reporter: "owner-a", Seq: 7, Owed: map[string]int{"worker-x": 2}})
	snap, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	dst := newPlacementFSMWithRecoveryStore(src.recoveryStore)
	if err := dst.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatal(err)
	}
	if jobs(dst)["worker-x"].OpenedUnixNano != 1000 {
		t.Fatal("the job was lost across snapshot/restore")
	}
	r, ok := dst.obligationReport("owner-a")
	if !ok || r.Seq != 7 || r.Owed["worker-x"] != 2 {
		t.Fatalf("the report was lost across snapshot/restore: %+v", r)
	}
	// The restored replica still rejects a stale retry.
	report(t, dst, 3000, StorageObligationReport{Reporter: "owner-a", Seq: 7, Owed: map[string]int{"worker-x": 9}})
	if r, _ := dst.obligationReport("owner-a"); r.Owed["worker-x"] != 2 {
		t.Fatal("a restored replica accepted a retried report")
	}
}

// The view: holders from the FSM, pending from reports, and staleness that
// makes the job incomplete instead of all-clear.
func TestStorageObligationViews(t *testing.T) {
	now := time.Unix(0, 10*int64(time.Hour))
	freshStamp := now.Add(-time.Minute).UnixNano()
	staleStamp := now.Add(-obligationStaleAfter - time.Minute).UnixNano()
	f := newPlacementFSM()
	if f.storageObligationViews(nil, now) != nil {
		t.Fatal("no jobs must mean no views")
	}
	placeHolding(t, f, "sb-1", "owner-a", "worker-x")
	placeHolding(t, f, "sb-2", "owner-b", "worker-x")
	drain(t, f, "worker-x", true, 1000)
	report(t, f, freshStamp, StorageObligationReport{Reporter: "owner-a", Seq: 1, Owed: map[string]int{"worker-x": 2}})
	report(t, f, staleStamp, StorageObligationReport{Reporter: "owner-gone", Seq: 1, Owed: map[string]int{"worker-x": 5}})
	report(t, f, freshStamp, StorageObligationReport{Reporter: "owner-b", Seq: 1})

	// owner-c is expected (alive, can own sandboxes) but never reported.
	views := f.storageObligationViews([]string{"owner-a", "owner-b", "owner-c"}, now)
	if len(views) != 1 {
		t.Fatalf("views = %+v", views)
	}
	v := views[0]
	if v.Holders != 2 {
		t.Fatalf("holders = %d, want 2 (two placements still list worker-x)", v.Holders)
	}
	if v.PendingDeletes != 7 {
		t.Fatalf("pending = %d, want 7 (fresh 2 + stale 5 — a silent owner keeps its last count)", v.PendingDeletes)
	}
	if v.Complete || v.ReadyForAttestation {
		t.Fatalf("a stale/absent reporter must make the job incomplete: %+v", v)
	}
	stale := map[string]bool{}
	for _, r := range v.StaleReporters {
		stale[r.NodeID] = r.Stale
	}
	if !stale["owner-c"] || !stale["owner-gone"] || len(stale) != 2 {
		t.Fatalf("stale reporters = %+v, want owner-c (never reported) and owner-gone (silent, still owing)", v.StaleReporters)
	}
	if v.OpenedAt.IsZero() {
		t.Fatal("opened_at missing")
	}

	// Everything moved and everyone fresh: ready for attestation (still open).
	f2 := newPlacementFSM()
	drain(t, f2, "worker-x", true, 1000)
	report(t, f2, freshStamp, StorageObligationReport{Reporter: "owner-a", Seq: 1, Owed: map[string]int{"worker-x": 1}})
	report(t, f2, freshStamp+1, StorageObligationReport{Reporter: "owner-a", Seq: 2})
	v2 := f2.storageObligationViews([]string{"owner-a"}, now)[0]
	if !v2.Complete || !v2.ReadyForAttestation || v2.PendingDeletes != 0 || v2.Holders != 0 {
		t.Fatalf("a fully cleared job = %+v, want complete and ready (and still listed)", v2)
	}
}

func TestObligationBatcherFoldsAndDedupes(t *testing.T) {
	var b obligationBatcher
	if b.take() != nil {
		t.Fatal("empty batcher returned reports")
	}
	b.add([]StorageObligationReport{
		{Reporter: "owner-a", Seq: 2},
		{Reporter: "owner-a", Seq: 1}, // older retry
		{Reporter: " ", Seq: 9},
		{Reporter: "owner-b", Seq: 1},
	})
	b.add([]StorageObligationReport{{Reporter: "owner-a", Seq: 3}})
	got := b.take()
	if len(got) != 2 || got[0].Reporter != "owner-a" || got[0].Seq != 3 || got[1].Reporter != "owner-b" {
		t.Fatalf("batch = %+v, want the newest owner-a and owner-b", got)
	}
	if b.take() != nil {
		t.Fatal("take did not clear")
	}
}

func TestWorthApplying(t *testing.T) {
	now := time.Unix(0, int64(time.Hour))
	cur := StorageObligationReport{Reporter: "a", Seq: 5, Owed: map[string]int{"x": 1}, ReceivedUnixNano: now.Add(-time.Minute).UnixNano()}
	for _, tc := range []struct {
		name string
		r    StorageObligationReport
		have bool
		want bool
	}{
		{"first report", StorageObligationReport{Seq: 1}, false, true},
		{"retry of what the FSM has", StorageObligationReport{Seq: 5, Owed: map[string]int{"x": 1}}, true, false},
		{"changed counts", StorageObligationReport{Seq: 6, Owed: map[string]int{"x": 2}}, true, true},
		{"unchanged heartbeat too soon", StorageObligationReport{Seq: 6, Owed: map[string]int{"x": 1}}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := worthApplying(tc.r, cur, tc.have, now); got != tc.want {
				t.Fatalf("worthApplying = %v, want %v", got, tc.want)
			}
		})
	}
	old := cur
	old.ReceivedUnixNano = now.Add(-obligationReportRefresh).UnixNano()
	if !worthApplying(StorageObligationReport{Seq: 6, Owed: map[string]int{"x": 1}}, old, true, now) {
		t.Fatal("an unchanged heartbeat that is due was dropped; the owner would go stale while healthy")
	}
}

func TestIsRawObligationReport(t *testing.T) {
	if !isRawObligationReport(command{Op: opReportStorageObligations}) {
		t.Fatal("an owner's report must be batched")
	}
	if isRawObligationReport(command{Op: opReportStorageObligations, StampUnixNano: 1}) {
		t.Fatal("the leader's folded batch must be applied, not re-queued")
	}
	if isRawObligationReport(command{Op: opPlace}) {
		t.Fatal("other ops are not reports")
	}
	if normalizeOwed(map[string]int{"x": 0}) != nil || owedEqual(map[string]int{"x": 1}, map[string]int{"x": 2}) {
		t.Fatal("normalize/equal mishandle zero or differing counts")
	}
}

// End to end on a real single-node cluster: a report submitted through the
// normal apply path is queued, folded by the batcher into one entry, shows in
// the view, and a retry does not change it.
func TestClusterFoldsReportsIntoTheView(t *testing.T) {
	c, cleanup := newTestCluster(t, "node1", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	if err := c.SetNodeDrainState(ctx, "worker-x", true); err != nil {
		t.Fatal(err)
	}
	r := StorageObligationReport{Reporter: "node1", Seq: 1, Owed: map[string]int{"worker-x": 3}}
	if err := c.ReportStorageObligations(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := c.ReportStorageObligations(ctx, r); err != nil { // retry
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the batched report to reach the FSM", func() bool {
		got, ok := c.fsm.obligationReport("node1")
		return ok && got.Owed["worker-x"] == 3
	})
	views, err := c.StorageObligations(ctx)
	if err != nil || len(views) != 1 || views[0].NodeID != "worker-x" || views[0].PendingDeletes != 3 {
		t.Fatalf("view = %+v %v", views, err)
	}
	if !views[0].Complete {
		t.Fatalf("the only expected reporter (node1) reported; job should be complete: %+v", views[0])
	}
	if (*Cluster)(nil) != nil {
		t.Fatal("unreachable")
	}
	if v, _ := (*Cluster)(nil).StorageObligations(ctx); v != nil {
		t.Fatal("nil cluster must report nothing")
	}
}

// An agent (ingress/worker) has no FSM: it reads the view from ONE server and
// submits its report through the ordinary apply path.
func TestAgentStorageObligations(t *testing.T) {
	var applied []command
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case PublicInternalStorageObligationsPath:
			_ = json.NewEncoder(w).Encode(StorageObligationsResponse{Obligations: []StorageObligationView{{NodeID: "worker-x", PendingDeletes: 2}}})
		case PublicInternalApplyPath, InternalAPIPath:
			body, _ := io.ReadAll(r.Body)
			cmd, err := decodeCommand(body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			applied = append(applied, cmd)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	views, err := agent.StorageObligations(context.Background())
	if err != nil || len(views) != 1 || views[0].PendingDeletes != 2 {
		t.Fatalf("agent view = %+v %v", views, err)
	}
	if err := agent.ReportStorageObligations(context.Background(), StorageObligationReport{Reporter: "worker-self", Seq: 3, Owed: map[string]int{"worker-x": 1, "zero": 0}}); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0].Op != opReportStorageObligations || applied[0].StampUnixNano != 0 ||
		len(applied[0].ObligationReports) != 1 || len(applied[0].ObligationReports[0].Owed) != 1 {
		t.Fatalf("agent report reached the control plane as %+v", applied)
	}
}

// A delete ACK clears the owner's outbox row, so its next report owes
// nothing — and the operator-visible job must STAY open. An ACK of the
// current copies is not proof the disk holds no older ciphertext; only an
// attestation (or an uncordon) closes it.
func TestAckedDeletesDoNotCloseTheJob(t *testing.T) {
	f := newPlacementFSM()
	placeHolding(t, f, "sb-1", "owner-a", "worker-x")
	drain(t, f, "worker-x", true, 1000)
	report(t, f, 2000, StorageObligationReport{Reporter: "owner-a", Seq: 1, Owed: map[string]int{"worker-x": 1}})
	// The peer ACKed the delete: the owner's outbox row is gone, so its next
	// report owes worker-x nothing.
	report(t, f, 3000, StorageObligationReport{Reporter: "owner-a", Seq: 2})
	if _, open := jobs(f)["worker-x"]; !open {
		t.Fatal("ACKed deletes closed the job; only an attestation may")
	}
}

func TestAgentStorageObligationsSurfacesAFailedRead(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusServiceUnavailable)
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
	if _, err := agent.StorageObligations(context.Background()); err == nil {
		t.Fatal("a failed control-plane read returned no error; the view would render as all-clear")
	}
	if !containsReporter([]StorageObligationReporter{{NodeID: "a"}}, "a") || containsReporter(nil, "a") {
		t.Fatal("containsReporter")
	}
}

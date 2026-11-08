package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// Regression tests for per-team quotas (plan item P2): replicated quota
// records, a usage index derived from placement rows, and leader admission
// that is exact under concurrent creates on one node and across nodes.

func teamSpec(cpu float64, mem int) *models.CreateSandboxRequest {
	return &models.CreateSandboxRequest{Image: "alpine", CPU: cpu, MemoryMB: mem}
}

func reserveCmd(id, owner string, spec *models.CreateSandboxRequest) command {
	return command{Op: opReserve, SandboxID: id, OwnerNodeID: "w1", IncarnationID: "inc-" + id, OwnerRef: owner,
		Spec: spec, ExpiresUnix: time.Now().Add(time.Minute).Unix()}
}

func usageOf(f *placementFSM, team string) models.TeamQuotaUsage {
	_, u, _ := f.teamQuota(team)
	return u
}

func TestFSMTeamQuotaPutDeleteIdempotent(t *testing.T) {
	f := newPlacementFSM()
	put := command{Op: opPutTeamQuota, StampUnixNano: 10, TeamQuota: &TeamQuotaRecord{Team: "risk", MaxSandboxes: 2}}
	res, ok := applyOp(t, f, put).(teamQuotaApplyResult)
	if !ok || !res.Changed || res.Quota.Generation != 1 || res.Quota.CreatedUnixNano != 10 {
		t.Fatalf("first put = %+v", res)
	}
	put.StampUnixNano = 20
	if res = applyOp(t, f, put).(teamQuotaApplyResult); res.Changed || res.Quota.Generation != 1 {
		t.Fatalf("the same quota twice must be a no-op: %+v", res)
	}
	put.TeamQuota = &TeamQuotaRecord{Team: "risk", MaxSandboxes: 3}
	if res = applyOp(t, f, put).(teamQuotaApplyResult); !res.Changed || res.Quota.Generation != 2 || res.Quota.CreatedUnixNano != 10 || res.Quota.UpdatedUnixNano != 20 {
		t.Fatalf("change = %+v", res)
	}
	for range 2 {
		if got := applyOp(t, f, command{Op: opDeleteTeamQuota, TeamQuota: &TeamQuotaRecord{Team: "risk"}}); got != nil {
			t.Fatalf("delete = %v (a repeated delete must succeed)", got)
		}
	}
	if _, _, found := f.teamQuota("risk"); found {
		t.Fatal("quota survived delete")
	}
	for _, bad := range []command{{Op: opPutTeamQuota}, {Op: opDeleteTeamQuota}, {Op: opPutTeamQuota, TeamQuota: &TeamQuotaRecord{}}} {
		if got := applyOp(t, f, bad); got == nil {
			t.Fatalf("%v without a team was accepted", bad.Op)
		}
	}
}

// Usage is derived from the rows: reserve counts, a promote does not count
// twice, a resize changes the size, a delete gives it back, and only team
// owners are counted.
func TestFSMTeamUsageFollowsPlacementRows(t *testing.T) {
	f := newPlacementFSM()
	applyOp(t, f, reserveCmd("sb-1", "team:risk", teamSpec(1, 512)))
	applyOp(t, f, reserveCmd("sb-2", "team:risk", teamSpec(0, 0))) // server defaults
	applyOp(t, f, reserveCmd("sb-op", "", teamSpec(4, 4096)))      // operator: never counted
	applyOp(t, f, reserveCmd("sb-acct", "acct-x", teamSpec(4, 4096)))
	want := models.TeamQuotaUsage{Sandboxes: 2, CPU: 1 + models.DefaultCPU, MemoryMB: 512 + models.DefaultMemoryMB}
	if got := usageOf(f, "risk"); got != want {
		t.Fatalf("after reserve = %+v, want %+v", got, want)
	}
	// The promote carries the same spec: still two sandboxes.
	if got := applyOp(t, f, command{Op: opPlace, SandboxID: "sb-1", OwnerNodeID: "w1", OwnerRef: "team:risk",
		ExpectedIncarnationID: "inc-sb-1", IncarnationID: "inc-sb-1", Spec: teamSpec(1, 512)}); got != nil {
		t.Fatalf("promote: %v", got)
	}
	if got := usageOf(f, "risk"); got != want {
		t.Fatalf("after promote = %+v, want %+v (no double count)", got, want)
	}
	// The hot row carries the mirror; an operator's row does not pay for it.
	if p := f.placements["sb-1"]; p.QuotaCPU != 1 || p.QuotaMemoryMB != 512 {
		t.Fatalf("hot mirror = %v/%v", p.QuotaCPU, p.QuotaMemoryMB)
	}
	if p := f.placements["sb-op"]; p.QuotaCPU != 0 || p.QuotaMemoryMB != 0 {
		t.Fatalf("an operator row carries a quota mirror: %+v", p)
	}
	// A resize through the spec.
	if got := applyOp(t, f, command{Op: opUpsertSpec, SandboxID: "sb-1", ExpectedIncarnationID: "inc-sb-1", Spec: teamSpec(2, 1024)}); got != nil {
		t.Fatalf("upsert spec: %v", got)
	}
	want = models.TeamQuotaUsage{Sandboxes: 2, CPU: 2 + models.DefaultCPU, MemoryMB: 1024 + models.DefaultMemoryMB}
	if got := usageOf(f, "risk"); got != want {
		t.Fatalf("after resize = %+v, want %+v", got, want)
	}
	if got := applyOp(t, f, command{Op: opCancelReserve, SandboxID: "sb-2", ExpectedIncarnationID: "inc-sb-2"}); got != nil {
		t.Fatalf("cancel: %v", got)
	}
	if got := applyOp(t, f, command{Op: opDelete, SandboxID: "sb-1", ExpectedIncarnationID: "inc-sb-1"}); got != nil {
		t.Fatalf("delete: %v", got)
	}
	if got := usageOf(f, "risk"); got != (models.TeamQuotaUsage{}) {
		t.Fatalf("after delete = %+v, want zero", got)
	}
	if got := usageOf(f, "x"); got != (models.TeamQuotaUsage{}) {
		t.Fatalf("a non-team owner was counted: %+v", got)
	}
}

// A dead owner's reservations are dropped by opOrphanOwner: their share goes
// with them, or a team would lose a slot to every node that died mid-create.
func TestFSMTeamUsageDropsOrphanedReservations(t *testing.T) {
	f := newPlacementFSM()
	applyOp(t, f, reserveCmd("sb-1", "team:risk", teamSpec(1, 512)))
	if got := applyOp(t, f, command{Op: opOrphanOwner, NodeID: "w1"}); got != nil {
		t.Fatalf("orphan owner: %v", got)
	}
	if got := usageOf(f, "risk"); got != (models.TeamQuotaUsage{}) {
		t.Fatalf("after orphan of reservations = %+v", got)
	}
}

// Snapshot and restore carry the quotas and rebuild usage from the rows,
// including a legacy row written before quotas (no mirror: default size).
func TestFSMTeamQuotaSnapshotRestore(t *testing.T) {
	f := newPlacementFSM()
	applyOp(t, f, command{Op: opPutTeamQuota, StampUnixNano: 1, TeamQuota: &TeamQuotaRecord{Team: "risk", MaxSandboxes: 5, MaxCPU: 8}})
	applyOp(t, f, reserveCmd("sb-1", "team:risk", teamSpec(2, 2048)))
	f.mu.Lock()
	legacy := f.placements["sb-1"]
	legacy.SandboxID = "sb-legacy"
	legacy.QuotaCPU, legacy.QuotaMemoryMB, legacy.RecoveryRef = 0, 0, ""
	f.placements["sb-legacy"] = legacy
	f.mu.Unlock()

	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := snap.Persist(&bufferSink{buf: &buf}); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(bytes.NewReader(buf.Bytes()))); err != nil {
		t.Fatal(err)
	}
	rec, usage, found := restored.teamQuota("risk")
	if !found || rec.MaxSandboxes != 5 || rec.MaxCPU != 8 {
		t.Fatalf("restored quota = %+v found=%v", rec, found)
	}
	want := models.TeamQuotaUsage{Sandboxes: 2, CPU: 2 + models.DefaultCPU, MemoryMB: 2048 + models.DefaultMemoryMB}
	if usage != want {
		t.Fatalf("restored usage = %+v, want %+v", usage, want)
	}
}

// The admission answer: count, CPU and memory each enforced; a promote or a
// retried reservation never counts twice; a batch counts its own earlier
// members; shrinking is always allowed; no quota means no limit.
func TestFSMAdmitTeamQuotas(t *testing.T) {
	f := newPlacementFSM()
	applyOp(t, f, command{Op: opPutTeamQuota, TeamQuota: &TeamQuotaRecord{Team: "risk", MaxSandboxes: 2, MaxCPU: 3, MaxMemoryMB: 3072}})
	applyOp(t, f, reserveCmd("sb-1", "team:risk", teamSpec(1, 1024)))

	cases := []struct {
		name    string
		cmd     command
		wantErr string
	}{
		{name: "fits", cmd: reserveCmd("sb-2", "team:risk", teamSpec(1, 1024))},
		{name: "cpu over", cmd: reserveCmd("sb-2", "team:risk", teamSpec(3, 512)), wantErr: "CPU"},
		{name: "memory over", cmd: reserveCmd("sb-2", "team:risk", teamSpec(1, 4096)), wantErr: "memory"},
		{name: "retry of a counted reservation", cmd: reserveCmd("sb-1", "team:risk", teamSpec(1, 1024))},
		{name: "batch over the count", cmd: command{Op: opReserveBatch, Reservations: []reservationCommand{
			{SandboxID: "sb-a", OwnerRef: "team:risk", Spec: teamSpec(0.5, 256)},
			{SandboxID: "sb-b", OwnerRef: "team:risk", Spec: teamSpec(0.5, 256)},
		}}, wantErr: "sandboxes"},
		{name: "other team has no quota", cmd: reserveCmd("sb-o", "team:other", teamSpec(64, 65536))},
		{name: "operator is never limited", cmd: reserveCmd("sb-op", "", teamSpec(64, 65536))},
		{name: "unmarked promote is not admitted", cmd: command{Op: opPlace, SandboxID: "sb-new", OwnerRef: "team:risk", Spec: teamSpec(64, 65536)}},
		{name: "marked promote of a new sandbox is", cmd: command{Op: opPlace, SandboxID: "sb-new", OwnerRef: "team:risk", Spec: teamSpec(64, 65536), QuotaAdmit: true}, wantErr: "CPU"},
		{name: "marked resize that grows", cmd: command{Op: opUpsertSpec, SandboxID: "sb-1", Spec: teamSpec(4, 1024), QuotaAdmit: true}, wantErr: "CPU"},
		{name: "marked resize that shrinks", cmd: command{Op: opUpsertSpec, SandboxID: "sb-1", Spec: teamSpec(0.5, 512), QuotaAdmit: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := f.admitTeamQuotas(teamQuotaAsks(tc.cmd))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("admit = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrTeamQuotaExceeded) || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), `"risk"`) {
				t.Fatalf("admit = %v, want a refusal naming %q and the team", err, tc.wantErr)
			}
		})
	}
	// A team pushed over a lowered quota may still shrink.
	applyOp(t, f, command{Op: opPutTeamQuota, TeamQuota: &TeamQuotaRecord{Team: "risk", MaxCPU: 0.25}})
	if err := f.admitTeamQuotas(teamQuotaAsks(command{Op: opUpsertSpec, SandboxID: "sb-1", Spec: teamSpec(0.5, 1024), QuotaAdmit: true})); err != nil {
		t.Fatalf("shrinking while over a lowered quota = %v", err)
	}
	if !f.anyTeamQuotaFor(teamQuotaAsks(command{Op: opUpsertSpec, SandboxID: "sb-1", Spec: teamSpec(1, 1), QuotaAdmit: true})) {
		t.Fatal("a spec change must find its team from the row it changes")
	}
	if f.anyTeamQuotaFor(teamQuotaAsks(reserveCmd("sb-z", "team:other", teamSpec(1, 1)))) {
		t.Fatal("a team without a quota must not pay for the barrier")
	}
}

func TestQuotaAdmitMarking(t *testing.T) {
	ctx := WithTeamQuotaAdmission(context.Background())
	for op, want := range map[opCode]bool{opPlace: true, opUpsertSpec: true, opReserve: false, opDelete: false} {
		if got := markQuotaAdmit(ctx, command{Op: op}).QuotaAdmit; got != want {
			t.Fatalf("op %v marked = %v, want %v", op, got, want)
		}
	}
	if markQuotaAdmit(context.Background(), command{Op: opPlace}).QuotaAdmit {
		t.Fatal("an unmarked context must not mark")
	}
	if !needsTeamQuotaAdmission(command{Op: opPlace, QuotaAdmit: true}) || needsTeamQuotaAdmission(command{Op: opReserve, QuotaAdmit: true}) {
		t.Fatal("needsTeamQuotaAdmission")
	}
	b, _ := json.Marshal(command{Op: opPlace})
	if strings.Contains(string(b), "quota_admit") || strings.Contains(string(b), "team_quota") || strings.Contains(string(b), "quota_replay") {
		t.Fatalf("an unmarked command grew quota fields on the wire: %s", b)
	}
}

func TestTeamQuotaApplyVerdictSurvivesForwarding(t *testing.T) {
	err := fmt.Errorf("cluster: fsm apply: %w", models.CheckTeamQuota("risk", models.TeamQuotaRequest{MaxSandboxes: 1}, models.TeamQuotaUsage{Sandboxes: 1}, models.TeamQuotaUsage{Sandboxes: 1}))
	if ApplyErrorStatus(err) != http.StatusTooManyRequests || ApplyErrorRetryAfterSeconds(err) != 0 {
		t.Fatalf("status = %d retry = %d", ApplyErrorStatus(err), ApplyErrorRetryAfterSeconds(err))
	}
	back := forwardApplyStatus(http.StatusTooManyRequests, err.Error())
	if !errors.Is(back, ErrTeamQuotaExceeded) || errors.Is(back, ErrCreateBackpressure) {
		t.Fatalf("forwarded = %v, want the quota sentinel, never backpressure", back)
	}
	if bp := forwardApplyStatus(http.StatusTooManyRequests, "worker busy"); !errors.Is(bp, ErrCreateBackpressure) {
		t.Fatalf("plain 429 = %v, want backpressure as before", bp)
	}
	if out := TeamQuotaWriteOutcome(ErrClusterVersion); out.Code != teamQuotaCodeClusterVersion || !errors.Is(out.err(), ErrClusterVersion) {
		t.Fatalf("outcome = %+v", out)
	}
	if TeamQuotaWriteOutcome(errors.New("x")).Code != "" || (TeamQuotaWriteResponse{}).err() != nil {
		t.Fatal("unknown errors carry no code")
	}
	if (TeamQuotaWriteResponse{Code: "weird", Message: "m"}).err() == nil {
		t.Fatal("an unknown code must still be an error")
	}
}

// The race the plan names, on one leader: N concurrent creates for a team
// with fewer free slots than N. Every reservation is decided under the
// leader's admission queue against usage that includes the ones before it,
// so exactly the free slots are granted.
func TestTeamQuotaConcurrentReservationsOnOneLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newTestCluster(t, "quota-one", true, nil)
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	giveFreshCapacity(leader)
	ctx := context.Background()
	if _, err := leader.WriteTeamQuota(ctx, TeamQuotaWriteRequest{Quota: TeamQuotaRecord{Team: "risk", MaxSandboxes: 3}}); err != nil {
		t.Fatalf("WriteTeamQuota: %v", err)
	}
	target := PlacementTarget{NodeID: leader.nodeID, APIURL: leader.apiURL}
	granted, refused := raceReservations(t, ctx, []*Cluster{leader}, target, 12)
	if granted != 3 || refused != 9 {
		t.Fatalf("granted %d refused %d, want exactly 3 and 9", granted, refused)
	}
	if u := usageOf(leader.fsm, "risk"); u.Sandboxes != 3 {
		t.Fatalf("usage = %+v, want 3 sandboxes", u)
	}
	leader.reservationAdmissionMu.Lock()
	barrierTerm := leader.admission.term
	leader.reservationAdmissionMu.Unlock()
	if barrierTerm == 0 {
		t.Fatal("the leader admitted without its per-term barrier")
	}
	// The read path agrees.
	resp, err := leader.ReadTeamQuota(ctx, TeamQuotaReadRequest{Team: "risk"})
	if err != nil || !resp.Found || resp.Usage.Sandboxes != 3 || !resp.Authoritative {
		t.Fatalf("read = %+v %v", resp, err)
	}
}

// The same race across two nodes: half the creates enter on a follower,
// which forwards each reservation to the leader. The leader's queue is the
// single serialization point, so the follower's creates cannot slip past.
func TestTeamQuotaConcurrentReservationsAcrossNodes(t *testing.T) {
	if testing.Short() {
		t.Skip("starts two raft nodes")
	}
	leader, cleanupLeader := newTestCluster(t, "quota-ldr", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)
	follower, cleanupFollower := newTestCluster(t, "quota-fol", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)
	// Every write below goes through the follower first; until its Raft has
	// heard from the leader it answers ErrNotLeader (CI flake, 2026-11-07).
	waitForFollowerToReachLeader(t, follower, leader.nodeID, 20*time.Second)
	giveFreshCapacity(leader)
	giveFreshCapacity(follower)
	ctx := context.Background()
	// The v1 internal endpoint, as the daemon attaches it: a follower's
	// quota write goes one hop to the leader through it.
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+PublicInternalTeamQuotaWritePath, func(w http.ResponseWriter, r *http.Request) {
		var req TeamQuotaWriteRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp, err := leader.WriteTeamQuota(r.Context(), req)
		if err != nil {
			_ = json.NewEncoder(w).Encode(TeamQuotaWriteOutcome(err))
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	leader.AttachInternalHandler(mux)
	// Written on the follower: it forwards one hop to the leader.
	if _, err := follower.WriteTeamQuota(ctx, TeamQuotaWriteRequest{Quota: TeamQuotaRecord{Team: "risk", MaxSandboxes: 4}}); err != nil {
		t.Fatalf("WriteTeamQuota via follower: %v", err)
	}
	target := PlacementTarget{NodeID: leader.nodeID, APIURL: leader.apiURL}
	granted, refused := raceReservations(t, ctx, []*Cluster{leader, follower}, target, 16)
	if granted != 4 || refused != 12 {
		t.Fatalf("granted %d refused %d, want exactly 4 and 12", granted, refused)
	}
	deadline := time.Now().Add(5 * time.Second)
	for usageOf(follower.fsm, "risk").Sandboxes != 4 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if u := usageOf(follower.fsm, "risk"); u.Sandboxes != 4 {
		t.Fatalf("follower's derived usage = %+v, want the same 4 the leader admitted", u)
	}
	// A spec write that grows a sandbox past the quota is refused through
	// the follower too, and one that shrinks is not.
	if err := leader.WriteTeamQuotaLimits(ctx, "risk", 4, 2.5); err != nil {
		t.Fatal(err)
	}
	id := firstTeamSandbox(leader.fsm)
	grow := WithTeamQuotaAdmission(ctx)
	if err := follower.UpsertSpec(grow, id, teamSpec(8, 256), PlacementSecrets{}); !errors.Is(err, ErrTeamQuotaExceeded) {
		t.Fatalf("growing resize via follower = %v, want ErrTeamQuotaExceeded", err)
	}
	if err := follower.UpsertSpec(grow, id, teamSpec(0.25, 256), PlacementSecrets{}); err != nil {
		t.Fatalf("shrinking resize via follower = %v", err)
	}
}

// WriteTeamQuotaLimits is a test shorthand for a put with CPU.
func (c *Cluster) WriteTeamQuotaLimits(ctx context.Context, team string, sandboxes int, cpu float64) error {
	_, err := c.WriteTeamQuota(ctx, TeamQuotaWriteRequest{Quota: TeamQuotaRecord{Team: team, MaxSandboxes: sandboxes, MaxCPU: cpu}})
	return err
}

func firstTeamSandbox(f *placementFSM) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for id := range f.teamUsageEntries {
		return id
	}
	return ""
}

// raceReservations starts n creates at once, spread over nodes, and counts
// how many the leader granted and how many the quota refused. Any other
// error fails the test: the race must be decided by the quota alone.
func raceReservations(t *testing.T, ctx context.Context, nodes []*Cluster, target PlacementTarget, n int) (granted, refused int) {
	t.Helper()
	var ok, no atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			node := nodes[i%len(nodes)]
			err := node.ReserveOnTarget(ctx, fmt.Sprintf("sb-race-%02d", i), target, teamSpec(0.25, 128),
				PlacementSecrets{OwnerRef: "team:risk"}, time.Minute)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrTeamQuotaExceeded):
				no.Add(1)
			default:
				errs <- err
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("unexpected reservation error: %v", err)
	}
	return int(ok.Load()), int(no.Load())
}

// The rolling-upgrade gate: a quota is written only once every Raft server
// reports the op set, so no replica ever skips one.
func TestWriteTeamQuotaRefusedDuringRollingUpgrade(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newTestCluster(t, "quota-gate", true, nil)
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	if err := leader.raft.raft.AddNonvoter("old-server", raft.ServerAddress("127.0.0.1:1"), 0, time.Second).Error(); err != nil {
		t.Fatalf("add old server: %v", err)
	}
	leader.gossip.memberIndex.upsert(Member{NodeID: "old-server", Alive: true, Role: config.NodeRoleServer, FSMOpsVersion: teamQuotaFSMOpsVersion - 1})
	_, err := leader.WriteTeamQuota(context.Background(), TeamQuotaWriteRequest{Quota: TeamQuotaRecord{Team: "risk", MaxSandboxes: 1}})
	if !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("write with an old server = %v, want ErrClusterVersion", err)
	}
}

func TestTeamQuotaClusterWithoutRaft(t *testing.T) {
	var c *Cluster
	if _, err := c.WriteTeamQuota(context.Background(), TeamQuotaWriteRequest{}); err == nil {
		t.Fatal("nil cluster write")
	}
	if _, err := c.ReadTeamQuota(context.Background(), TeamQuotaReadRequest{}); err == nil {
		t.Fatal("nil cluster read")
	}
	if err := c.admitTeamQuotaCommand(command{}); err != nil {
		t.Fatalf("nil cluster admit = %v", err)
	}
	if err := (&Cluster{}).admissionBarrier(); err != nil {
		t.Fatalf("barrier without raft = %v", err)
	}
}

func TestAgentTeamQuotaReadWriteAndCache(t *testing.T) {
	var reads, writes atomic.Int32
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case PublicInternalTeamQuotaReadPath:
			reads.Add(1)
			var req TeamQuotaReadRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Team == "broken" {
				_ = json.NewEncoder(w).Encode(TeamQuotaReadResponse{})
				return true
			}
			_ = json.NewEncoder(w).Encode(TeamQuotaReadResponse{Found: true, Authoritative: true,
				Quota: TeamQuotaRecord{Team: req.Team, MaxSandboxes: 2}, Usage: models.TeamQuotaUsage{Sandboxes: 1}})
			return true
		case PublicInternalTeamQuotaWritePath:
			writes.Add(1)
			var req TeamQuotaWriteRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Quota.Team == "old" {
				_ = json.NewEncoder(w).Encode(TeamQuotaWriteOutcome(ErrClusterVersion))
				return true
			}
			_ = json.NewEncoder(w).Encode(TeamQuotaWriteResponse{Quota: req.Quota, Changed: true})
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
	ctx := context.Background()
	for range 3 {
		resp, err := agent.ReadTeamQuota(ctx, TeamQuotaReadRequest{Team: "risk"})
		if err != nil || !resp.Found || resp.Quota.MaxSandboxes != 2 {
			t.Fatalf("read = %+v %v", resp, err)
		}
	}
	if reads.Load() != 1 {
		t.Fatalf("control-plane reads = %d, want 1 (cached)", reads.Load())
	}
	if _, err := agent.WriteTeamQuota(ctx, TeamQuotaWriteRequest{Quota: TeamQuotaRecord{Team: "risk", MaxSandboxes: 3}}); err != nil {
		t.Fatalf("write = %v", err)
	}
	if _, err := agent.ReadTeamQuota(ctx, TeamQuotaReadRequest{Team: "risk"}); err != nil || reads.Load() != 2 {
		t.Fatalf("a write must drop the cached read: reads=%d err=%v", reads.Load(), err)
	}
	if _, err := agent.WriteTeamQuota(ctx, TeamQuotaWriteRequest{Quota: TeamQuotaRecord{Team: "old"}}); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("write during upgrade = %v, want ErrClusterVersion", err)
	}
	if _, err := agent.ReadTeamQuota(ctx, TeamQuotaReadRequest{Team: "broken"}); err == nil {
		t.Fatal("a non-authoritative read must be an error")
	}
	var nilAgent *Agent
	if _, err := nilAgent.ReadTeamQuota(ctx, TeamQuotaReadRequest{}); err == nil {
		t.Fatal("nil agent read")
	}
	if _, err := nilAgent.WriteTeamQuota(ctx, TeamQuotaWriteRequest{}); err == nil {
		t.Fatal("nil agent write")
	}
}

// A team at its quota answered over the agent's control-plane hop keeps its
// sentinel, so an agent-routed create answers 429 team_quota_exceeded, not
// "backpressure".
func TestAgentControlPlaneCarriesTeamQuotaRefusal(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && (r.URL.Path == PublicInternalApplyPath || r.URL.Path == InternalAPIPath) {
			http.Error(w, "cluster: fsm apply: "+ErrTeamQuotaExceeded.Error()+`: team "risk" holds 2 of its 2 sandboxes`, http.StatusTooManyRequests)
			return
		}
		http.NotFound(w, r)
	}))
	err := agent.ReserveOnTarget(context.Background(), "sb-x", PlacementTarget{NodeID: "node2"}, teamSpec(1, 1),
		PlacementSecrets{IncarnationID: "inc", OwnerRef: "team:risk"}, time.Minute)
	if !errors.Is(err, ErrTeamQuotaExceeded) {
		t.Fatalf("ReserveOnTarget over control plane = %v, want ErrTeamQuotaExceeded", err)
	}
}

func TestTeamQuotaCacheExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	c := &teamQuotaCache{now: func() time.Time { return now }}
	calls := 0
	fetch := func(context.Context, TeamQuotaReadRequest) (TeamQuotaReadResponse, error) {
		calls++
		return TeamQuotaReadResponse{Found: true}, nil
	}
	_, _ = c.read(context.Background(), TeamQuotaReadRequest{Team: "t"}, fetch)
	_, _ = c.read(context.Background(), TeamQuotaReadRequest{Team: "t"}, fetch)
	now = now.Add(teamQuotaCacheTTL)
	_, _ = c.read(context.Background(), TeamQuotaReadRequest{Team: "t"}, fetch)
	if calls != 2 {
		t.Fatalf("fetches = %d, want 2", calls)
	}
	if _, err := c.read(context.Background(), TeamQuotaReadRequest{Team: "u"}, func(context.Context, TeamQuotaReadRequest) (TeamQuotaReadResponse, error) {
		return TeamQuotaReadResponse{}, errors.New("down")
	}); err == nil {
		t.Fatal("a failed fetch must be an error")
	}
	if (&teamQuotaCache{}).clock().IsZero() {
		t.Fatal("default clock")
	}
}

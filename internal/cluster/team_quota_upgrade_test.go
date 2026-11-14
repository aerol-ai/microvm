package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Regression tests for team quotas across a rolling upgrade (review of PR
// #959, finding 5). A worker on a build before quotas resizes with a spec
// write that carries no QuotaAdmit mark, and an upgraded leader used to skip
// admission for it. Now the leader checks every spec write that grows a
// team's sandbox, whatever its sender says, and a quota is set only once
// every live member runs a build that enforces it.

// The reviewer's reproducer: main's worker sends opUpsertSpec with no
// QuotaAdmit field, growing a sandbox from 1 to 8 CPU against a quota of 2.
func TestReview923LegacyWorkerResizeMustNotBypassQuota(t *testing.T) {
	f := newPlacementFSM()
	applyOp(t, f, command{Op: opPutTeamQuota, TeamQuota: &TeamQuotaRecord{Team: "risk", MaxCPU: 2}})
	applyOp(t, f, reserveCmd("sb-old-worker", "team:risk", teamSpec(1, 512)))
	// main's worker sends opUpsertSpec with no QuotaAdmit field.
	cmd := command{Op: opUpsertSpec, SandboxID: "sb-old-worker", Spec: teamSpec(8, 512)}
	c := &Cluster{fsm: f}
	if err := c.admitTeamQuotaCommand(cmd); !errors.Is(err, ErrTeamQuotaExceeded) {
		t.Fatalf("quota-enabled leader admitted legacy-worker resize to 8 CPU against quota 2: %v", err)
	}
}

// Every spec write is checked from the leader's own rows; only growth can be
// refused, and only a boot backfill is exempt. A promote stays opt-in: an
// unmarked one is a boot replay of a sandbox the team already holds.
func TestTeamQuotaSpecWritesAreCheckedWithoutAMark(t *testing.T) {
	f := newPlacementFSM()
	applyOp(t, f, command{Op: opPutTeamQuota, TeamQuota: &TeamQuotaRecord{Team: "risk", MaxCPU: 2}})
	applyOp(t, f, reserveCmd("sb-1", "team:risk", teamSpec(1, 512)))
	applyOp(t, f, reserveCmd("sb-free", "team:other", teamSpec(1, 512)))
	c := &Cluster{fsm: f}
	cases := []struct {
		name      string
		cmd       command
		refused   bool
		admission bool // takes the leader's admission queue
	}{
		{name: "unmarked growth that fits", cmd: command{Op: opUpsertSpec, SandboxID: "sb-1", Spec: teamSpec(2, 512)}, admission: true},
		{name: "unmarked growth past the quota", cmd: command{Op: opUpsertSpec, SandboxID: "sb-1", Spec: teamSpec(3, 512)}, refused: true, admission: true},
		{name: "marked growth past the quota", cmd: command{Op: opUpsertSpec, SandboxID: "sb-1", Spec: teamSpec(3, 512), QuotaAdmit: true}, refused: true, admission: true},
		{name: "same size (a lifecycle write-through)", cmd: command{Op: opUpsertSpec, SandboxID: "sb-1", Spec: teamSpec(1, 512)}, admission: true},
		{name: "shrink", cmd: command{Op: opUpsertSpec, SandboxID: "sb-1", Spec: teamSpec(0.5, 256)}, admission: true},
		{name: "boot backfill", cmd: command{Op: opUpsertSpec, SandboxID: "sb-1", Spec: teamSpec(64, 512), QuotaReplay: true}},
		{name: "secrets-only spec write", cmd: command{Op: opUpsertSpec, SandboxID: "sb-1"}},
		{name: "team with no quota", cmd: command{Op: opUpsertSpec, SandboxID: "sb-free", Spec: teamSpec(64, 512)}},
		{name: "unmarked promote (boot replay)", cmd: command{Op: opPlace, SandboxID: "sb-new", OwnerRef: "team:risk", Spec: teamSpec(64, 512)}},
		{name: "marked promote", cmd: command{Op: opPlace, SandboxID: "sb-new", OwnerRef: "team:risk", Spec: teamSpec(64, 512), QuotaAdmit: true}, refused: true, admission: true},
		{name: "reservation (its own queue)", cmd: reserveCmd("sb-r", "team:risk", teamSpec(64, 512)), refused: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.admitTeamQuotaCommand(tc.cmd)
			if tc.refused != errors.Is(err, ErrTeamQuotaExceeded) || (!tc.refused && err != nil) {
				t.Fatalf("admit = %v, want refused %v", err, tc.refused)
			}
			if got := c.takesTeamQuotaAdmission(tc.cmd); got != tc.admission {
				t.Fatalf("takesTeamQuotaAdmission = %v, want %v", got, tc.admission)
			}
		})
	}
	if (&Cluster{}).takesTeamQuotaAdmission(command{Op: opUpsertSpec, SandboxID: "sb-1", Spec: teamSpec(9, 1)}) {
		t.Fatal("a node with no FSM has no admission to take")
	}
	replay := withTeamQuotaReplay(context.Background())
	if !markQuotaAdmit(replay, command{Op: opUpsertSpec}).QuotaReplay || markQuotaAdmit(replay, command{Op: opPlace}).QuotaReplay {
		t.Fatal("the replay mark applies to spec writes only")
	}
	if markQuotaAdmit(context.Background(), command{Op: opUpsertSpec}).QuotaReplay {
		t.Fatal("an unmarked context must not mark a replay")
	}
	// Apply ignores both marks: a replica on any build reads the same state.
	g := newPlacementFSM()
	applyOp(t, g, reserveCmd("sb-1", "team:risk", teamSpec(1, 512)))
	applyOp(t, g, command{Op: opUpsertSpec, SandboxID: "sb-1", ExpectedIncarnationID: "inc-sb-1", IncarnationID: "inc-sb-1", Spec: teamSpec(4, 512), QuotaReplay: true, QuotaAdmit: true})
	h := newPlacementFSM()
	applyOp(t, h, reserveCmd("sb-1", "team:risk", teamSpec(1, 512)))
	applyOp(t, h, command{Op: opUpsertSpec, SandboxID: "sb-1", ExpectedIncarnationID: "inc-sb-1", IncarnationID: "inc-sb-1", Spec: teamSpec(4, 512)})
	if usageOf(g, "risk") != usageOf(h, "risk") || usageOf(g, "risk").CPU != 4 {
		t.Fatalf("marked %+v vs unmarked %+v: apply must not read the marks", usageOf(g, "risk"), usageOf(h, "risk"))
	}
}

// A quota is set only once every live member, any role, runs a build that
// enforces it; a delete only loosens and needs the Raft gate alone.
func TestTeamQuotaPutWaitsForEveryLiveMember(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newTestCluster(t, "quota-live-gate", true, nil)
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	ctx := context.Background()
	put := TeamQuotaWriteRequest{Quota: TeamQuotaRecord{Team: "risk", MaxCPU: 2}}
	steps := []struct {
		name   string
		member Member
		wantOK bool
	}{
		{"a worker on the build before quotas", Member{NodeID: "wrk-old", Alive: true, Role: config.NodeRoleWorker, FSMOpsVersion: teamQuotaFSMOpsVersion - 1}, false},
		{"it upgrades", Member{NodeID: "wrk-old", Alive: true, Role: config.NodeRoleWorker, FSMOpsVersion: fsmOpsVersion}, true},
		{"an ingress node on the build before", Member{NodeID: "ing-old", Alive: true, Role: config.NodeRoleIngress, FSMOpsVersion: teamQuotaFSMOpsVersion - 1}, false},
		{"it dies", Member{NodeID: "ing-old", Alive: false, Role: config.NodeRoleIngress, FSMOpsVersion: teamQuotaFSMOpsVersion - 1}, true},
	}
	for _, step := range steps {
		leader.gossip.memberIndex.upsert(step.member)
		_, err := leader.WriteTeamQuota(ctx, put)
		if step.wantOK != (err == nil) || (err != nil && !errors.Is(err, ErrClusterVersion)) {
			t.Fatalf("%s: put = %v, want ok %v (or ErrClusterVersion)", step.name, err, step.wantOK)
		}
	}
	leader.gossip.memberIndex.upsert(Member{NodeID: "wrk-old", Alive: true, Role: config.NodeRoleWorker, FSMOpsVersion: teamQuotaFSMOpsVersion - 1})
	if _, err := leader.WriteTeamQuota(ctx, TeamQuotaWriteRequest{Delete: true, Quota: TeamQuotaRecord{Team: "risk"}}); err != nil {
		t.Fatalf("delete with an old worker live = %v, want it allowed", err)
	}
	if resp, err := leader.ReadTeamQuota(ctx, TeamQuotaReadRequest{Team: "risk"}); err != nil || resp.Found {
		t.Fatalf("after delete = %+v %v", resp, err)
	}
}

// End to end on a real leader: a spec write with no mark (a worker on the
// build before quotas) is refused when it grows a team past its quota, one
// that keeps the size passes, and the boot backfill of a spec the row never
// had is never refused.
func TestTeamQuotaUnmarkedSpecWritesThroughTheLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	c, cleanup := newTestCluster(t, "quota-unmarked", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	if _, err := c.WriteTeamQuota(ctx, TeamQuotaWriteRequest{Quota: TeamQuotaRecord{Team: "risk", MaxCPU: 2}}); err != nil {
		t.Fatal(err)
	}
	seed := reserveCmd("sb-1", "team:risk", teamSpec(1, 512))
	seed.OwnerNodeID = c.nodeID
	payload, _ := encodeCommand(seed)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("seed reservation: %v", err)
	}
	if err := c.UpsertSpec(ctx, "sb-1", teamSpec(8, 512), PlacementSecrets{}); !errors.Is(err, ErrTeamQuotaExceeded) {
		t.Fatalf("unmarked growth past the quota = %v, want ErrTeamQuotaExceeded", err)
	}
	if err := c.UpsertSpec(ctx, "sb-1", teamSpec(1, 512), PlacementSecrets{}); err != nil {
		t.Fatalf("a write that keeps the size = %v", err)
	}
	if u := usageOf(c.fsm, "risk"); u.CPU != 1 {
		t.Fatalf("usage = %+v, want the refused growth left out", u)
	}

	// A spec-less row this node owns counts the default size; the boot
	// backfill records its real size even though that takes the team over.
	payload, _ = encodeCommand(command{Op: opPlace, SandboxID: "sb-legacy", OwnerNodeID: c.nodeID, OwnerRef: "team:risk", IncarnationID: "inc-legacy"})
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("seed spec-less placement: %v", err)
	}
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID: "sb-legacy", Spec: teamSpec(4, 512), Secrets: PlacementSecrets{IncarnationID: "inc-legacy", OwnerRef: "team:risk"},
	}}); err != nil {
		t.Fatalf("boot backfill over the quota = %v, want it recorded", err)
	}
	got, _ := c.fsm.get("sb-legacy")
	if got.Spec == nil || got.Spec.CPU != 4 || usageOf(c.fsm, "risk").CPU != 5 {
		t.Fatalf("backfill spec %+v usage %+v, want CPU 4 recorded and usage 5", got.Spec, usageOf(c.fsm, "risk"))
	}
}

// A worker's boot backfill carries the replay mark to the leader.
func TestAgentAssertOwnershipBackfillIsAQuotaReplay(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-nil-spec" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-nil-spec",
				Placement: Placement{SandboxID: "sb-nil-spec", OwnerNodeID: "worker-self", OwnerState: PlacementOwnerStateActive, IncarnationID: "inc-nil-spec"},
				Owner:     OwnerInfo{NodeID: "worker-self", IsSelf: true},
			})
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
	if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID: "sb-nil-spec", Spec: &models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 4}, Secrets: PlacementSecrets{IncarnationID: "inc-nil-spec"},
	}}); err != nil {
		t.Fatalf("AssertOwnership: %v", err)
	}
	for _, cmd := range capture.commandsSnapshot() {
		if cmd.Op == opUpsertSpec {
			if !cmd.QuotaReplay {
				t.Fatalf("backfill reached the leader unmarked: %+v", cmd)
			}
			return
		}
	}
	t.Fatalf("no backfill sent: %+v", capture.commandsSnapshot())
}

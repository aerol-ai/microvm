package cluster

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Node certificates get only what their role needs: on a live leader, a
// worker's proposals are bound to the worker itself (peer_proposals.go).

func workerApplyCtx(id string) context.Context {
	return ContextWithApplyPeer(context.Background(), id, roleCert(id, JoinRoleWorker))
}

// A worker places a sandbox only on itself. A placement it names another
// node as the owner of (here the leader, with a mount and a recreate
// policy that node's owner watcher would act on) is refused, and nothing
// is placed; its own placement goes through.
func TestWorkerPlacesOnlyOnItself(t *testing.T) {
	c, cleanup := newTestCluster(t, "lp-place", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	inc, err := MintIncarnationID()
	if err != nil {
		t.Fatal(err)
	}
	spec := &models.CreateSandboxRequest{
		Image:    "example.test/app:1",
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
		Mounts:   []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://bucket", Target: "/data"}},
	}
	other, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-other", OwnerNodeID: "lp-place", IncarnationID: inc,
		OwnerRef: "team:payments", Spec: spec})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), other); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("a worker's placement on another node = %v", err)
	}
	if _, placed := c.fsm.fullPlacementsForOwner("lp-place")["sb-other"]; placed {
		t.Fatal("a refused placement reached the FSM")
	}
	own, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-own", OwnerNodeID: "wkr-9", IncarnationID: inc,
		OwnerRef: "team:payments", Spec: &models.CreateSandboxRequest{Image: "alpine"}})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), own); err != nil {
		t.Fatalf("a worker's own placement: %v", err)
	}
}

// A worker cannot move another node's sandbox to itself: only a WASM
// sandbox (the WASM migration's import) is reassigned to the worker that
// sends it; a container sandbox stays where it is.
func TestWorkerReassignsOnlyAWasmSandboxToItself(t *testing.T) {
	c, cleanup := newTestCluster(t, "lp-own", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	server := ContextWithApplyPeer(context.Background(), "lp-own", roleCert("lp-own", ""))
	place := func(id, runtime string) string {
		inc, _ := MintIncarnationID()
		cmd, _ := encodeCommand(command{Op: opPlace, SandboxID: id, OwnerNodeID: "lp-own", IncarnationID: inc,
			OwnerRef: "team:payments", Spec: &models.CreateSandboxRequest{Image: "alpine", Runtime: runtime}})
		if err := c.ApplyEncoded(server, cmd); err != nil {
			t.Fatalf("server place %s: %v", id, err)
		}
		return inc
	}
	reassign := func(id, inc string) error {
		cmd, _ := encodeCommand(command{Op: opReassign, SandboxID: id, OwnerNodeID: "wkr-9",
			OwnerAPIURL: "https://wkr-9:21212", ExpectedIncarnationID: inc})
		return c.ApplyEncoded(workerApplyCtx("wkr-9"), cmd)
	}
	inc := place("sb-container", "docker")
	if err := reassign("sb-container", inc); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("a worker's reassign of a container sandbox to itself = %v", err)
	}
	if owner, err := c.OwnerOf("sb-container"); err != nil || owner.NodeID != "lp-own" {
		t.Fatalf("owner after a refused reassign = %+v %v", owner, err)
	}
	inc = place("sb-wasm", models.RuntimeWasm)
	if err := reassign("sb-wasm", inc); err != nil {
		t.Fatalf("the WASM migration's import reassign: %v", err)
	}
	if owner, err := c.OwnerOf("sb-wasm"); err != nil || owner.NodeID != "wkr-9" {
		t.Fatalf("owner after the import reassign = %+v %v", owner, err)
	}
}

// A worker writes only its own entries in the node-keyed indexes: a
// snapshot's home, a catalogue slice, an obligation report. Another
// node's are refused and stay as they were; its own go through.
func TestWorkerWritesOnlyItsOwnEntries(t *testing.T) {
	c, cleanup := newTestCluster(t, "lp-idx", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	w := workerApplyCtx("wkr-9")
	apply := func(cmd command) error {
		payload, _ := encodeCommand(cmd)
		return c.ApplyEncoded(w, payload)
	}
	if err := apply(command{Op: opRegisterSnapshotNode, SnapshotName: "team-a-base", NodeID: "wkr-9"}); err != nil {
		t.Fatalf("its own snapshot home: %v", err)
	}
	for name, cmd := range map[string]command{
		"another node's snapshot home": {Op: opRegisterSnapshotNode, SnapshotName: "team-b-base", NodeID: "lp-idx"},
		"another node's catalogue slice": {Op: opPublishArtifactCatalog, ArtifactKind: ArtifactKindTemplate, NodeID: "lp-idx",
			ArtifactEpoch: 1 << 40, ArtifactRevision: 1, ArtifactWithdraw: true},
		"another node's obligation report": {Op: opReportStorageObligations, StampUnixNano: time.Now().UnixNano(),
			ObligationReports: []StorageObligationReport{{Reporter: "lp-idx", Seq: math.MaxUint64, Owed: map[string]int{}}}},
		"another node's obligation report, unstamped": {Op: opReportStorageObligations,
			ObligationReports: []StorageObligationReport{{Reporter: "lp-idx", Seq: math.MaxUint64, Owed: map[string]int{}}}},
	} {
		if err := apply(cmd); !errors.Is(err, ErrPeerProposalRefused) {
			t.Errorf("%s = %v", name, err)
		}
	}
	if home, ok := c.fsm.snapshotHomeForProposal("team-b-base"); ok {
		t.Errorf("a refused snapshot home was written: %s", home)
	}
	if r, ok := c.fsm.obligationReport("lp-idx"); ok && r.Seq == math.MaxUint64 {
		t.Error("a refused obligation report was written")
	}
}

// Adopt never admits a server from gossip: a member that gossips server,
// mixed or nothing but that Raft does not count is not admitted, and a
// record that says server reads as no role while its node is not in Raft.
func TestAdoptNeverAdmitsAServerFromGossip(t *testing.T) {
	c, cleanup := newTestCluster(t, "lp-adopt", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	for _, gossiped := range []string{"", "mixed", "server"} {
		if role, why := c.adoptRole(Member{NodeID: "wkr-gossip", Role: gossiped}); role != "" || why == "" {
			t.Errorf("gossip role %q, not in Raft: adopted as %q", gossiped, role)
		}
	}
	if role, _ := c.adoptRole(Member{NodeID: "lp-adopt", Role: "server"}); role != JoinRoleServer {
		t.Errorf("a Raft server adopted as %q", role)
	}
	for gossiped, want := range map[string]string{"worker": JoinRoleWorker, "ingress": JoinRoleIngress} {
		if role, _ := c.adoptRole(Member{NodeID: "n-" + gossiped, Role: gossiped}); role != want {
			t.Errorf("gossip role %q adopted as %q", gossiped, role)
		}
	}
	if role, _ := (&Cluster{}).adoptRole(Member{NodeID: "x", Role: "server"}); role != "" {
		t.Errorf("a cluster with no Raft adopted a server: %q", role)
	}

	// What an adopt from before this change may have written: a record
	// that says server for a node Raft does not count.
	l := newJoinLog(t)
	l.apply(command{Op: opAdoptNodes, StampUnixNano: 100, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{
		{NodeID: "wkr-adopted", Role: JoinRoleServer, KeyHash: testKey("wkr-adopted")},
	}}})
	role := PeerRole(&Cluster{fsm: l.f}, "wkr-adopted", roleCert("wkr-adopted", ""))
	if access := controlplane.NodeAccess("wkr-adopted", role); access.Role == controlplane.RoleAdmin {
		t.Fatalf("a node not in Raft, admitted as a server, reads as %q (%q)", role, access.Role)
	}
}

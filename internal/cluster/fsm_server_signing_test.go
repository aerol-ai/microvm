package cluster

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Regression tests for the servers' signing record in the FSM (CLAUDE.md
// "Cluster mode is fragile"): written once, resealed under compare-and-set,
// carried by snapshots, never proposed by a worker.

func applySigning(t *testing.T, f *placementFSM, idx uint64, w *ServerSigningWrite) any {
	t.Helper()
	data, err := encodeCommand(command{Op: opPutServerSigning, ServerSigning: w})
	if err != nil {
		t.Fatal(err)
	}
	return f.Apply(&raft.Log{Index: idx, Data: data})
}

func TestFSMServerSigningWrittenOnceAndResealed(t *testing.T) {
	f := newPlacementFSM()
	if _, ok := f.serverSigningRecord(); ok {
		t.Fatal("a record before any write")
	}
	first := ServerSigning{Sealed: []byte("sealed-1"), SinceUnixNano: 100}
	if res, ok := applySigning(t, f, 1, &ServerSigningWrite{Signing: first}).(serverSigningApplyResult); !ok || !res.Changed {
		t.Fatalf("first write = %+v", res)
	}
	// A second first write (another leader's race) keeps the first.
	if res, ok := applySigning(t, f, 2, &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed-2"), SinceUnixNano: 200}}).(serverSigningApplyResult); !ok || res.Changed || string(res.Record.Sealed) != "sealed-1" {
		t.Fatalf("racing first write = %+v", res)
	}
	// A reseal names what it replaces and keeps Since.
	if err, _ := applySigning(t, f, 3, &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed-3"), SinceUnixNano: 100}, Expect: []byte("stale")}).(error); !errors.Is(err, ErrServerSigningConflict) {
		t.Fatalf("reseal of a stale record = %v", err)
	}
	if err, _ := applySigning(t, f, 4, &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed-3"), SinceUnixNano: 999}, Expect: []byte("sealed-1")}).(error); !errors.Is(err, ErrServerSigningConflict) {
		t.Fatalf("reseal that moves Since = %v", err)
	}
	if res, ok := applySigning(t, f, 5, &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed-3"), SinceUnixNano: 100}, Expect: []byte("sealed-1")}).(serverSigningApplyResult); !ok || !res.Changed {
		t.Fatalf("reseal = %+v", res)
	}
	if rec, _ := f.serverSigningRecord(); string(rec.Sealed) != "sealed-3" || rec.SinceUnixNano != 100 {
		t.Fatalf("record = %+v", rec)
	}
	for name, w := range map[string]*ServerSigningWrite{
		"no payload": nil,
		"no seed":    {Signing: ServerSigning{SinceUnixNano: 1}},
		"no since":   {Signing: ServerSigning{Sealed: []byte("x")}},
	} {
		if err, _ := applySigning(t, f, 6, w).(error); !errors.Is(err, ErrServerSigningInvalid) {
			t.Errorf("%s = %v", name, err)
		}
	}
	empty := newPlacementFSM()
	if err, _ := applySigning(t, empty, 1, &ServerSigningWrite{Signing: first, Expect: []byte("x")}).(error); !errors.Is(err, ErrServerSigningConflict) {
		t.Fatalf("reseal with no record = %v", err)
	}
}

func TestFSMServerSigningSnapshotRestore(t *testing.T) {
	f := newPlacementFSM()
	applySigning(t, f, 1, &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed"), SinceUnixNano: 7}})
	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	if rec, ok := restored.serverSigningRecord(); !ok || string(rec.Sealed) != "sealed" || rec.SinceUnixNano != 7 {
		t.Fatalf("restored = %+v %v", rec, ok)
	}
	restored.restoreServerSigningLocked(&ServerSigning{SinceUnixNano: 7})
	if _, ok := restored.serverSigningRecord(); ok {
		t.Fatal("a malformed record restored")
	}
	if newPlacementFSM().serverSigningSnapshotLocked() != nil {
		t.Fatal("a snapshot with no record carries one")
	}
}

// setActive writes the active version as the leader's reconcile (expect
// is the version it moves from; 0 is the first write) or a finalize
// (rollout set) would.
func setActive(t *testing.T, c *Cluster, idx uint64, fv, expect int, rollout string) {
	t.Helper()
	c.fsm.mu.Lock()
	defer c.fsm.mu.Unlock()
	if rollout != "" {
		c.fsm.activeVersion = &ActiveVersion{FV: fv, RolloutID: rollout, FromFV: expect, SetUnixNano: 1}
		c.fsm.publishActiveLocked()
		return
	}
	if _, err := c.fsm.applySetActiveVersionLocked(command{Op: opSetActiveVersion, StampUnixNano: 1, ActiveVersion: &ActiveVersionCommand{FV: fv, ExpectFV: expect}}); err != nil {
		t.Fatal(err)
	}
}

// The record is written once the active cluster version reaches the one
// servers sign from, whatever a member reports in gossip, except after the
// active version's first write, which counted only the servers: then every
// live member must report it too, or the operator starts it anyway. A
// cluster whose certificates name no role never writes it. Only the leader
// writes it; a worker cannot propose it.
func TestServerSigningGate(t *testing.T) {
	c, cleanup := newTestCluster(t, "ldr-signing", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	w := ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed"), SinceUnixNano: time.Now().Add(2 * time.Minute).UnixNano()}}
	member := func(id string, fv int) Member {
		m := recreateCandidate(id, "worker", 10)
		m.FSMOpsVersion = fv
		return m
	}
	self := c.gossip.selfMember()
	self.FSMOpsVersion, self.Alive = fsmOpsVersion, true
	seedGossipView(t, c, []Member{self, member("wkr-quiet", 0), member("wkr-new", serverSigningFSMOpsVersion)})

	// Certificates that name no role: never.
	setActive(t, c, 1, serverSigningFSMOpsVersion, 0, "r-1")
	if g := c.ServerSigningGate(true); g.Allowed || g.RolesInCertificates || !strings.Contains(g.Reason, "names no role") {
		t.Fatalf("role-less certificates: %+v", g)
	}
	c.selfCertRole = func() string { return JoinRoleServer }

	// Below the version, every server at it and no rollout (an upgrade
	// with install.sh): the members that hold the active version are
	// named, the gate is held, and the operator may start it.
	c.fsm.mu.Lock()
	c.fsm.activeVersion = nil
	c.fsm.publishActiveLocked()
	c.fsm.mu.Unlock()
	setActive(t, c, 2, serverSigningFSMOpsVersion-1, 0, "")
	if g := c.ServerSigningGate(false); g.Allowed || !g.ServersAtVersion || g.RolloutInFlight || !g.Held() ||
		!strings.Contains(g.Reason, "wkr-quiet") || !strings.Contains(g.Reason, "aerolvm upgrade signing start") {
		t.Fatalf("below the version, no rollout: %+v", g)
	}
	if !c.ServerSigningGate(true).Allowed {
		t.Fatal("the operator could not start it with every server at the version")
	}
	// A rollout under way: its finalize moves the version; not held.
	c.fsm.mu.Lock()
	c.fsm.rollout = &RolloutRecord{ID: "r-9", State: upgradewire.StateDone}
	c.fsm.mu.Unlock()
	if g := c.ServerSigningGate(false); g.Allowed || !g.RolloutInFlight || g.Held() || !strings.Contains(g.Reason, "aerolvm upgrade finalize") {
		t.Fatalf("below the version, a rollout under way: %+v", g)
	}
	c.fsm.mu.Lock()
	c.fsm.rollout = nil
	c.fsm.mu.Unlock()
	// A server below the version: never, forced or not.
	if err := c.raft.raft.AddNonvoter("srv-old", "127.0.0.1:1", 0, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	seedGossipView(t, c, []Member{self, member("wkr-quiet", 0), member("srv-old", serverSigningFSMOpsVersion-1)})
	if g := c.ServerSigningGate(true); g.Allowed || g.ServersAtVersion || g.Held() || !strings.Contains(g.Reason, "upgrade every server first") {
		t.Fatalf("a server below the version: %+v", g)
	}
	if _, err := c.WriteServerSigning(ctx, w, true); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("a forced write with a server below the version = %v", err)
	}
	if err := c.raft.raft.RemoveServer("srv-old", 0, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	seedGossipView(t, c, []Member{self, member("wkr-quiet", 0), member("wkr-new", serverSigningFSMOpsVersion)})

	// Moved there from a written version: gossip does not hold it.
	setActive(t, c, 3, serverSigningFSMOpsVersion, serverSigningFSMOpsVersion-1, "")
	if g := c.ServerSigningGate(false); !g.Allowed || g.FirstWrite || len(g.Waiting) != 1 || g.Waiting[0] != "wkr-quiet" {
		t.Fatalf("moved to the version: %+v", g)
	}
	if n := c.membersBelowActive(); n != 1 {
		t.Fatalf("members below the active version = %d, want the one that reports none", n)
	}

	// Its first write: every live member must report it, or the operator
	// starts it anyway.
	c.fsm.mu.Lock()
	c.fsm.activeVersion = nil
	c.fsm.publishActiveLocked()
	c.fsm.mu.Unlock()
	setActive(t, c, 4, serverSigningFSMOpsVersion, 0, "")
	g := c.ServerSigningGate(false)
	if g.Allowed || !g.FirstWrite || !strings.Contains(g.Reason, "wkr-quiet") || !strings.Contains(g.Reason, "aerolvm upgrade signing start") {
		t.Fatalf("first write with a quiet member: %+v", g)
	}
	if _, err := c.WriteServerSigning(ctx, w, false); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("write held by the first write = %v", err)
	}
	if !c.ServerSigningGate(true).Allowed {
		t.Fatal("the operator could not start it")
	}
	seedGossipView(t, c, []Member{self, member("wkr-new", serverSigningFSMOpsVersion)})
	if !c.ServerSigningAllowed() {
		t.Fatal("not allowed once every member reports the version")
	}
	seedGossipView(t, c, []Member{self, member("wkr-quiet", 0)})

	// A finalize: allowed.
	setActive(t, c, 5, serverSigningFSMOpsVersion, serverSigningFSMOpsVersion, "r-2")
	if !c.ServerSigningAllowed() {
		t.Fatal("not allowed after a finalize")
	}

	// Every other Raft server's certificate must name the server role too,
	// forced or not: part way through moving onto roles, a server whose
	// certificate names none could be all a node reaches.
	if err := c.raft.raft.AddNonvoter("srv-2", "127.0.0.1:1", 0, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	seedGossipView(t, c, []Member{self, member("wkr-quiet", 0), member("srv-2", fsmOpsVersion)})
	for _, tc := range []struct {
		role string
		err  error
		want string
	}{
		{"", nil, "srv-2's certificate names \"\""},
		{JoinRoleWorker, nil, "srv-2's certificate names \"worker\""},
		{"", errors.New("no answer"), "srv-2's certificate could not be read"},
	} {
		tc := tc
		c.peerCertRoleHook = func(m Member) (string, error) { return tc.role, tc.err }
		c.serverCertCheck.at = time.Time{}
		if g := c.ServerSigningGate(true); g.Allowed || g.RolesInCertificates || !strings.Contains(g.Reason, tc.want) {
			t.Fatalf("another server's certificate %q %v: %+v", tc.role, tc.err, g)
		}
		if _, err := c.WriteServerSigning(ctx, w, true); !errors.Is(err, ErrClusterVersion) {
			t.Fatalf("a write with another server's certificate %q = %v", tc.role, err)
		}
	}
	// The reading stands for a while; then a server that proves its role.
	reads := 0
	c.peerCertRoleHook = func(m Member) (string, error) { reads++; return JoinRoleServer, nil }
	if c.ServerSigningAllowed() {
		t.Fatal("a reading was not kept")
	}
	c.serverCertCheck.at = time.Now().Add(-2 * serverCertCheckEvery) // it has run out
	if !c.ServerSigningAllowed() || !c.ServerSigningAllowed() || reads != 1 {
		t.Fatalf("every server proves its role: allowed %v, %d readings", c.ServerSigningAllowed(), reads)
	}
	c.peerCertRoleHook = nil
	if err := c.raft.raft.RemoveServer("srv-2", 0, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	c.serverCertCheck.at = time.Time{}
	seedGossipView(t, c, []Member{self, member("wkr-quiet", 0)})
	rec, err := c.WriteServerSigning(ctx, w, false)
	if err != nil || string(rec.Sealed) != "sealed" {
		t.Fatalf("write = %+v %v", rec, err)
	}
	if got, ok := c.ServerSigningRecord(); !ok || string(got.Sealed) != "sealed" {
		t.Fatalf("record = %+v", got)
	}
	raw, _ := encodeCommand(command{Op: opPutServerSigning, ServerSigning: &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("mine"), SinceUnixNano: 1}, Expect: []byte("sealed")}})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), raw); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("a worker's write = %v", err)
	}
	var nilCluster *Cluster
	if _, ok := nilCluster.ServerSigningRecord(); ok || nilCluster.ServerSigningAllowed() {
		t.Fatal("a nil cluster has a record")
	}
}

// Once servers sign, only a server puts a cloud identity into a
// placement's spec or changes a placement's owner: those are what a server
// signs the sandbox's identity tokens from.
func TestIdentityStaysAsServersSetIt(t *testing.T) {
	idn := &models.IdentityRequest{RoleTag: "deploy"}
	st := fakeProposalState{signing: true, placements: map[string]Placement{
		"sb-id":    {SandboxID: "sb-id", OwnerNodeID: "wkr-1", OwnerRef: "team:a", Spec: &models.CreateSandboxRequest{Identity: idn}},
		"sb-plain": {SandboxID: "sb-plain", OwnerNodeID: "wkr-1", OwnerRef: "team:a", Spec: &models.CreateSandboxRequest{}},
	}}
	spec := func(i *models.IdentityRequest) *models.CreateSandboxRequest {
		return &models.CreateSandboxRequest{Image: "alpine", Identity: i}
	}
	for _, tc := range []struct {
		name string
		cmd  command
		want bool
	}{
		{"reserve with an identity", command{Op: opReserve, SandboxID: "sb-new", OwnerNodeID: "wkr-1", Spec: spec(idn)}, false},
		{"reserve with none", command{Op: opReserve, SandboxID: "sb-new", OwnerNodeID: "wkr-1", Spec: spec(nil)}, true},
		{"place a new sandbox with an identity", command{Op: opPlace, SandboxID: "sb-new", OwnerNodeID: "wkr-1", Spec: spec(idn)}, false},
		{"promote with the identity it has", command{Op: opPlace, SandboxID: "sb-id", OwnerNodeID: "wkr-1", Spec: spec(&models.IdentityRequest{RoleTag: "deploy", Audience: "sts.amazonaws.com"})}, true},
		{"promote with another identity", command{Op: opPlace, SandboxID: "sb-id", OwnerNodeID: "wkr-1", Spec: spec(&models.IdentityRequest{RoleTag: "admin"})}, false},
		{"add an identity to a plain sandbox", command{Op: opUpsertSpec, SandboxID: "sb-plain", Spec: spec(idn)}, false},
		{"drop the identity", command{Op: opUpsertSpec, SandboxID: "sb-id", Spec: spec(nil)}, true},
		{"place with another owner", command{Op: opPlace, SandboxID: "sb-id", OwnerNodeID: "wkr-1", OwnerRef: "team:b"}, false},
		{"place with the same owner", command{Op: opPlace, SandboxID: "sb-id", OwnerNodeID: "wkr-1", OwnerRef: "team:a"}, true},
	} {
		if got := peerMayPropose(JoinRoleWorker, "wkr-1", tc.cmd, st); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
		if !peerMayPropose(JoinRoleServer, "srv-1", tc.cmd, st) {
			t.Errorf("%s: a server may not", tc.name)
		}
	}
	// Before servers sign, nothing changes.
	st.signing = false
	if !peerMayPropose(JoinRoleWorker, "wkr-1", command{Op: opReserve, SandboxID: "sb-new", OwnerNodeID: "wkr-1", Spec: spec(idn)}, st) {
		t.Fatal("a reservation with an identity refused before servers sign")
	}
}

func applyFSMCommand(t *testing.T, f *placementFSM, idx uint64, cmd command) any {
	t.Helper()
	data, err := encodeCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
	return f.Apply(&raft.Log{Index: idx, Data: data})
}

// Since lies a short lead after the leader's clock on the write; a record
// that names any other time is refused.
func TestFSMServerSigningSinceNearTheLeadersClock(t *testing.T) {
	stamp := time.Unix(1_800_000_000, 0).UnixNano()
	for name, tc := range map[string]struct {
		since int64
		ok    bool
	}{
		"the leader's lead":       {stamp + int64(2*time.Minute), true},
		"its clock a little fast": {stamp - int64(30*time.Second), true},
		"well in the past":        {stamp - int64(2*time.Minute), false},
		"far in the future":       {stamp + int64(20*time.Minute), false},
	} {
		f := newPlacementFSM()
		res := applyFSMCommand(t, f, 1, command{Op: opPutServerSigning, StampUnixNano: stamp,
			ServerSigning: &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("s"), SinceUnixNano: tc.since}}})
		_, wrote := res.(serverSigningApplyResult)
		if err, _ := res.(error); wrote != tc.ok || (!tc.ok && !errors.Is(err, ErrServerSigningInvalid)) {
			t.Errorf("%s: %v", name, res)
		}
	}
}

// The end of old tokens is set once, from the leader's clock and never
// before Since; a reseal and a snapshot keep it.
func TestFSMEndOldTokens(t *testing.T) {
	f := newPlacementFSM()
	end := func(idx uint64, stamp int64) any {
		return applyFSMCommand(t, f, idx, command{Op: opPutServerSigning, StampUnixNano: stamp, ServerSigning: &ServerSigningWrite{EndOldTokens: true}})
	}
	if err, _ := end(1, 500).(error); !errors.Is(err, ErrServerSigningConflict) {
		t.Fatalf("an end before the record = %v", err)
	}
	applySigning(t, f, 2, &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed-1"), SinceUnixNano: 1000}})
	if err, _ := end(3, 0).(error); !errors.Is(err, ErrServerSigningInvalid) {
		t.Fatalf("an end with no clock = %v", err)
	}
	if res, ok := end(4, 500).(serverSigningApplyResult); !ok || !res.Changed || res.Record.OldTokensEndUnixNano != 1000 {
		t.Fatalf("an end before Since = %+v", res)
	}
	if res, ok := end(5, 9000).(serverSigningApplyResult); !ok || res.Changed || res.Record.OldTokensEndUnixNano != 1000 {
		t.Fatalf("a second end = %+v", res)
	}
	if res, ok := applySigning(t, f, 6, &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed-2"), SinceUnixNano: 1000}, Expect: []byte("sealed-1")}).(serverSigningApplyResult); !ok || res.Record.OldTokensEndUnixNano != 1000 {
		t.Fatalf("a reseal dropped the end: %+v", res)
	}
	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	g := newPlacementFSM()
	if err := g.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	if rec, ok := g.serverSigningRecord(); !ok || rec.OldTokensEndUnixNano != 1000 || string(rec.Sealed) != "sealed-2" {
		t.Fatalf("restored = %+v", rec)
	}
}

// Once servers sign, an owner that sends its sandbox's spec again without
// the cloud identity (an ownership replay, a spec write, an orphan claim)
// keeps the identity the placement has; before that version, the spec is
// taken as sent.
func TestFSMKeepsTheIdentityOnASpecSentAgain(t *testing.T) {
	inc := "inc-1"
	withIdentity := &models.CreateSandboxRequest{Image: "alpine", Identity: &models.IdentityRequest{RoleTag: "deploy"}}
	without := func() *models.CreateSandboxRequest { return &models.CreateSandboxRequest{Image: "alpine", CPU: 2} }
	identityOf := func(f *placementFSM) *models.IdentityRequest {
		p, _ := f.fullPlacementLocked("sb-1")
		if p.Spec == nil {
			return nil
		}
		return p.Spec.Identity
	}
	for _, active := range []int{serverSigningFSMOpsVersion, serverSigningFSMOpsVersion - 1} {
		f := newPlacementFSM()
		f.activeFV.Store(int64(active))
		keeps := active >= serverSigningFSMOpsVersion
		if err, _ := applyFSMCommand(t, f, 1, command{Op: opPlace, SandboxID: "sb-1", OwnerNodeID: "wkr-1", IncarnationID: inc, Spec: withIdentity}).(error); err != nil {
			t.Fatal(err)
		}
		steps := []command{
			{Op: opPlace, SandboxID: "sb-1", OwnerNodeID: "wkr-1", ExpectedIncarnationID: inc, Spec: without()},
			{Op: opUpsertSpec, SandboxID: "sb-1", ExpectedIncarnationID: inc, Spec: without()},
			{Op: opOrphanOwner, NodeID: "wkr-1"},
			{Op: opClaimOrphan, SandboxID: "sb-1", OwnerNodeID: "wkr-1", IncarnationID: inc, Spec: without()},
		}
		for i, cmd := range steps {
			if err, _ := applyFSMCommand(t, f, uint64(2+i), cmd).(error); err != nil {
				t.Fatalf("fv %d op %d: %v", active, cmd.Op, err)
			}
			if cmd.Op == opOrphanOwner {
				continue
			}
			got := identityOf(f)
			if keeps && (got == nil || got.RoleTag != "deploy") || !keeps && got != nil {
				t.Errorf("fv %d after op %d: identity %+v", active, cmd.Op, got)
			}
			if keeps {
				// Put it back for the next step below the version.
				continue
			}
			f.mu.Lock()
			p, _ := f.fullPlacementLocked("sb-1")
			spec := *withIdentity
			p.Spec = &spec
			_ = f.storePlacementLocked("sb-1", p)
			f.mu.Unlock()
		}
		// The command's own spec is never changed.
		if without().Identity != nil || steps[0].Spec.Identity != nil {
			t.Fatal("a command's spec was changed")
		}
	}
}

// The gauges say whether servers sign, whether the gate holds the record
// back once the active version allows it, and how many members lag.
func TestServerSigningGauges(t *testing.T) {
	c, cleanup := newTestCluster(t, "ldr-gauges", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	c.selfCertRole = func() string { return JoinRoleServer }
	self := c.gossip.selfMember()
	self.FSMOpsVersion, self.Alive = fsmOpsVersion, true
	quiet := recreateCandidate("wkr-quiet", "worker", 10)
	seedGossipView(t, c, []Member{self, quiet})
	setActive(t, c, 1, serverSigningFSMOpsVersion, 0, "")
	c.refreshServerSigningGauges()
	if serverSigningOn.Value() != 0 || serverSigningHeld.Value() != 1 || serverSigningWaiting.Value() != 1 {
		t.Fatalf("held: on %d held %d waiting %d", serverSigningOn.Value(), serverSigningHeld.Value(), serverSigningWaiting.Value())
	}
	if _, err := c.WriteServerSigning(context.Background(), ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("s"), SinceUnixNano: time.Now().Add(time.Minute).UnixNano()}}, true); err != nil {
		t.Fatal(err)
	}
	c.refreshServerSigningGauges()
	if serverSigningOn.Value() != 1 || serverSigningHeld.Value() != 0 {
		t.Fatalf("on: on %d held %d", serverSigningOn.Value(), serverSigningHeld.Value())
	}
}

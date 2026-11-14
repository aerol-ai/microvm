package cluster

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

// Regression tests for opAdmitNodeByCert (external-CA mode, C23, plan
// §15.2.1): every rule of a token admit but the token (CLAUDE.md rule 6).

func certAdmitCmd(nodeID, role, key string, stamp int64) command {
	return command{Op: opAdmitNodeByCert, StampUnixNano: stamp, JoinAdmit: &JoinAdmitCommand{
		NodeID: nodeID, Role: role, KeyHash: key, NotAfterUnixNano: stamp + int64(NodeCertLifetime),
	}}
}

func TestFSMAdmitNodeByCertRules(t *testing.T) {
	l := newJoinLog(t)
	res, ok := l.apply(certAdmitCmd("srv-1", JoinRoleServer, testKey("s1"), 100)).(JoinAdmitResult)
	if !ok || res.Replay || res.Node.NodeID != "srv-1" || res.Node.Role != JoinRoleServer || res.Node.TokenID != "" {
		t.Fatalf("admit = %+v", res)
	}
	if rec, ok := l.f.admittedNode("srv-1"); !ok || rec.KeyHash != testKey("s1") {
		t.Fatalf("admitted = %+v %v", rec, ok)
	}
	// A retry is the same answer.
	if again, ok := l.apply(certAdmitCmd("srv-1", JoinRoleServer, testKey("s1"), 200)).(JoinAdmitResult); !ok || !again.Replay {
		t.Fatalf("retry = %+v", again)
	}
	for name, tc := range map[string]struct {
		cmd  command
		want error
	}{
		// The certificate's role is the node's only role.
		"another role, same key": {certAdmitCmd("srv-1", JoinRoleWorker, testKey("s1"), 300), ErrJoinRoleMismatch},
		// One key per ID until the node is deleted.
		"a second key for the ID": {certAdmitCmd("srv-1", JoinRoleServer, testKey("s1-new"), 300), ErrNodeIDInUse},
		// A key belongs to one node.
		"another node's key": {certAdmitCmd("srv-2", JoinRoleServer, testKey("s1"), 300), ErrJoinKeyInUse},
	} {
		if err := asApplyErr(l.apply(tc.cmd)); !errors.Is(err, tc.want) {
			t.Errorf("%s = %v, want %v", name, err, tc.want)
		}
	}
	for i, bad := range []command{
		{Op: opAdmitNodeByCert, StampUnixNano: 1},
		{Op: opAdmitNodeByCert, JoinAdmit: &JoinAdmitCommand{NodeID: "a", Role: JoinRoleWorker, KeyHash: testKey("a")}}, // no stamp
		certAdmitCmd("BAD ID", JoinRoleWorker, testKey("a"), 1),
		certAdmitCmd("a", JoinRoleWorker, "not-a-hash", 1),
		certAdmitCmd("a", "boss", testKey("a"), 1),
		{Op: opAdmitNodeByCert, StampUnixNano: 1, JoinAdmit: &JoinAdmitCommand{TokenID: "abcdef", NodeID: "a", Role: JoinRoleWorker, KeyHash: testKey("a")}},
	} {
		if err := asApplyErr(l.apply(bad)); err == nil {
			t.Errorf("bad admit %d accepted", i)
		}
	}
	// A token join of the same ID with another key is refused too: the
	// ID's key is pinned whichever way it was admitted.
	_, tok := testJoinToken(t, JoinRoleServer, 400, time.Hour, false)
	l.apply(putTokenCmd(tok, 400))
	if err := asApplyErr(l.apply(admitCmd(tok.ID, "srv-1", JoinRoleServer, testKey("thief"), 401))); !errors.Is(err, ErrNodeIDInUse) {
		t.Fatalf("a token join of a certificate-admitted ID = %v", err)
	}
}

// A deleted node's key is tombstoned: its old certificate can't come back,
// and a fresh key replaces the deny record (J7).
func TestFSMAdmitNodeByCertAfterDelete(t *testing.T) {
	l := newJoinLog(t)
	l.apply(certAdmitCmd("wkr-1", JoinRoleWorker, testKey("w1"), 100))
	l.apply(denyCmd("wkr-1", 200))
	if err := asApplyErr(l.apply(certAdmitCmd("wkr-1", JoinRoleWorker, testKey("w1"), 300))); !errors.Is(err, ErrJoinKeyRevoked) {
		t.Fatalf("the deleted node's own key = %v", err)
	}
	res, ok := l.apply(certAdmitCmd("wkr-1", JoinRoleWorker, testKey("w1-new"), 300)).(JoinAdmitResult)
	if !ok || !res.ReplacedDeny || res.Node.KeyHash != testKey("w1-new") {
		t.Fatalf("a fresh key after the delete = %+v", res)
	}
	if err := l.f.peerTrustSnapshot().checkPeerKey("wkr-1", testKey("w1"), 300); !errors.Is(err, ErrPeerKeyRevoked) {
		t.Fatalf("the old key's trust = %v", err)
	}
}

// A certificate admit survives a snapshot like a token admit.
func TestFSMAdmitNodeByCertSnapshot(t *testing.T) {
	l := newJoinLog(t)
	l.apply(certAdmitCmd("ing-1", JoinRoleIngress, testKey("i1"), 100))
	snap, err := l.f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	snap.Release()
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	rec, ok := restored.admittedNode("ing-1")
	if !ok || rec.Role != JoinRoleIngress || rec.KeyHash != testKey("i1") || rec.TokenID != "" {
		t.Fatalf("restored = %+v %v", rec, ok)
	}
	// The retry rule holds across the restore.
	again := applyDenyLogAt(t, restored, 2, certAdmitCmd("ing-1", JoinRoleIngress, testKey("i1"), 200))
	if res, ok := again.(JoinAdmitResult); !ok || !res.Replay {
		t.Fatalf("retry after restore = %+v", again)
	}
}

// Only a cluster whose every server applies the op may propose it.
func TestWriteJoinAdmitByCertGate(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	c, cleanup := newTestCluster(t, "cert-gate-a", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	admit := &JoinAdmitCommand{NodeID: "wkr-cert", Role: JoinRoleWorker, KeyHash: testKey("wc"), NotAfterUnixNano: time.Now().Add(time.Hour).UnixNano()}
	out, err := c.WriteJoin(t.Context(), JoinWriteRequest{Kind: joinWriteAdmitByCert, Admit: admit})
	if err != nil || out.Admit == nil || out.Admit.Node.NodeID != "wkr-cert" || out.Admit.Node.TokenID != "" {
		t.Fatalf("admit by cert = %+v, %v", out, err)
	}
	if _, err := c.WriteJoin(t.Context(), JoinWriteRequest{Kind: joinWriteAdmitByCert}); !errors.Is(err, ErrJoinBadRequest) {
		t.Fatalf("no admit = %v", err)
	}
	if err := c.raft.raft.AddNonvoter("cert-gate-b", "127.0.0.1:1", 0, 0).Error(); err != nil {
		t.Fatal(err)
	}
	c.gossip.currentMemberIndex().upsert(Member{NodeID: "cert-gate-b", Alive: true, FSMOpsVersion: externalCAFSMOpsVersion - 1})
	if _, err := c.WriteJoin(t.Context(), JoinWriteRequest{Kind: joinWriteAdmitByCert, Admit: admit}); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("a server on the previous build = %v", err)
	}
}

package cluster

import (
	"bytes"
	"crypto/x509"
	"io"
	"reflect"
	"testing"
	"time"
)

// J10: deny records and tombstones are dropped once every cert their node
// could hold has expired, through Raft (at a join's stamp, so every
// replica drops the same ones), and the worker copy keeps only live ones.

// pruneTestLog denies a never-admitted node and an admitted one whose cert
// outlives a full life after the delete, then joins at, before and past
// each expiry.
func pruneTestLog(t *testing.T) (log []command, plainExpiry, longExpiry int64) {
	const stamp = int64(10_000_000_000)
	_, tok := testJoinToken(t, JoinRoleWorker, stamp, 0, true)
	long := admitCmd(tok.ID, "wkr-long", JoinRoleWorker, testKey("long"), stamp)
	long.JoinAdmit.NotAfterUnixNano = stamp + 2*int64(NodeCertLifetime)
	plainExpiry = certsGoneAt(0, stamp+1)
	longExpiry = certsGoneAt(long.JoinAdmit.NotAfterUnixNano, stamp+1)
	log = []command{
		putTokenCmd(tok, stamp),
		long,
		denyCmd("wkr-plain", stamp+1),
		denyCmd("wkr-long", stamp+1),
		admitCmd(tok.ID, "wkr-n1", JoinRoleWorker, testKey("n1"), plainExpiry-1),
		admitCmd(tok.ID, "wkr-n2", JoinRoleWorker, testKey("n2"), plainExpiry),
		admitCmd(tok.ID, "wkr-n3", JoinRoleWorker, testKey("n3"), longExpiry),
	}
	return log, plainExpiry, longExpiry
}

func deniedIDs(f *placementFSM) []string {
	nodes, _ := f.deniedNodesView()
	out := []string{}
	for _, n := range nodes {
		out = append(out, n.NodeID)
	}
	return out
}

func TestFSMPrunesExpiredDenyRecords(t *testing.T) {
	log, plainExpiry, longExpiry := pruneTestLog(t)
	f := newPlacementFSM()
	at := func(i int) { applyDenyLogAt(t, f, uint64(i+1), log[i]) }
	for i := 0; i < 4; i++ {
		at(i)
	}
	nodes, _ := f.deniedNodesView()
	if len(nodes) != 2 || nodes[0].ExpiresUnixNano != longExpiry || nodes[1].ExpiresUnixNano != plainExpiry {
		t.Fatalf("records = %+v, want expiries %d and %d", nodes, longExpiry, plainExpiry)
	}
	// A join before the first expiry drops nothing.
	at(4)
	_, v1 := f.deniedNodesView()
	if got := deniedIDs(f); len(got) != 2 {
		t.Fatalf("pruned early: %v", got)
	}
	// A join at the never-admitted node's expiry drops its record, moves
	// the agents' cursor, and keeps the one whose cert lives longer.
	at(5)
	_, v2 := f.deniedNodesView()
	if got := deniedIDs(f); len(got) != 1 || got[0] != "wkr-long" || v2 <= v1 || f.isNodeDenied("wkr-plain") || !f.isNodeDenied("wkr-long") {
		t.Fatalf("after the plain expiry: %v at %d (was %d)", got, v2, v1)
	}
	if len(f.revokedKeysView()) != 1 {
		t.Fatalf("the longer cert's tombstone went early: %+v", f.revokedKeysView())
	}
	// Past the longer cert's life the record and its tombstone go too.
	at(6)
	if got := deniedIDs(f); len(got) != 0 || len(f.revokedKeysView()) != 0 {
		t.Fatalf("after every expiry: %v %+v", got, f.revokedKeysView())
	}
	// A record from before the expiry field gets the plain bound.
	if got := (NodeDenyRecord{DeniedUnixNano: 7}).expiresAt(); got != certsGoneAt(0, 7) {
		t.Fatalf("legacy record expiry = %d", got)
	}
	// A retried delete leaves its record's expiry as first written.
	g := newPlacementFSM()
	applyDenyLogAt(t, g, 1, denyCmd("wkr-x", 5))
	applyDenyLogAt(t, g, 2, denyCmd("wkr-x", 500))
	if nodes, _ := g.deniedNodesView(); nodes[0].ExpiresUnixNano != certsGoneAt(0, 5) {
		t.Fatalf("retried delete moved the expiry: %+v", nodes)
	}
}

// Replay safety: a snapshot taken anywhere in the log, then the rest of
// the log, reaches the same records, tombstones and cursor as applying it
// all, so every replica prunes at the same entry.
func TestFSMDenyPruneReplay(t *testing.T) {
	log, _, _ := pruneTestLog(t)
	full := newPlacementFSM()
	for i, cmd := range log {
		applyDenyLogAt(t, full, uint64(i+1), cmd)
	}
	want := joinViewOf(full)
	for cut := 1; cut < len(log); cut++ {
		prefix := newPlacementFSM()
		for i := 0; i < cut; i++ {
			applyDenyLogAt(t, prefix, uint64(i+1), log[i])
		}
		snap, err := prefix.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		sink := &memSnapshotSink{}
		if err := snap.Persist(sink); err != nil {
			t.Fatal(err)
		}
		snap.Release()
		resumed := newPlacementFSM()
		if err := resumed.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
			t.Fatal(err)
		}
		for i := cut; i < len(log); i++ {
			applyDenyLogAt(t, resumed, uint64(i+1), log[i])
		}
		if got := joinViewOf(resumed); !reflect.DeepEqual(got, want) {
			t.Fatalf("cut at %d: resumed %+v\nwant %+v", cut, got, want)
		}
	}
}

// The feed and the worker's copy keep only tombstones that can still
// refuse a cert: past their life they wait only for the next join to drop
// them, so they are not sent and not kept.
func TestDenyFeedAndMirrorKeepOnlyLiveTombstones(t *testing.T) {
	now := time.Now()
	live, dead := now.Add(time.Hour).UnixNano(), now.Add(-time.Hour).UnixNano()
	f := newPlacementFSM()
	f.joinStateInitLocked()
	f.revokedKeys[testKey("live")] = RevokedKey{KeyHash: testKey("live"), NodeID: "a", ExpiresUnixNano: live}
	f.revokedKeys[testKey("dead")] = RevokedKey{KeyHash: testKey("dead"), NodeID: "b", ExpiresUnixNano: dead}
	f.revokedKeys[nodeCertsTombstoneKey("c")] = RevokedKey{KeyHash: nodeCertsTombstoneKey("c"), NodeID: "c", ExpiresUnixNano: live, IssuedBeforeUnixNano: now.UnixNano()}
	f.revokedKeys[nodeCertsTombstoneKey("d")] = RevokedKey{KeyHash: nodeCertsTombstoneKey("d"), NodeID: "d", ExpiresUnixNano: dead, IssuedBeforeUnixNano: now.UnixNano()}
	f.deniedNodesVersion = 3
	resp, changed := (&Cluster{fsm: f}).DeniedNodes(0)
	if !changed || len(resp.RevokedKeys) != 2 {
		t.Fatalf("feed = %+v", resp.RevokedKeys)
	}
	for _, k := range resp.RevokedKeys {
		if k.ExpiresUnixNano != live {
			t.Fatalf("feed sent an expired tombstone: %+v", k)
		}
	}

	// The worker drops expired entries even from an older server's feed.
	resp.RevokedKeys = append(resp.RevokedKeys, f.revokedKeys[testKey("dead")], f.revokedKeys[nodeCertsTombstoneKey("d")], RevokedKey{})
	var m agentDenyMirror
	m.mergeAt(resp, now.UnixNano())
	if len(m.revoked) != 1 || len(m.cutoffs) != 1 {
		t.Fatalf("mirror kept revoked %v cutoffs %v", m.revoked, m.cutoffs)
	}
	old, fresh := now.Add(-time.Minute), now.Add(time.Minute)
	if !m.oldCert("c", old, now.UnixNano()) || m.oldCert("c", fresh, now.UnixNano()) || m.oldCert("d", old, now.UnixNano()) || m.oldCert("", old, 0) {
		t.Fatal("mirror cutoffs answer wrong")
	}
	if m.oldCert("c", old, live) {
		t.Fatal("a cutoff refuses past its life")
	}
	var nilMirror *agentDenyMirror
	if nilMirror.oldCert("c", old, 0) {
		t.Fatal("nil mirror refused")
	}
	// The server's lock-free view answers the same.
	f.publishPeerTrustLocked()
	view := f.peerTrustSnapshot()
	if err := view.checkPeerCert("c", &x509.Certificate{NotBefore: old}, now.UnixNano()); err == nil {
		t.Fatal("server view accepted a cert from before the delete")
	}
	if err := view.checkPeerCert("c", &x509.Certificate{NotBefore: fresh}, now.UnixNano()); err != nil {
		t.Fatalf("server view refused a fresh cert: %v", err)
	}
	if view.checkPeerCert("c", nil, 0) != nil {
		t.Fatal("nil leaf refused")
	}
	var nilView *peerTrustView
	if nilView.checkPeerCert("c", &x509.Certificate{NotBefore: old}, 0) != nil {
		t.Fatal("nil view refused")
	}
	if (RevokedKey{KeyHash: "node:x"}).byNodeID() || !(RevokedKey{KeyHash: "node:x", NodeID: "x"}).byNodeID() {
		t.Fatal("byNodeID")
	}
}

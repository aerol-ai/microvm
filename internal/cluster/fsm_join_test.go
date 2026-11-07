package cluster

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// Regression tests for the join ops (fsm_join.go): apply rules, one winner
// per node ID, the deny tombstone, snapshot/restore, replay and the
// mixed-version rule (CLAUDE.md rule 6).

// testKey is a deterministic fake key hash.
func testKey(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}

// testJoinToken makes a token record for role at stamp with ttl (0 never).
func testJoinToken(t *testing.T, role string, stamp int64, ttl time.Duration, reusable bool) (string, JoinTokenRecord) {
	t.Helper()
	token, err := GenerateJoinToken()
	if err != nil {
		t.Fatal(err)
	}
	id, secret, err := ParseJoinToken(token)
	if err != nil {
		t.Fatal(err)
	}
	disc, err := joinDiscoveryKey(id, secret)
	if err != nil {
		t.Fatal(err)
	}
	rec := JoinTokenRecord{
		ID: id, Role: role, SecretHash: joinTokenSecretHash(id, secret), DiscoveryKey: disc,
		CreatedBy: "operator:test", CreatedUnixNano: stamp, Reusable: reusable,
	}
	if ttl > 0 {
		rec.ExpiresUnixNano = stamp + int64(ttl)
	}
	return token, rec
}

func putTokenCmd(rec JoinTokenRecord, stamp int64) command {
	r := rec
	return command{Op: opPutJoinToken, StampUnixNano: stamp, JoinToken: &r}
}

func admitCmd(tokenID, nodeID, role, key string, stamp int64) command {
	return command{Op: opAdmitNode, StampUnixNano: stamp, JoinAdmit: &JoinAdmitCommand{
		TokenID: tokenID, NodeID: nodeID, Role: role, KeyHash: key, NotAfterUnixNano: stamp + int64(NodeCertLifetime),
	}}
}

// joinLog applies commands at consecutive indexes from 1.
type joinLog struct {
	t     *testing.T
	f     *placementFSM
	index uint64
}

func newJoinLog(t *testing.T) *joinLog { return &joinLog{t: t, f: newPlacementFSM()} }

func (l *joinLog) apply(cmd command) any {
	l.index++
	return applyDenyLogAt(l.t, l.f, l.index, cmd)
}

func TestFSMJoinTokenPutAndDelete(t *testing.T) {
	l := newJoinLog(t)
	_, rec := testJoinToken(t, JoinRoleWorker, 100, time.Hour, false)
	got, ok := l.apply(putTokenCmd(rec, 100)).(JoinTokenRecord)
	if !ok || got.ID != rec.ID || got.Role != JoinRoleWorker {
		t.Fatalf("put = %+v", got)
	}
	// A retried put of the same token answers the stored row.
	if again, ok := l.apply(putTokenCmd(rec, 200)).(JoinTokenRecord); !ok || again.CreatedUnixNano != 100 {
		t.Fatalf("retried put = %+v", again)
	}
	// A different secret on the same id never overwrites it.
	other := rec
	other.SecretHash = bytes.Repeat([]byte{1}, 32)
	if err := asApplyErr(l.apply(putTokenCmd(other, 300))); !errors.Is(err, ErrJoinTokenIDTaken) {
		t.Fatalf("colliding id = %v", err)
	}
	bad := []command{
		{Op: opPutJoinToken, StampUnixNano: 1},
		{Op: opPutJoinToken, JoinToken: &rec}, // no stamp
		putTokenCmd(JoinTokenRecord{ID: "BAD", Role: JoinRoleWorker}, 1),
		putTokenCmd(JoinTokenRecord{ID: "abcdef", Role: "boss", SecretHash: rec.SecretHash, DiscoveryKey: rec.DiscoveryKey}, 1),
		putTokenCmd(JoinTokenRecord{ID: "abcdef", Role: JoinRoleWorker, SecretHash: []byte{1}, DiscoveryKey: rec.DiscoveryKey}, 1),
		putTokenCmd(JoinTokenRecord{ID: "abcdef", Role: JoinRoleServer, SecretHash: rec.SecretHash, DiscoveryKey: rec.DiscoveryKey}, 1), // server never-expiring
	}
	for i, cmd := range bad {
		if err := asApplyErr(l.apply(cmd)); err == nil {
			t.Fatalf("bad put %d accepted", i)
		}
	}
	if _, ok := l.f.joinToken(rec.ID); !ok {
		t.Fatal("token missing")
	}
	if err := asApplyErr(l.apply(command{Op: opDeleteJoinToken, JoinTokenID: rec.ID})); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.f.joinToken(rec.ID); ok {
		t.Fatal("revoked token still stored")
	}
	// Revoke is idempotent; a blank id is refused.
	if err := asApplyErr(l.apply(command{Op: opDeleteJoinToken, JoinTokenID: rec.ID})); err != nil {
		t.Fatal(err)
	}
	if err := asApplyErr(l.apply(command{Op: opDeleteJoinToken})); err == nil {
		t.Fatal("blank revoke accepted")
	}
	// A literal FSM (no maps) takes a delete too.
	lit := &placementFSM{}
	if err := asApplyErr(applyDenyLogAt(t, lit, 1, command{Op: opDeleteJoinToken, JoinTokenID: "abcdef"})); err != nil {
		t.Fatal(err)
	}
}

func TestFSMAdmitNodeRules(t *testing.T) {
	const stamp = int64(1_000_000_000)
	l := newJoinLog(t)
	_, single := testJoinToken(t, JoinRoleWorker, stamp, time.Hour, false)
	_, reusable := testJoinToken(t, JoinRoleWorker, stamp, 0, true)
	_, server := testJoinToken(t, JoinRoleServer, stamp, time.Hour, false)
	_, short := testJoinToken(t, JoinRoleIngress, stamp, time.Minute, false)
	for _, rec := range []JoinTokenRecord{single, reusable, server, short} {
		l.apply(putTokenCmd(rec, stamp))
	}

	res, ok := l.apply(admitCmd(single.ID, "wkr-1", JoinRoleWorker, testKey("k1"), stamp+1)).(JoinAdmitResult)
	if !ok || res.Replay || res.Node.KeyHash != testKey("k1") || res.Node.TokenID != single.ID || res.Node.AdmittedUnixNano != stamp+1 {
		t.Fatalf("first admit = %+v", res)
	}
	// Same token, ID and key: the same answer, flagged as a replay.
	res, _ = l.apply(admitCmd(single.ID, "wkr-1", JoinRoleWorker, testKey("k1"), stamp+2)).(JoinAdmitResult)
	if !res.Replay || res.Node.AdmittedUnixNano != stamp+1 {
		t.Fatalf("replay = %+v", res)
	}
	// The replay still works after the token expires.
	res, _ = l.apply(admitCmd(single.ID, "wkr-1", JoinRoleWorker, testKey("k1"), stamp+int64(2*time.Hour))).(JoinAdmitResult)
	if !res.Replay {
		t.Fatalf("replay past TTL = %+v", res)
	}

	cases := []struct {
		name string
		cmd  command
		want error
	}{
		{"single-use token, other node", admitCmd(single.ID, "wkr-2", JoinRoleWorker, testKey("k2"), stamp+3), ErrJoinTokenUsed},
		{"single-use token, same node other key", admitCmd(single.ID, "wkr-1", JoinRoleWorker, testKey("k9"), stamp+3), ErrJoinTokenUsed},
		{"unknown token", admitCmd("zzzzzz", "wkr-3", JoinRoleWorker, testKey("k3"), stamp+3), ErrJoinTokenInvalid},
		{"role mismatch", admitCmd(server.ID, "srv-1", JoinRoleWorker, testKey("k4"), stamp+3), ErrJoinRoleMismatch},
		{"expired", admitCmd(short.ID, "ing-1", JoinRoleIngress, testKey("k5"), stamp+int64(time.Minute)), ErrJoinTokenExpired},
		{"key admitted elsewhere", admitCmd(reusable.ID, "wkr-4", JoinRoleWorker, testKey("k1"), stamp+3), ErrJoinKeyInUse},
		{"ID held by another key", admitCmd(reusable.ID, "wkr-1", JoinRoleWorker, testKey("k6"), stamp+3), ErrNodeIDInUse},
	}
	for _, tc := range cases {
		if err := asApplyErr(l.apply(tc.cmd)); !errors.Is(err, tc.want) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	invalid := []command{
		{Op: opAdmitNode, StampUnixNano: 1},
		{Op: opAdmitNode, JoinAdmit: &JoinAdmitCommand{TokenID: reusable.ID, NodeID: "x", Role: JoinRoleWorker, KeyHash: testKey("x")}},
		admitCmd(reusable.ID, "bad id!", JoinRoleWorker, testKey("x"), 1),
		admitCmd(reusable.ID, "wkr-9", JoinRoleWorker, "nothex", 1),
	}
	for i, cmd := range invalid {
		if err := asApplyErr(l.apply(cmd)); err == nil {
			t.Fatalf("invalid admit %d accepted", i)
		}
	}

	// A reusable token admits many nodes and records each use, capped.
	for i := 0; i < maxJoinTokenUses+3; i++ {
		id := fmt.Sprintf("auto-%d", i)
		if _, ok := l.apply(admitCmd(reusable.ID, id, JoinRoleWorker, testKey(id), stamp+10+int64(i))).(JoinAdmitResult); !ok {
			t.Fatalf("reusable admit %d failed", i)
		}
	}
	tok, _ := l.f.joinToken(reusable.ID)
	if len(tok.UsedBy) != maxJoinTokenUses || tok.UsedBy[0].NodeID != "auto-3" {
		t.Fatalf("used-by = %d entries, first %+v", len(tok.UsedBy), tok.UsedBy[0])
	}
	if rec, ok := l.f.admittedNode("auto-0"); !ok || rec.Role != JoinRoleWorker {
		t.Fatalf("admitted auto-0 = %+v %v", rec, ok)
	}
}

// One winner per node ID: two joins for one ID with different keys apply
// one after the other; the first wins and the second is refused, whatever
// order they were proposed in.
func TestFSMAdmitNodeOneWinnerPerNodeID(t *testing.T) {
	const stamp = int64(5_000)
	for _, order := range [][2]string{{"a", "b"}, {"b", "a"}} {
		l := newJoinLog(t)
		_, ta := testJoinToken(t, JoinRoleWorker, stamp, time.Hour, false)
		_, tb := testJoinToken(t, JoinRoleWorker, stamp, time.Hour, false)
		l.apply(putTokenCmd(ta, stamp))
		l.apply(putTokenCmd(tb, stamp))
		tokens := map[string]string{"a": ta.ID, "b": tb.ID}
		first := l.apply(admitCmd(tokens[order[0]], "wkr-x", JoinRoleWorker, testKey(order[0]), stamp+1))
		second := l.apply(admitCmd(tokens[order[1]], "wkr-x", JoinRoleWorker, testKey(order[1]), stamp+2))
		if _, ok := first.(JoinAdmitResult); !ok {
			t.Fatalf("order %v: first = %v", order, first)
		}
		if err := asApplyErr(second); !errors.Is(err, ErrNodeIDInUse) {
			t.Fatalf("order %v: second = %v, want ErrNodeIDInUse", order, second)
		}
		if rec, _ := l.f.admittedNode("wkr-x"); rec.KeyHash != testKey(order[0]) {
			t.Fatalf("order %v: admitted %s", order, rec.KeyHash)
		}
		// The loser's token is still unused: it can join under another ID.
		if _, ok := l.apply(admitCmd(tokens[order[1]], "wkr-y", JoinRoleWorker, testKey(order[1]), stamp+3)).(JoinAdmitResult); !ok {
			t.Fatalf("order %v: loser's token unusable", order)
		}
	}
}

// The tombstone rule (Codex CEO finding 6): a deleted node's key stays
// refused after a fresh join reuses its ID; the fresh join replaces the
// deny record; the old key can't join again.
func TestFSMDenyTombstonesAdmittedKey(t *testing.T) {
	const stamp = int64(10_000_000_000)
	l := newJoinLog(t)
	_, t1 := testJoinToken(t, JoinRoleWorker, stamp, time.Hour, false)
	_, t2 := testJoinToken(t, JoinRoleWorker, stamp, time.Hour, false)
	_, t3 := testJoinToken(t, JoinRoleWorker, stamp, time.Hour, false)
	l.apply(putTokenCmd(t1, stamp))
	l.apply(putTokenCmd(t2, stamp))
	l.apply(putTokenCmd(t3, stamp))
	l.apply(admitCmd(t1.ID, "wkr-1", JoinRoleWorker, testKey("old"), stamp+1))
	now := stamp + 2
	if err := l.f.peerTrustSnapshot().checkPeerKey("wkr-1", testKey("old"), now); err != nil {
		t.Fatalf("admitted key refused: %v", err)
	}
	if err := l.f.peerTrustSnapshot().checkPeerKey("wkr-1", testKey("other"), now); !errors.Is(err, ErrPeerKeyNotAdmitted) {
		t.Fatalf("unadmitted key = %v", err)
	}
	if err := l.f.peerTrustSnapshot().checkPeerKey("legacy-node", testKey("anything"), now); err != nil {
		t.Fatalf("a node with no admitted record keeps today's behaviour: %v", err)
	}

	l.apply(denyCmd("wkr-1", stamp+10))
	_, version := l.f.deniedNodesView()
	if _, ok := l.f.admittedNode("wkr-1"); ok {
		t.Fatal("deny left the admitted record")
	}
	revoked := l.f.revokedKeysView()
	if len(revoked) != 1 || revoked[0].KeyHash != testKey("old") || revoked[0].ExpiresUnixNano != stamp+10+int64(NodeCertLifetime)+int64(revokedKeySkew) {
		t.Fatalf("tombstones = %+v", revoked)
	}
	// The old key can't come back through a join, under any ID.
	if err := asApplyErr(l.apply(admitCmd(t2.ID, "wkr-1", JoinRoleWorker, testKey("old"), stamp+20))); !errors.Is(err, ErrJoinKeyRevoked) {
		t.Fatalf("revoked key rejoin = %v", err)
	}
	// A fresh join with a new key replaces the deny record.
	res, ok := l.apply(admitCmd(t2.ID, "wkr-1", JoinRoleWorker, testKey("new"), stamp+30)).(JoinAdmitResult)
	if !ok || !res.ReplacedDeny {
		t.Fatalf("fresh join = %+v", res)
	}
	if l.f.isNodeDenied("wkr-1") {
		t.Fatal("fresh join left the deny record")
	}
	if _, v := l.f.deniedNodesView(); v <= version {
		t.Fatalf("deny cursor did not move (%d -> %d): workers would keep refusing the ID", version, v)
	}
	trust := l.f.peerTrustSnapshot()
	if err := trust.checkPeerKey("wkr-1", testKey("old"), stamp+31); !errors.Is(err, ErrPeerKeyRevoked) {
		t.Fatalf("old cert of the reused ID = %v, want revoked", err)
	}
	if err := trust.checkPeerKey("wkr-1", testKey("new"), stamp+31); err != nil {
		t.Fatalf("new key refused: %v", err)
	}
	// A retried delete of the new node tombstones the new key too.
	l.apply(denyCmd("wkr-1", stamp+40))
	if len(l.f.revokedKeysView()) != 2 {
		t.Fatalf("second deny tombstones = %+v", l.f.revokedKeysView())
	}
	// Tombstones expire at an entry stamped past their life, on every replica.
	later := stamp + 40 + int64(NodeCertLifetime) + int64(revokedKeySkew) + 1
	l.apply(admitCmd(t3.ID, "wkr-9", JoinRoleWorker, testKey("fresh"), later))
	if got := l.f.revokedKeysView(); len(got) != 0 {
		t.Fatalf("expired tombstones kept: %+v", got)
	}
	// Past its expiry a tombstone no longer refuses, even before a prune.
	view := &peerTrustView{revoked: map[string]int64{testKey("x"): 5}}
	if view.checkPeerKey("n", testKey("x"), 5) != nil || view.revokedKey(testKey("x"), 6) {
		t.Fatal("an expired tombstone still refuses")
	}
	var nilView *peerTrustView
	if nilView.checkPeerKey("n", "k", 1) != nil || nilView.revokedKey("k", 1) {
		t.Fatal("nil view refused")
	}
}

func TestFSMAdoptNodes(t *testing.T) {
	const stamp = int64(77)
	l := newJoinLog(t)
	_, tok := testJoinToken(t, JoinRoleWorker, stamp, time.Hour, false)
	l.apply(putTokenCmd(tok, stamp))
	l.apply(admitCmd(tok.ID, "joined", JoinRoleWorker, testKey("joined"), stamp))
	l.apply(denyCmd("gone", stamp))
	cmd := command{Op: opAdoptNodes, StampUnixNano: stamp + 1, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{
		{NodeID: "srv-1", Role: JoinRoleServer, KeyHash: testKey("srv-1"), NotAfterUnixNano: 999},
		{NodeID: "wkr-1", Role: JoinRoleWorker, KeyHash: testKey("wkr-1")},
		{NodeID: "joined", Role: JoinRoleWorker, KeyHash: testKey("joined")},
		{NodeID: "other", Role: JoinRoleWorker, KeyHash: testKey("joined")},
		{NodeID: "conflict", Role: JoinRoleWorker, KeyHash: testKey("c1")},
		{NodeID: "gone", Role: JoinRoleWorker, KeyHash: testKey("gone")},
		{NodeID: "bad id!", Role: JoinRoleWorker, KeyHash: testKey("bad")},
	}}}
	l.apply(command{Op: opAdoptNodes, StampUnixNano: stamp, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{{NodeID: "conflict", Role: JoinRoleWorker, KeyHash: testKey("c0")}}}})
	res, ok := l.apply(cmd).(JoinAdoptResult)
	if !ok {
		t.Fatalf("adopt = %v", res)
	}
	if !reflect.DeepEqual(res.Admitted, []string{"srv-1", "wkr-1"}) || !reflect.DeepEqual(res.Already, []string{"joined"}) {
		t.Fatalf("adopt result = %+v", res)
	}
	for _, id := range []string{"other", "conflict", "gone", "bad id!"} {
		if res.Skipped[id] == "" {
			t.Fatalf("%s not skipped: %+v", id, res.Skipped)
		}
	}
	if rec, _ := l.f.admittedNode("srv-1"); !rec.IsServer() || rec.TokenID != adoptTokenID || rec.NotAfterUnixNano != 999 {
		t.Fatalf("adopted server = %+v", rec)
	}
	// Running adopt again changes nothing.
	again, _ := l.apply(cmd).(JoinAdoptResult)
	if len(again.Admitted) != 0 || len(again.Already) != 3 {
		t.Fatalf("second adopt = %+v", again)
	}
	if err := asApplyErr(l.apply(command{Op: opAdoptNodes, StampUnixNano: 1})); err == nil {
		t.Fatal("adopt without members accepted")
	}
	if err := asApplyErr(l.apply(command{Op: opAdoptNodes, JoinAdopt: &JoinAdoptCommand{}})); err == nil {
		t.Fatal("adopt without a stamp accepted")
	}
}

func TestFSMRekeyNode(t *testing.T) {
	const stamp = int64(1_000)
	l := newJoinLog(t)
	l.apply(command{Op: opAdoptNodes, StampUnixNano: stamp, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{
		{NodeID: "wkr-1", Role: JoinRoleWorker, KeyHash: testKey("k1")},
		{NodeID: "wkr-2", Role: JoinRoleWorker, KeyHash: testKey("k2")},
	}}})
	rekey := func(node, old, new string, at int64) any {
		return l.apply(command{Op: opRekeyNode, StampUnixNano: at, JoinRekey: &JoinRekeyCommand{NodeID: node, OldKeyHash: old, NewKeyHash: new, NotAfterUnixNano: at + 100}})
	}
	rec, ok := rekey("wkr-1", testKey("k1"), testKey("k1b"), stamp+1).(AdmittedNode)
	if !ok || rec.KeyHash != testKey("k1b") || rec.PrevKeyHash != testKey("k1") || rec.PrevUntilUnixNano != stamp+1+int64(rekeyGrace) {
		t.Fatalf("rekey = %+v", rec)
	}
	if again, ok := rekey("wkr-1", testKey("k1"), testKey("k1b"), stamp+2).(AdmittedNode); !ok || again.PrevUntilUnixNano != rec.PrevUntilUnixNano {
		t.Fatalf("retried rekey = %+v", again)
	}
	trust := l.f.peerTrustSnapshot()
	if err := trust.checkPeerKey("wkr-1", testKey("k1"), stamp+5); err != nil {
		t.Fatalf("previous key inside the grace: %v", err)
	}
	if err := trust.checkPeerKey("wkr-1", testKey("k1"), rec.PrevUntilUnixNano); !errors.Is(err, ErrPeerKeyNotAdmitted) {
		t.Fatalf("previous key after the grace = %v", err)
	}
	cases := []struct {
		node, old, new string
		want           error
	}{
		{"nobody", testKey("a"), testKey("b"), ErrNotAdmitted},
		{"wkr-1", testKey("k1"), testKey("k1c"), ErrRekeyConflict},
		{"wkr-1", testKey("k1b"), testKey("k2"), ErrJoinKeyInUse},
	}
	for _, tc := range cases {
		if err := asApplyErr(rekey(tc.node, tc.old, tc.new, stamp+3)); !errors.Is(err, tc.want) {
			t.Fatalf("rekey %+v = %v", tc, err)
		}
	}
	// Deleting during the grace tombstones both keys.
	l.apply(denyCmd("wkr-1", stamp+4))
	if got := l.f.revokedKeysView(); len(got) != 2 {
		t.Fatalf("deny during grace tombstoned %+v", got)
	}
	l.apply(command{Op: opAdoptNodes, StampUnixNano: stamp + 5, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{{NodeID: "wkr-3", Role: JoinRoleWorker, KeyHash: testKey("k3")}}}})
	if err := asApplyErr(rekey("wkr-3", testKey("k3"), testKey("k1b"), stamp+6)); !errors.Is(err, ErrJoinKeyRevoked) {
		t.Fatalf("rekey onto a revoked key = %v", err)
	}
	for _, bad := range []command{
		{Op: opRekeyNode, StampUnixNano: 1},
		{Op: opRekeyNode, JoinRekey: &JoinRekeyCommand{NodeID: "wkr-2", OldKeyHash: testKey("k2"), NewKeyHash: testKey("z")}},
		{Op: opRekeyNode, StampUnixNano: 1, JoinRekey: &JoinRekeyCommand{NodeID: "wkr-2", OldKeyHash: "x", NewKeyHash: testKey("z")}},
	} {
		if err := asApplyErr(l.apply(bad)); err == nil {
			t.Fatalf("bad rekey %+v accepted", bad)
		}
	}
}

// joinTestLog touches every join op next to a placement and the deny path.
func joinTestLog(t *testing.T) []command {
	const stamp = int64(2_000_000_000)
	_, single := testJoinToken(t, JoinRoleWorker, stamp, time.Hour, false)
	_, reuse := testJoinToken(t, JoinRoleWorker, stamp, 0, true)
	_, srv := testJoinToken(t, JoinRoleServer, stamp, time.Hour, false)
	return []command{
		{Op: opPlace, SandboxID: "sb-1", OwnerNodeID: "wkr-1", OwnerAPIURL: "http://wkr-1", IncarnationID: "inc-1"},
		putTokenCmd(single, stamp),
		putTokenCmd(reuse, stamp),
		putTokenCmd(srv, stamp),
		{Op: opAdoptNodes, StampUnixNano: stamp + 1, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{{NodeID: "seed", Role: JoinRoleServer, KeyHash: testKey("seed")}}}},
		admitCmd(single.ID, "wkr-1", JoinRoleWorker, testKey("w1"), stamp+2),
		admitCmd(single.ID, "wkr-1", JoinRoleWorker, testKey("w1"), stamp+3), // retry
		admitCmd(reuse.ID, "wkr-2", JoinRoleWorker, testKey("w2"), stamp+4),
		admitCmd(srv.ID, "srv-2", JoinRoleServer, testKey("s2"), stamp+5),
		{Op: opRekeyNode, StampUnixNano: stamp + 6, JoinRekey: &JoinRekeyCommand{NodeID: "wkr-2", OldKeyHash: testKey("w2"), NewKeyHash: testKey("w2b")}},
		denyCmd("wkr-1", stamp+7),
		admitCmd(reuse.ID, "wkr-1", JoinRoleWorker, testKey("w1b"), stamp+8), // fresh join over the deny
		{Op: opDeleteJoinToken, JoinTokenID: srv.ID},
	}
}

type joinView struct {
	base     fsmView
	tokens   []JoinTokenRecord
	admitted []AdmittedNode
	revoked  []RevokedKey
}

func joinViewOf(f *placementFSM) joinView {
	tokens, admitted, revoked := f.joinStateView()
	return joinView{base: viewOf(f), tokens: tokens, admitted: admitted, revoked: revoked}
}

func TestFSMJoinSnapshotRestore(t *testing.T) {
	f := newPlacementFSM()
	for i, cmd := range joinTestLog(t) {
		applyDenyLogAt(t, f, uint64(i+1), cmd)
	}
	snap, err := f.Snapshot()
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
	got, want := joinViewOf(restored), joinViewOf(f)
	// A restore's deny cursor is the snapshot's index (restoreDeniedNodesLocked).
	if got.base.deniedAt != 13 {
		t.Fatalf("restored cursor = %d, want the snapshot index 13", got.base.deniedAt)
	}
	got.base.deniedAt, want.base.deniedAt = 0, 0
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("restored %+v\nwant %+v", got, want)
	}
	if err := restored.peerTrustSnapshot().checkPeerKey("wkr-1", testKey("w1"), 1); !errors.Is(err, ErrPeerKeyRevoked) {
		t.Fatalf("restored trust view lost the tombstone: %v", err)
	}
	// An older snapshot has no join state: nothing issued, admitted or
	// revoked, and anything held before is cleared. Blank rows are dropped.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(fsmSnapshotPayload{Version: 3, JoinTokens: []JoinTokenRecord{{}}, AdmittedNodes: []AdmittedNode{{NodeID: "x"}}, RevokedKeys: []RevokedKey{{}}}); err != nil {
		t.Fatal(err)
	}
	if err := restored.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatal(err)
	}
	tokens, admitted, revoked := restored.joinStateView()
	if len(tokens)+len(admitted)+len(revoked) != 0 {
		t.Fatalf("old snapshot restored %v %v %v", tokens, admitted, revoked)
	}
	if _, v := restored.deniedNodesView(); v != 3 {
		// The blank tombstone row still says "a tombstone table exists", so
		// agents are told to refetch; the cursor is the snapshot's index.
		t.Fatalf("cursor = %d", v)
	}
}

func TestFSMJoinReplay(t *testing.T) {
	log := joinTestLog(t)
	full := newPlacementFSM()
	for i, cmd := range log {
		applyDenyLogAt(t, full, uint64(i+1), cmd)
	}
	want := joinViewOf(full)
	if len(want.admitted) != 4 || len(want.revoked) != 1 || len(want.tokens) != 2 {
		t.Fatalf("full replay = %+v", want)
	}
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

// applyAsFV11 is a build without the join ops: they land on the default
// branch. Its opDenyNode never tombstones, which only matters once an
// admitted record exists — and none can until every server runs fv 13.
func applyAsFV11(t *testing.T, f *placementFSM, index uint64, cmd command) any {
	t.Helper()
	if isJoinOp(cmd.Op) {
		cmd.Op = opCode(254)
	}
	return applyDenyLogAt(t, f, index, cmd)
}

func TestFSMJoinMixedVersionDeterminism(t *testing.T) {
	var gated []command
	for _, cmd := range joinTestLog(t) {
		if !isJoinOp(cmd.Op) {
			gated = append(gated, cmd)
		}
	}
	oldFSM, newFSM := newPlacementFSM(), newPlacementFSM()
	for i, cmd := range gated {
		if err := asApplyErr(applyAsFV11(t, oldFSM, uint64(i+1), cmd)); err != nil {
			t.Fatalf("old build, entry %d: %v", i, err)
		}
		if err := asApplyErr(applyDenyLogAt(t, newFSM, uint64(i+1), cmd)); err != nil {
			t.Fatalf("new build, entry %d: %v", i, err)
		}
	}
	if o, n := joinViewOf(oldFSM), joinViewOf(newFSM); !reflect.DeepEqual(o, n) {
		t.Fatalf("same gated log, different state:\n old %+v\n new %+v", o, n)
	}

	// Ungated, an old build fails every join op and diverges only in the
	// join tables (and in a deny that removed nothing it held).
	oldFSM, newFSM = newPlacementFSM(), newPlacementFSM()
	unknown := 0
	for i, cmd := range joinTestLog(t) {
		if err := asApplyErr(applyAsFV11(t, oldFSM, uint64(i+1), cmd)); err != nil {
			if !isJoinOp(cmd.Op) || !strings.Contains(err.Error(), "unknown op") {
				t.Fatalf("old build, entry %d: %v", i, err)
			}
			unknown++
		}
		applyDenyLogAt(t, newFSM, uint64(i+1), cmd)
	}
	o, n := joinViewOf(oldFSM), joinViewOf(newFSM)
	if unknown == 0 || len(o.admitted) != 0 || len(n.admitted) == 0 {
		t.Fatalf("ungated: old %+v new %+v", o, n)
	}
	if !reflect.DeepEqual(o.base.placements, n.base.placements) {
		t.Fatalf("placements diverged outside the join state")
	}
}

func TestJoinRoleForNodeRole(t *testing.T) {
	for role, want := range map[string]string{
		"": JoinRoleServer, "mixed": JoinRoleServer, "server": JoinRoleServer, "server,worker": JoinRoleServer,
		"worker": JoinRoleWorker, "worker,ingress": JoinRoleWorker, "ingress": JoinRoleIngress,
	} {
		if got := joinRoleForNodeRole(role); got != want {
			t.Fatalf("joinRoleForNodeRole(%q) = %q, want %q", role, got, want)
		}
	}
}

func TestApplyEncodedRefusesJoinOps(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newTestCluster(t, "join-fwd", true, nil)
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	_, rec := testJoinToken(t, JoinRoleServer, 1, time.Hour, false)
	for _, cmd := range []command{
		putTokenCmd(rec, 1),
		{Op: opDeleteJoinToken, JoinTokenID: rec.ID},
		admitCmd(rec.ID, "evil", JoinRoleServer, testKey("evil"), 2),
		{Op: opAdoptNodes, StampUnixNano: 1, JoinAdopt: &JoinAdoptCommand{}},
		{Op: opRekeyNode, StampUnixNano: 1, JoinRekey: &JoinRekeyCommand{}},
	} {
		payload, _ := encodeCommand(cmd)
		if err := leader.ApplyEncoded(t.Context(), payload); !errors.Is(err, errJoinOpNotForwardable) {
			t.Fatalf("forwarded op %d = %v", cmd.Op, err)
		}
	}
	_ = raft.Log{}
}

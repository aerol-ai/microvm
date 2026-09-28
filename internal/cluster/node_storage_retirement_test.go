package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The obligations an attestation discharges live in the delete outbox of
// whichever node owns the secret, and an operator's request reaches an
// arbitrary entry node. The attestation therefore has to be replicated
// control-plane state — small administrative metadata, one row per
// decommissioned node — not a row on the node that served the call.
func TestNodeStorageRetirementIsReplicatedControlPlaneState(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-retire", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	attestedAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	if err := c.RetireNodeStorage(ctx, "node-gone", "operator", "disk destroyed", attestedAt); err != nil {
		t.Fatalf("RetireNodeStorage: %v", err)
	}
	// Idempotent: a repeat attestation replaces rather than duplicates.
	if err := c.RetireNodeStorage(ctx, "node-gone", "operator", "disk destroyed", attestedAt); err != nil {
		t.Fatalf("repeat RetireNodeStorage: %v", err)
	}

	recs, err := c.NodeStorageRetirements(ctx)
	if err != nil {
		t.Fatalf("NodeStorageRetirements: %v", err)
	}
	if len(recs) != 1 || recs[0].NodeID != "node-gone" {
		t.Fatalf("retirements = %+v, want exactly one for node-gone", recs)
	}
	if !recs[0].AttestedAt().Equal(attestedAt.UTC()) {
		t.Fatalf("attested at %v, want %v; every replica must fence against the same time", recs[0].AttestedAt(), attestedAt.UTC())
	}
	if recs[0].Actor != "operator" || recs[0].Reason != "disk destroyed" {
		t.Fatalf("attestation lost its provenance: %+v", recs[0])
	}

	// A peer read carries the same answer, marked authoritative so a worker
	// can tell it apart from "could not ask".
	peer := c.NodeStorageRetirementsForPeer()
	if !peer.Authoritative || len(peer.Retirements) != 1 {
		t.Fatalf("peer read = %+v; a non-authoritative answer must never read as an empty set", peer)
	}

	if err := c.RevokeNodeStorageRetirement(ctx, "node-gone"); err != nil {
		t.Fatalf("RevokeNodeStorageRetirement: %v", err)
	}
	if recs, err = c.NodeStorageRetirements(ctx); err != nil || len(recs) != 0 {
		t.Fatalf("after revoke: recs=%+v err=%v", recs, err)
	}
}

// Attestations must survive log compaction like any other FSM state.
func TestNodeStorageRetirementSurvivesSnapshotRestore(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.storageRetirements["node-gone"] = NodeStorageRetirement{
		NodeID: "node-gone", Actor: "op", Reason: "shredded", AttestedUnixNano: time.Now().UnixNano(),
	}

	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got := restored.nodeStorageRetirementsSnapshot()
	if len(got) != 1 || got[0].NodeID != "node-gone" || got[0].Reason != "shredded" {
		t.Fatalf("restored retirements = %+v; a compacted log would forget the attestation", got)
	}
}

// An operator's request can land on a worker or ingress, which hold no FSM.
// Both the write and the read are then RPCs, and an unreachable control plane
// must surface as an error — "no attestations" would silently re-pin every
// obligation the operator discharged.
func TestAgentNodeStorageRetirementRoundTrip(t *testing.T) {
	var applied []command
	authoritative := true
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case PublicInternalApplyPath, InternalAPIPath:
			body, _ := io.ReadAll(r.Body)
			cmd, err := decodeCommand(body)
			if err != nil {
				t.Errorf("decode forwarded command: %v", err)
				return
			}
			applied = append(applied, cmd)
			w.WriteHeader(http.StatusNoContent)
		case PublicInternalNodeStorageRetirementsPath:
			_ = json.NewEncoder(w).Encode(NodeStorageRetirementsResponse{
				Retirements:   []NodeStorageRetirement{{NodeID: "node-gone", AttestedUnixNano: 42}},
				Authoritative: authoritative,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	ctx := context.Background()

	attestedAt := time.Unix(1700000000, 0)
	if err := agent.RetireNodeStorage(ctx, "node-gone", "op", "disk destroyed", attestedAt); err != nil {
		t.Fatalf("RetireNodeStorage: %v", err)
	}
	if len(applied) != 1 || applied[0].Op != opRetireNodeStorage || applied[0].StorageRetirement == nil {
		t.Fatalf("forwarded commands = %+v", applied)
	}
	if got := applied[0].StorageRetirement.AttestedUnixNano; got != attestedAt.UTC().UnixNano() {
		t.Fatalf("attested unix = %d, want %d; every replica fences against the same time", got, attestedAt.UTC().UnixNano())
	}
	if err := agent.RetireNodeStorage(ctx, "", "op", "", attestedAt); err == nil {
		t.Fatal("an attestation with no node id was forwarded")
	}
	if err := agent.RevokeNodeStorageRetirement(ctx, "node-gone"); err != nil {
		t.Fatalf("RevokeNodeStorageRetirement: %v", err)
	}
	if len(applied) != 2 || applied[1].Op != opRevokeNodeStorage {
		t.Fatalf("revoke was not forwarded: %+v", applied)
	}
	if err := agent.RevokeNodeStorageRetirement(ctx, " "); err == nil {
		t.Fatal("a revoke with no node id was forwarded")
	}

	recs, err := agent.NodeStorageRetirements(ctx)
	if err != nil || len(recs) != 1 || recs[0].NodeID != "node-gone" {
		t.Fatalf("read = %+v err=%v", recs, err)
	}
	authoritative = false
	if _, err := agent.NodeStorageRetirements(ctx); err == nil {
		t.Fatal("a non-authoritative retirement read was accepted as the attestation set")
	}
}

// A worker's authoritative read asks the control plane for the LEADER's
// answer; the discovery read does not.
func TestAgentAuthoritativeRetirementReadAsksForTheLeader(t *testing.T) {
	var paths []string
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		_ = json.NewEncoder(w).Encode(NodeStorageRetirementsResponse{Authoritative: true})
	}))
	ctx := context.Background()

	if _, err := agent.NodeStorageRetirements(ctx); err != nil {
		t.Fatalf("discovery read: %v", err)
	}
	if _, err := agent.AuthoritativeNodeStorageRetirements(ctx); err != nil {
		t.Fatalf("authoritative read: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("requests = %v", paths)
	}
	if strings.Contains(paths[0], "authoritative=true") {
		t.Fatalf("the discovery read asked for the leader: %q", paths[0])
	}
	if !strings.Contains(paths[1], "authoritative=true") {
		t.Fatalf("the authoritative read did not ask for the leader: %q", paths[1])
	}

	var none *Agent
	if _, err := none.AuthoritativeNodeStorageRetirements(ctx); err == nil {
		t.Fatal("an unconfigured agent answered an authoritative read")
	}
}

// A zero attestation time cannot fence anything, so it reads as "no time".
func TestNodeStorageRetirementAttestedAtPrecision(t *testing.T) {
	if got := (NodeStorageRetirement{}).AttestedAt(); !got.IsZero() {
		t.Fatalf("zero attestation carried a time: %v", got)
	}
	// Sub-second precision matters: a copy distributed a few hundred
	// milliseconds before the attestation must not read as newer than it.
	at := time.Now().UTC()
	rec := NodeStorageRetirement{AttestedUnixNano: at.UnixNano()}
	if got := rec.AttestedAt(); !got.Equal(at) {
		t.Fatalf("attested at %v, want %v", got, at)
	}
}

// A follower's own FSM cannot order itself against a revoke, so the
// authoritative read forwards to the leader. Server and mixed nodes hold
// delete outboxes of their own, so this path has to work for them — without
// it every one of them fails closed forever on an attestation the operator
// did make.
func TestClusterAuthoritativeRetirementReadForwardsToTheLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupL := newTestCluster(t, "srv-retire-leader", true, nil)
	defer cleanupL()
	follower, cleanupF := newTestCluster(t, "srv-retire-follower", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupF()
	waitForLeader(t, leader, 10*time.Second)
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)
	waitForLeader(t, follower, 10*time.Second)
	ctx := context.Background()

	// The leader answers from its own FSM.
	if err := leader.RetireNodeStorage(ctx, "node-gone", "operator", "disk destroyed", time.Now()); err != nil {
		t.Fatal(err)
	}
	recs, err := leader.AuthoritativeNodeStorageRetirements(ctx)
	if err != nil || len(recs) != 1 {
		t.Fatalf("leader read = %+v err=%v", recs, err)
	}

	// A follower forwards. The probe reuses the leader's raft so the HTTP
	// branches do not need a second election; only its gossip view and
	// internal client differ.
	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("authoritative") != "true" {
			http.Error(w, "the forwarded read did not ask for the leader", http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	leaderID := follower.Leader()
	if leaderID == "" {
		t.Fatal("follower reported no leader")
	}
	// The probe reuses the FOLLOWER's raft, so it really is a follower; only
	// its gossip view and internal client are redirected at the stub.
	probeFor := func(internalURL string, client *http.Client) *Cluster {
		index := newGossipMemberIndex()
		index.upsert(Member{NodeID: leaderID, Alive: true, InternalURL: internalURL})
		probe := &Cluster{
			nodeID:   follower.nodeID,
			patToken: "tok",
			fsm:      follower.fsm,
			raft:     follower.raft,
			gossip:   &gossipNode{memberIndex: index},
		}
		probe.setInternalClient(client)
		return probe
	}

	status, body = http.StatusOK, `{"retirements":[{"node_id":"node-gone","attested_unix_nano":7}],"authoritative":true}`
	got, err := probeFor(srv.URL, srv.Client()).AuthoritativeNodeStorageRetirements(ctx)
	if err != nil || len(got) != 1 || got[0].NodeID != "node-gone" {
		t.Fatalf("forwarded read = %+v err=%v", got, err)
	}

	// An answer that is not authoritative is refused rather than trusted.
	status, body = http.StatusOK, `{"retirements":[],"authoritative":false}`
	if _, err := probeFor(srv.URL, srv.Client()).AuthoritativeNodeStorageRetirements(ctx); err == nil {
		t.Fatal("a non-authoritative answer was accepted")
	}

	status, body = http.StatusOK, "{not-json"
	if _, err := probeFor(srv.URL, srv.Client()).AuthoritativeNodeStorageRetirements(ctx); err == nil {
		t.Fatal("decode error expected")
	}
	status, body = http.StatusServiceUnavailable, "not leader"
	if _, err := probeFor(srv.URL, srv.Client()).AuthoritativeNodeStorageRetirements(ctx); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("503 = %v", err)
	}
	status, body = http.StatusInternalServerError, "boom"
	if _, err := probeFor(srv.URL, srv.Client()).AuthoritativeNodeStorageRetirements(ctx); err == nil {
		t.Fatal("500 expected")
	}
	if _, err := probeFor("http://127.0.0.1:1", http.DefaultClient).AuthoritativeNodeStorageRetirements(ctx); err == nil {
		t.Fatal("dial error expected")
	}

	var none *Cluster
	if _, err := none.AuthoritativeNodeStorageRetirements(ctx); err == nil {
		t.Fatal("a nil cluster answered an authoritative read")
	}
}

// The forwarding path's preconditions: no leader, no internal client, and no
// internal URL for the leader are all fail-closed, because a discharge
// authorized by nothing is not authorized at all.
func TestClusterAuthoritativeRetirementReadPreconditions(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupL := newTestCluster(t, "srv-precond-leader", true, nil)
	defer cleanupL()
	follower, cleanupF := newTestCluster(t, "srv-precond-follower", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupF()
	waitForLeader(t, leader, 10*time.Second)
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)
	waitForLeader(t, follower, 10*time.Second)
	ctx := context.Background()

	leaderID := follower.Leader()
	if leaderID == "" {
		t.Fatal("follower reported no leader")
	}

	// Gossip knows the leader but has no internal URL for it.
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: leaderID, Alive: true})
	noURL := &Cluster{nodeID: follower.nodeID, fsm: follower.fsm, raft: follower.raft, gossip: &gossipNode{memberIndex: index}}
	noURL.setInternalClient(http.DefaultClient)
	if _, err := noURL.AuthoritativeNodeStorageRetirements(ctx); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("missing internal URL = %v, want ErrPeerInternalURLRequired", err)
	}

	// No internal client at all.
	noClient := &Cluster{nodeID: follower.nodeID, fsm: follower.fsm, raft: follower.raft, gossip: &gossipNode{memberIndex: index}}
	if _, err := noClient.AuthoritativeNodeStorageRetirements(ctx); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("missing internal client = %v, want ErrPeerInternalURLRequired", err)
	}

	// A node with no FSM cannot answer either.
	if _, err := (&Cluster{}).AuthoritativeNodeStorageRetirements(ctx); err == nil {
		t.Fatal("a cluster with no placement state answered an authoritative read")
	}
}

// Leadership is not an authority claim on its own: raft applies to the FSM
// asynchronously, so a node can win an election while its FSM still holds an
// attestation the operator already revoked. The authoritative read therefore
// takes a quorum round (VerifyLeader) and waits for the apply queue to drain
// (Barrier) before answering, and the PEER path uses the same read rather
// than touching the FSM directly.
func TestAuthoritativeRetirementReadWaitsForTheFSM(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "srv-barrier", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	if err := c.RetireNodeStorage(ctx, "node-gone", "operator", "disk destroyed", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeNodeStorageRetirement(ctx, "node-gone"); err != nil {
		t.Fatal(err)
	}
	// The barrier is what makes this read see the revoke that was committed
	// a moment ago rather than whatever the FSM happened to have applied.
	recs, err := c.AuthoritativeNodeStorageRetirements(ctx)
	if err != nil {
		t.Fatalf("authoritative read: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("read returned %+v after a committed revoke", recs)
	}

	// The peer-facing form answers from the same barriered path.
	resp, err := c.NodeStorageRetirementsForPeerAuthoritative(ctx)
	if err != nil || !resp.Authoritative || len(resp.Retirements) != 0 {
		t.Fatalf("peer authoritative read = %+v err=%v", resp, err)
	}

	// A node that is no longer able to prove leadership must fail closed
	// rather than serve its own FSM.
	if err := c.raft.raft.Shutdown().Error(); err != nil {
		t.Fatalf("shutdown raft: %v", err)
	}
	if _, err := c.AuthoritativeNodeStorageRetirements(ctx); err == nil {
		t.Fatal("a node that cannot prove leadership still answered an authoritative read")
	}
	if _, err := c.NodeStorageRetirementsForPeerAuthoritative(ctx); err == nil {
		t.Fatal("the peer path served an unverified answer")
	}
}

// The barrier makes the read authoritative, but raft gives no way to CANCEL
// one: Barrier's timeout bounds enqueueing the entry, not waiting for the FSM
// to apply it, and neither future wait watches ctx.Done(). A stuck FSM
// therefore holds the caller — the secret-outbox maintenance loop, or a peer
// handler whose client has already gone — for as long as it stays stuck, and
// then answers with a nil error although the deadline has long passed.
func TestAuthoritativeRetirementReadHonoursItsDeadline(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-deadline", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	// Gate the FSM the way a slow apply does: hold its lock, then put an
	// entry in flight so the FSM goroutine is parked inside Apply. Every
	// later entry — including a barrier — queues behind it.
	c.fsm.mu.Lock()
	unlocked := false
	defer func() {
		if !unlocked {
			c.fsm.mu.Unlock()
		}
	}()
	go func() {
		_ = c.RetireNodeStorage(context.Background(), "node-gone", "operator", "disk destroyed", time.Now())
	}()
	// Let the entry reach Apply and block there.
	time.Sleep(300 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := c.AuthoritativeNodeStorageRetirements(ctx)
		done <- err
	}()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		if elapsed > 2*time.Second {
			t.Fatalf("a read with a 50ms deadline returned after %s", elapsed)
		}
		if err == nil {
			t.Fatal("a read whose deadline expired returned success; it must fail closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a read with a 50ms deadline was still blocked after 2s: the caller's deadline does not bound the authority read")
	}

	c.fsm.mu.Unlock()
	unlocked = true
}

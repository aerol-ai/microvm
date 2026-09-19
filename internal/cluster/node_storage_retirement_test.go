package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
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

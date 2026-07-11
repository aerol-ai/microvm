package cluster

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestFSMSnapshotJoinFetchOnMiss pins the one blob-path dependency that must
// outlive the inline-only recovery cleanup
// (plans/remove-legacy-recovery-blob-path.md §2): FSM snapshots carry hot rows
// with a RecoveryRef but NOT the recovery payload itself, so a voter joining
// from a snapshot holds refs it has no local file for. The row-level
// fetch-on-miss resolver (resolveRecoveryRef → recoveryResolver → local
// cache) is its only way to hydrate specs for failover recreate — even in a
// world where every raft command is inline. Deleting it would break failover
// exactly once per joined voter, which no command-level test can catch.
func TestFSMSnapshotJoinFetchOnMiss(t *testing.T) {
	src := newPlacementFSM()
	spec := &models.CreateSandboxRequest{Image: "alpine:3.20", Name: "join-me", CPU: 1, MemoryMB: 512}
	if res := applyOp(t, src, command{
		Op: opPlace, SandboxID: "sb-join", OwnerNodeID: "A", OwnerAPIURL: "http://a",
		Spec: spec, SecretRef: "cluster-secret://sandbox/sb-join/v1", SecretVersion: 1,
	}); res != nil {
		t.Fatalf("place: %v", res)
	}

	snap, err := src.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}
	snapshotBytes := append([]byte(nil), sink.Buffer.Bytes()...)

	// Joining voter: empty local recovery store; the resolver stands in for
	// the HTTP GET half of PublicInternalRecoveryPath serving from a peer.
	joined := newPlacementFSMWithRecoveryStore(newPlacementRecoveryMemoryStore())
	fetches := 0
	joined.recoveryResolver = func(ctx context.Context, ref string) (RecoveryBlob, bool, error) {
		fetches++
		record, ok, err := src.recoveryStore.GetRecord(ref)
		if err != nil || !ok {
			return RecoveryBlob{}, ok, err
		}
		return recoveryBlobFromRecord(ref, record), true, nil
	}
	if err := joined.Restore(io.NopCloser(bytes.NewReader(snapshotBytes))); err != nil {
		t.Fatalf("restore: %v", err)
	}

	got, ok := joined.get("sb-join")
	if !ok {
		t.Fatal("placement missing after snapshot restore")
	}
	if got.Spec == nil || got.Spec.Image != "alpine:3.20" {
		t.Fatalf("Spec after snapshot join = %+v, want fetch-on-miss hydrated alpine:3.20", got.Spec)
	}
	if got.SecretRef != "cluster-secret://sandbox/sb-join/v1" || got.SecretVersion != 1 {
		t.Fatalf("secret handle after snapshot join = (%q, %d), want original", got.SecretRef, got.SecretVersion)
	}
	if fetches == 0 {
		t.Fatal("resolver never fired — test would pass even with the payload in the snapshot, which defeats its purpose")
	}

	// The fetched payload must be cached in the local store: a second read
	// (and every failover recreate after it) must not depend on the peer
	// staying alive.
	fetchesBeforeSecondRead := fetches
	if got2, ok := joined.get("sb-join"); !ok || got2.Spec == nil {
		t.Fatal("second read lost the hydrated payload")
	}
	if fetches != fetchesBeforeSecondRead {
		t.Fatalf("second read re-fetched from peer (fetches %d → %d), want local cache hit", fetchesBeforeSecondRead, fetches)
	}

	// A voter that restores before any peer is reachable (resolver misses)
	// must still restore cleanly: hot fields (Name, owner) intact, payload
	// simply unavailable until the resolver can serve — not an error, not a
	// dropped row.
	late := newPlacementFSMWithRecoveryStore(newPlacementRecoveryMemoryStore())
	if err := late.Restore(io.NopCloser(bytes.NewReader(snapshotBytes))); err != nil {
		t.Fatalf("restore without resolver: %v", err)
	}
	lateRow, ok := late.get("sb-join")
	if !ok {
		t.Fatal("placement missing after resolver-less restore")
	}
	if lateRow.Name != "join-me" || lateRow.OwnerNodeID != "A" {
		t.Fatalf("hot fields after resolver-less restore = (%q, %q), want (join-me, A)", lateRow.Name, lateRow.OwnerNodeID)
	}
	if lateRow.Spec != nil {
		t.Fatal("Spec present without resolver or local file — snapshot is carrying payloads it must not")
	}

	// Once a peer becomes reachable (the realistic join sequence: restore
	// finishes before gossip discovers members), the same row hydrates.
	late.recoveryResolver = func(ctx context.Context, ref string) (RecoveryBlob, bool, error) {
		record, ok, err := src.recoveryStore.GetRecord(ref)
		if err != nil || !ok {
			return RecoveryBlob{}, ok, err
		}
		return recoveryBlobFromRecord(ref, record), true, nil
	}
	if lateRow, ok := late.get("sb-join"); !ok || lateRow.Spec == nil {
		t.Fatal("row did not hydrate after resolver became available")
	}
}

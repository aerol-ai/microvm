package cluster

import (
	"context"
	"errors"
	"testing"
)

func TestFSMCustomHostnamesForSandbox(t *testing.T) {
	fsm := newPlacementFSM()
	if hn := fsm.customHostnamesForSandbox("not-found"); len(hn) != 0 {
		t.Errorf("expected empty hostnames for missing sandbox")
	}

	fsm.placements["sb1"] = Placement{
		CustomHostnames: []string{"test.com", "example.com"},
	}
	hn := fsm.customHostnamesForSandbox("sb1")
	if len(hn) != 2 || hn[0] != "test.com" || hn[1] != "example.com" {
		t.Errorf("unexpected hostnames: %v", hn)
	}

	// Mutating the returned slice shouldn't mutate the underlying FSM slice
	hn[0] = "mutated.com"
	if fsm.placements["sb1"].CustomHostnames[0] == "mutated.com" {
		t.Errorf("returned slice shares memory with fsm state")
	}
}

func TestFSMPagePlacementIDsByScanLocked(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.placements["sb2"] = Placement{}
	fsm.placements["sb1"] = Placement{}
	fsm.placements["sb3"] = Placement{}

	req := PlacementPageRequest{Limit: 2}
	ids := fsm.pagePlacementIDsByScanLocked(req, PlacementShardFilter{}, true, nil)
	if len(ids) != 2 || ids[0] != "sb1" || ids[1] != "sb2" {
		t.Errorf("unexpected pagination results: %v", ids)
	}
}

func TestFSMPagePlacementIDsLockedWithNilBtree(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.placementIDs = nil // force scan
	fsm.placements["sb1"] = Placement{}
	fsm.placements["sb2"] = Placement{}

	ids := fsm.pagePlacementIDsLocked(PlacementPageRequest{Limit: 10}, PlacementShardFilter{}, true, nil)
	if len(ids) != 2 {
		t.Errorf("unexpected ids length: %v", len(ids))
	}
}

func TestFSMPagePlacementIDsLockedWithSmallShards(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.placements["sb1"] = Placement{}
	fsm.shardIndex[0] = map[string]struct{}{"sb1": {}}
	fsm.placementIDs.ReplaceOrInsert("sb1")

	shard := PlacementShardForSandbox("sb1", 16)
	filter := PlacementShardFilter{ShardCount: 16, Shards: []int{shard}}
	want := map[int]struct{}{shard: {}}
	ids := fsm.pagePlacementIDsLocked(PlacementPageRequest{Limit: 10}, filter, false, want)
	if len(ids) != 1 || ids[0] != "sb1" {
		t.Errorf("expected sb1 from shard index lookup, got %v", ids)
	}
}

func TestFSMSnapshotRelease(t *testing.T) {
	s := &fsmSnapshot{}
	s.Release() // should not panic
}

func TestFSMLivePendingReservationCount(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.pendingReservationExpiries = pendingReservationExpiryHeap{
		{SandboxID: "sb1", ExpiresUnix: 100},
		{SandboxID: "sb2", ExpiresUnix: 200},
	}
	fsm.reservedIndex["sb1"] = struct{}{}
	fsm.reservedIndex["sb2"] = struct{}{}
	fsm.pendingReservationIDsByOwner = map[string]map[string]struct{}{
		"node1": {"sb1": {}, "sb2": {}},
	}
	fsm.pendingReservationClaims = map[string]pendingReservationClaim{
		"sb1": {ExpiresUnix: 100},
		"sb2": {ExpiresUnix: 200},
	}

	if c := fsm.livePendingReservationCount("node1", 50); c != 2 {
		t.Errorf("expected 2 live reservations, got %d", c)
	}
	if c := fsm.livePendingReservationCount("node1", 150); c != 1 {
		t.Errorf("expected 1 live reservation, got %d", c)
	}
	if c := fsm.livePendingReservationCount("node1", 250); c != 0 {
		t.Errorf("expected 0 live reservations, got %d", c)
	}
}

func TestFSMResolveRecoveryRef(t *testing.T) {
	fsm := newPlacementFSM()

	// local hit
	fsm.recoveryStore.Put("sb1", placementRecovery{SecretRef: "secret"})
	fsm.mu.Lock()
	for ref := range fsm.recoveryStore.(*placementRecoveryMemoryStore).rows {
		fsm.resolveRecoveryRef(ref)
		break
	}
	fsm.mu.Unlock()

	// remote fallback error
	fsm.recoveryResolver = func(ctx context.Context, ref string) (RecoveryBlob, bool, error) {
		return RecoveryBlob{}, false, errors.New("remote error")
	}
	fsm.mu.Lock()
	_, _, err := fsm.resolveRecoveryRef("unknown-ref")
	fsm.mu.Unlock()
	if err == nil {
		t.Errorf("expected error from remote fallback")
	}
}

func TestFSMValidateHostPortAvailableLocked(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.hostPortIndex[80] = hostPortClaim{SandboxID: "sb1", Port: 80}

	// should succeed for same sandbox
	err := fsm.validateHostPortAvailableLocked("sb1", 80, ExposedPortRoute{Protocol: "tcp", HostPort: 80})
	if err != nil {
		t.Errorf("expected success for same sandbox, got %v", err)
	}

	// should fail for different sandbox
	err = fsm.validateHostPortAvailableLocked("sb2", 80, ExposedPortRoute{Protocol: "tcp", HostPort: 80})
	if err == nil {
		t.Errorf("expected error for different sandbox")
	}
}

func TestFSMClaimCustomHostnameLocked(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.claimCustomHostnameLocked("sb1", "test.com")
	fsm.claimCustomHostnameLocked("sb2", "test.com") // caller canonicalizes

	if fsm.customHostnameIndex["test.com"] != "sb2" {
		t.Errorf("expected sb2 to overwrite test.com claim")
	}
}

func TestFSMStoreRecoveryBlob(t *testing.T) {
	fsm := newPlacementFSM()
	blob, _ := newRecoveryBlob("sb1", placementRecovery{SecretRef: "sr"})
	err := fsm.storeRecoveryBlob(blob)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	badBlob, _ := newRecoveryBlob("", placementRecovery{})
	err = fsm.storeRecoveryBlob(badBlob)
	if err == nil {
		t.Errorf("expected error for empty sandbox id")
	}
}

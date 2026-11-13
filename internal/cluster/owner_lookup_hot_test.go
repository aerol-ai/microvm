package cluster

import (
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// countingRecoveryStore counts reads of recovery payloads.
type countingRecoveryStore struct {
	placementRecoveryStore
	gets int
}

func (s *countingRecoveryStore) Get(ref string) (placementRecovery, bool, error) {
	s.gets++
	return s.placementRecoveryStore.Get(ref)
}

// F30: an owner lookup reads the hot row only. Before, it hydrated the
// sandbox's spec and secrets from the recovery store, a disk read for every
// lookup that missed the cache, though a lookup needs only the owner.
func TestOwnerLookupsReadNoRecoveryPayload(t *testing.T) {
	store := &countingRecoveryStore{placementRecoveryStore: newPlacementRecoveryMemoryStore()}
	f := newPlacementFSMWithRecoveryStore(store)
	spec := &models.CreateSandboxRequest{Image: "alpine:3.20", Name: "hot", CPU: 1, MemoryMB: 512}
	if res := applyOp(t, f, command{Op: opPlace, SandboxID: "sb-hot", OwnerNodeID: "A", OwnerAPIURL: "http://a", Spec: spec, IncarnationID: "inc-hot"}); res != nil {
		t.Fatalf("place: %v", res)
	}
	if p, _ := f.get("sb-hot"); p.Spec == nil || p.Spec.Image != "alpine:3.20" {
		t.Fatalf("the full row lost its spec: %+v", p.Spec)
	}
	store.gets = 0
	c := &Cluster{fsm: f, nodeID: "A"}
	owner, err := c.OwnerOf("sb-hot")
	if err != nil || owner.NodeID != "A" || owner.APIURL != "http://a" || !owner.IsSelf {
		t.Fatalf("OwnerOf = %+v, %v", owner, err)
	}
	if inc, ok, err := c.currentPlacementIncarnation("sb-hot"); err != nil || !ok || inc != "inc-hot" {
		t.Fatalf("incarnation = %q %v %v", inc, ok, err)
	}
	if store.gets != 0 {
		t.Fatalf("owner lookups read %d recovery payloads, want 0", store.gets)
	}
	if _, err := c.OwnerOf("sb-none"); err != ErrUnknownSandbox {
		t.Fatalf("an unknown sandbox = %v", err)
	}
	if p, ok := f.getHot("sb-hot"); !ok || p.Spec != nil || p.OwnerNodeID != "A" || p.IncarnationID != "inc-hot" {
		t.Fatalf("hot row = %+v %v", p, ok)
	}
}

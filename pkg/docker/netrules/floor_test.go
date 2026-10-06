package netrules

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// floorMemBackend adds the floor chain operations to memBackend.
type floorMemBackend struct {
	memBackend
	jumps   []string
	flushes int
	jumpErr error
}

func (f *floorMemBackend) EnsureJumpChain(parent, child string) error {
	if f.jumpErr != nil {
		return f.jumpErr
	}
	f.jumps = append(f.jumps, parent+"->"+child)
	return nil
}

func (f *floorMemBackend) FlushChain(chain string) error {
	f.flushes++
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.rules[:0]
	for _, r := range f.rules {
		if !strings.HasPrefix(r, "filter|"+chain+"|") {
			kept = append(kept, r)
		}
	}
	f.rules = kept
	return nil
}

// TestSetFloor (§5.10 PC-2): the floor is a whole-chain replace under a jump
// from the top of the user chain; an empty list clears it; IPv6 entries
// are skipped; a backend without chain management says so.
func TestSetFloor(t *testing.T) {
	be := &floorMemBackend{}
	m := NewWithBackend(be)
	subnet := netip.MustParsePrefix("172.17.0.0/16")
	floor := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd00::/8"), netip.MustParsePrefix("192.168.7.9/24")}
	if err := m.SetFloor(subnet, floor); err != nil {
		t.Fatal(err)
	}
	if be.jumps[0] != ChainDockerUser+"->"+ChainAerolvmFloor || be.flushes != 1 {
		t.Fatalf("jumps=%v flushes=%d", be.jumps, be.flushes)
	}
	if be.countMatching(ChainAerolvmFloor) != 2 || be.countMatching("192.168.7.0/24") != 1 {
		t.Fatalf("floor rules = %v", be.rules)
	}
	if err := m.SetFloor(subnet, nil); err != nil || be.countMatching(ChainAerolvmFloor) != 0 {
		t.Fatalf("clearing the floor: %v %v", err, be.rules)
	}
	be.jumpErr = errors.New("boom")
	if err := m.SetFloor(subnet, floor); err == nil {
		t.Fatal("chain errors surface")
	}
	if err := NewWithBackend(&memBackend{}).SetFloor(subnet, floor); !errors.Is(err, ErrFloorUnsupported) {
		t.Fatalf("plain backend: %v", err)
	}
	if err := m.SetFloor(netip.Prefix{}, floor); err != nil {
		t.Fatal("no subnet is a no-op")
	}
	var disabled *Manager
	if err := disabled.SetFloor(subnet, floor); err != nil || disabled.BridgeSubnet().IsValid() {
		t.Fatal("nil manager")
	}
	m.SetBridgeSubnet("10.88.3.0/16")
	if m.BridgeSubnet() != netip.MustParsePrefix("10.88.0.0/16") {
		t.Fatalf("bridge subnet = %v", m.BridgeSubnet())
	}
}

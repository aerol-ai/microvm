package netrules

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
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
	// The listed IPv4 ranges, and the subnet to itself: sandboxes are
	// isolated from each other by default.
	if be.countMatching(ChainAerolvmFloor) != 3 || be.countMatching("192.168.7.0/24") != 1 || be.countMatching("-d|172.17.0.0/16") != 1 {
		t.Fatalf("floor rules = %v", be.rules)
	}
	if err := m.SetFloor(subnet, nil); err != nil || be.countMatching(ChainAerolvmFloor) != 1 {
		t.Fatalf("clearing the operator's floor keeps the isolation rule: %v %v", err, be.rules)
	}
	SetSandboxInterconnect(true)
	if err := m.SetFloor(subnet, nil); err != nil || be.countMatching(ChainAerolvmFloor) != 0 {
		t.Fatalf("SB_SANDBOX_INTERCONNECT=true drops the isolation rule: %v %v", err, be.rules)
	}
	SetSandboxInterconnect(false)
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

// orderedBackend keeps each chain's rules in order and honours insert
// positions, so a test can see what a packet meets first.
type orderedBackend struct {
	mu     sync.Mutex
	chains map[string][]string
}

func (o *orderedBackend) key(spec []string) string { return strings.Join(spec, " ") }

func (o *orderedBackend) Exists(_, chain string, spec ...string) (bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Contains(o.chains[chain], o.key(spec)), nil
}

func (o *orderedBackend) Insert(_, chain string, pos int, spec ...string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	c := o.chains[chain]
	i := pos - 1
	if i > len(c) {
		i = len(c)
	}
	o.chains[chain] = slices.Insert(c, i, o.key(spec))
	return nil
}

func (o *orderedBackend) Delete(_, chain string, spec ...string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	c := o.chains[chain]
	if i := slices.Index(c, o.key(spec)); i >= 0 {
		o.chains[chain] = slices.Delete(c, i, i+1)
		return nil
	}
	return errNoMatch{}
}

// EnsureJumpChain is the netlink backend's contract: the jump is first, any
// lower one removed in the same step.
func (o *orderedBackend) EnsureJumpChain(parent, child string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	jump := "-j " + child
	c := slices.DeleteFunc(slices.Clone(o.chains[parent]), func(r string) bool { return r == jump })
	o.chains[parent] = slices.Insert(c, 0, jump)
	return nil
}

func (o *orderedBackend) FlushChain(chain string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.chains[chain] = nil
	return nil
}

func (o *orderedBackend) EnsureUserChain(string) error   { return nil }
func (o *orderedBackend) EnsureForwardJump(string) error { return nil }
func (o *orderedBackend) EnsureInputChain(string) error  { return nil }

func (o *orderedBackend) first(chain string) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.chains[chain]) == 0 {
		return ""
	}
	return o.chains[chain][0]
}

// TestFloorJumpStaysFirst: a packet meets the floor before any per-sandbox
// rule, so no sandbox gets past it by putting a floor address (or
// 0.0.0.0/0) in its allowlist: not one created before the floor went in,
// not one created after, not across a chain an older daemon filled with
// the jump lower down, and not after the chain was flushed and re-asserted.
func TestFloorJumpStaysFirst(t *testing.T) {
	be := &orderedBackend{chains: map[string][]string{}}
	m := NewWithBackend(be)
	m.SetBridgeSubnet("10.88.0.0/16")
	chain := m.filterChain()
	jump := "-j " + ChainAerolvmFloor
	subnet := netip.MustParsePrefix("10.88.0.0/16")
	floor := []netip.Prefix{netip.MustParsePrefix("169.254.169.254/32")}

	// Before the floor: a wide-open allowlist and a bridge accept.
	if err := m.ApplyEgressPolicy("10.88.0.5", []string{"0.0.0.0/0"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.ensureBridgeForwardAccept(); err != nil {
		t.Fatal(err)
	}
	// An older daemon's chain: the jump is there, but under those rules.
	be.chains[chain] = append(be.chains[chain], jump)
	if err := m.SetFloor(subnet, floor); err != nil {
		t.Fatal(err)
	}
	if be.first(chain) != jump || strings.Count(strings.Join(be.chains[chain], "\n"), jump) != 1 {
		t.Fatalf("after SetFloor the chain is %q", be.chains[chain])
	}
	// After the floor: every kind of rule lands below the jump.
	if err := m.ApplyEgressPolicy("10.88.0.6", []string{"169.254.169.254/32"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyEgressPolicy("10.88.0.7", []string{"0.0.0.0/0"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if err := m.BlockAllEgress("10.88.0.8"); err != nil {
		t.Fatal(err)
	}
	if err := m.BlockAllIngress("10.88.0.8"); err != nil {
		t.Fatal(err)
	}
	if be.first(chain) != jump {
		t.Fatalf("a per-sandbox rule went above the floor: %q", be.chains[chain])
	}
	// A flushed chain gets the jump back on top when it is re-asserted.
	be.chains[chain] = []string{"-s 10.88.0.0/16 -j ACCEPT"}
	if err := m.ReassertChain(); err != nil {
		t.Fatal(err)
	}
	if be.first(chain) != jump {
		t.Fatalf("after a flush and re-assert the chain is %q", be.chains[chain])
	}
	// Without a floor nothing changes: rules still go on top.
	plain := NewWithBackend(&orderedBackend{chains: map[string][]string{}})
	if plain.topPos() != 1 {
		t.Fatal("no floor: rules go on top")
	}
}

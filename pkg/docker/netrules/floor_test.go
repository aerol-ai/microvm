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
	ResetFloorsForTest()
	t.Cleanup(ResetFloorsForTest)
	be := &floorMemBackend{}
	m := NewWithBackend(be)
	subnet := netip.MustParsePrefix("172.17.0.0/16")
	floor := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd00::/8"), netip.MustParsePrefix("192.168.7.9/24")}
	if err := m.SetFloor(subnet, floor); err != nil {
		t.Fatal(err)
	}
	own := FloorChainFor(subnet)
	// Its own chain, plus the legacy shared one emptied once.
	if be.jumps[0] != ChainDockerUser+"->"+own || be.flushes != 2 {
		t.Fatalf("jumps=%v flushes=%d", be.jumps, be.flushes)
	}
	// The listed IPv4 ranges, and the subnet to itself: sandboxes are
	// isolated from each other by default.
	if be.countMatching(own) != 3 || be.countMatching("192.168.7.0/24") != 1 || be.countMatching("-d|172.17.0.0/16") != 1 {
		t.Fatalf("floor rules = %v", be.rules)
	}
	if err := m.SetFloor(subnet, nil); err != nil || be.countMatching(own) != 1 || be.flushes != 3 {
		t.Fatalf("clearing the operator's floor keeps the isolation rule: %v %v", err, be.rules)
	}
	SetSandboxInterconnect(true)
	if err := m.SetFloor(subnet, nil); err != nil || be.countMatching(own) != 0 {
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

// existsErrBackend fails rule checks, as a lost netlink socket would.
type existsErrBackend struct {
	*floorMemBackend
	err error
}

func (e *existsErrBackend) Exists(table, chain string, spec ...string) (bool, error) {
	if e.err != nil {
		return false, e.err
	}
	return e.floorMemBackend.Exists(table, chain, spec...)
}

// TestReassertFloor: the re-assert only checks a floor in place (no flush,
// no empty moment), rewrites it when a rule or the whole chain is gone, and
// reports errors rather than a floor it could not check.
func TestReassertFloor(t *testing.T) {
	subnet := netip.MustParsePrefix("172.17.0.0/16")
	imds := []netip.Prefix{netip.MustParsePrefix("169.254.169.254/32"), netip.MustParsePrefix("10.20.0.0/16")}
	chain := FloorChainFor(subnet)
	imdsDrop := memKey("filter", chain, floorDropSpec(subnet.String(), "169.254.169.254/32")...)
	cases := []struct {
		name         string
		damage       func(be *existsErrBackend)
		wantRepaired bool
		wantErr      bool
		wantFlushes  int // flushes the re-assert itself did
	}{
		{name: "whole: checked, not rewritten"},
		{name: "a DROP removed", damage: func(be *existsErrBackend) {
			be.mu.Lock()
			defer be.mu.Unlock()
			be.rules = slices.DeleteFunc(be.rules, func(r string) bool { return r == imdsDrop })
		}, wantRepaired: true, wantFlushes: 1},
		{name: "chain flushed", damage: func(be *existsErrBackend) { _ = be.FlushChain(chain) }, wantRepaired: true, wantFlushes: 1},
		{name: "jump cannot be put back", damage: func(be *existsErrBackend) { be.jumpErr = errors.New("chain gone") }, wantErr: true},
		{name: "rules cannot be checked", damage: func(be *existsErrBackend) { be.err = errors.New("netlink: socket closed") }, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ResetFloorsForTest()
			t.Cleanup(ResetFloorsForTest)
			be := &existsErrBackend{floorMemBackend: &floorMemBackend{}}
			m := NewWithBackend(be)
			if err := m.SetFloor(subnet, imds); err != nil {
				t.Fatal(err)
			}
			if tc.damage != nil {
				tc.damage(be)
			}
			flushes := be.flushes
			repaired, err := m.ReassertFloor()
			if repaired != tc.wantRepaired || (err != nil) != tc.wantErr {
				t.Fatalf("repaired=%v err=%v", repaired, err)
			}
			if got := be.flushes - flushes; got != tc.wantFlushes {
				t.Fatalf("the re-assert flushed %d times, want %d", got, tc.wantFlushes)
			}
			if !tc.wantErr && be.countMatching(chain) != 3 {
				t.Fatalf("floor after the re-assert: %v", be.rules)
			}
		})
	}

	// Nothing to re-assert: no manager, network rules off, or no floor set.
	ResetFloorsForTest()
	t.Cleanup(ResetFloorsForTest)
	var none *Manager
	disabled, err := New(false)
	if err != nil {
		t.Fatal(err)
	}
	be := &floorMemBackend{}
	for name, m := range map[string]*Manager{"nil": none, "disabled": disabled, "no floor yet": NewWithBackend(be)} {
		if repaired, err := m.ReassertFloor(); repaired || err != nil || len(be.jumps) != 0 {
			t.Fatalf("%s: repaired=%v err=%v jumps=%v", name, repaired, err, be.jumps)
		}
	}
	// A registry reset under a manager that had a floor: nothing to check.
	m := NewWithBackend(be)
	if err := m.SetFloor(subnet, imds); err != nil {
		t.Fatal(err)
	}
	ResetFloorsForTest()
	if repaired, err := m.ReassertFloor(); repaired || err != nil {
		t.Fatalf("forgotten floor: %v %v", repaired, err)
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
	ResetFloorsForTest()
	t.Cleanup(ResetFloorsForTest)
	be := &orderedBackend{chains: map[string][]string{}}
	m := NewWithBackend(be)
	m.SetBridgeSubnet("10.88.0.0/16")
	chain := m.filterChain()
	subnet := netip.MustParsePrefix("10.88.0.0/16")
	jump := "-j " + FloorChainFor(subnet)
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

// TestFloorsOfTwoRuntimesCoexist: docker, containerd and Firecracker each
// floor their own subnet from their own user chain. When they shared one
// floor chain, each SetFloor flushed it and only the last subnet kept a
// floor: on a node running containers and Firecracker guests, the other
// runtime's sandboxes lost the metadata, deny_cidrs and isolation drops.
func TestFloorsOfTwoRuntimesCoexist(t *testing.T) {
	ResetFloorsForTest()
	t.Cleanup(ResetFloorsForTest)
	be := &floorMemBackend{}
	containers := NewWithBackend(be)
	guests := NewWithBackend(be)
	guests.userChain = ChainAerolvmFC
	bridge := netip.MustParsePrefix("10.88.0.0/16")
	taps := netip.MustParsePrefix("172.16.0.0/16")
	imds := []netip.Prefix{netip.MustParsePrefix("169.254.169.254/32")}
	if FloorChainFor(bridge) == FloorChainFor(taps) || len(FloorChainFor(bridge)) > 28 {
		t.Fatalf("floor chains %q and %q must differ and fit iptables' 28 characters", FloorChainFor(bridge), FloorChainFor(taps))
	}
	if err := containers.SetFloor(bridge, imds); err != nil {
		t.Fatal(err)
	}
	if err := guests.SetFloor(taps, imds); err != nil {
		t.Fatal(err)
	}
	// Replacing one (an operator file change, a re-assert) leaves the other.
	if err := containers.SetFloor(bridge, imds); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"filter|" + FloorChainFor(bridge) + "|-s|10.88.0.0/16|-d|169.254.169.254/32|-j|DROP",
		"filter|" + FloorChainFor(taps) + "|-s|172.16.0.0/16|-d|169.254.169.254/32|-j|DROP",
		"filter|" + FloorChainFor(taps) + "|-s|172.16.0.0/16|-d|172.16.0.0/16|-j|DROP",
	} {
		if !slices.Contains(be.rules, want) {
			t.Errorf("missing %s in %v", want, be.rules)
		}
	}
	if !slices.Contains(be.jumps, ChainAerolvmFC+"->"+FloorChainFor(taps)) || !slices.Contains(be.jumps, ChainDockerUser+"->"+FloorChainFor(bridge)) {
		t.Fatalf("each runtime's chain jumps to its own floor: %v", be.jumps)
	}
}

// TestFloorsDropAcrossRuntimes: with interconnect off, a Firecracker guest
// cannot open a connection to a container sandbox on the same node, nor a
// container to a guest. Each floor drops its subnet to every sandbox subnet
// on the node, whichever runtime set its floor first. Found live: a guest on
// cluster-bank-flagship reached a container's toolbox agent (UC-339).
func TestFloorsDropAcrossRuntimes(t *testing.T) {
	bridge := netip.MustParsePrefix("10.88.0.0/16")
	taps := netip.MustParsePrefix("172.16.0.0/16")
	drop := func(from, to netip.Prefix) string {
		return "filter|" + FloorChainFor(from) + "|-s|" + from.String() + "|-d|" + to.String() + "|-j|DROP"
	}
	for _, order := range []string{"containers first", "guests first"} {
		t.Run(order, func(t *testing.T) {
			ResetFloorsForTest()
			t.Cleanup(ResetFloorsForTest)
			be := &floorMemBackend{}
			containers := NewWithBackend(be)
			containers.userChain = ChainAerolvmUser
			guests := NewWithBackend(be)
			guests.userChain = ChainAerolvmFC
			first, firstNet, second, secondNet := containers, bridge, guests, taps
			if order == "guests first" {
				first, firstNet, second, secondNet = guests, taps, containers, bridge
			}
			if err := first.SetFloor(firstNet, nil); err != nil {
				t.Fatal(err)
			}
			if err := second.SetFloor(secondNet, nil); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{drop(bridge, taps), drop(bridge, bridge), drop(taps, bridge), drop(taps, taps)} {
				if !slices.Contains(be.rules, want) {
					t.Errorf("missing %s in %v", want, be.rules)
				}
			}
			// An operator-file change re-renders one floor; the other keeps
			// its drop to the first's subnet.
			if err := containers.SetFloor(bridge, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(be.rules, drop(taps, bridge)) || !slices.Contains(be.rules, drop(bridge, taps)) {
				t.Fatalf("a re-render dropped the cross-runtime rules: %v", be.rules)
			}
		})
	}
	t.Run("interconnect on", func(t *testing.T) {
		ResetFloorsForTest()
		t.Cleanup(ResetFloorsForTest)
		SetSandboxInterconnect(true)
		t.Cleanup(func() { SetSandboxInterconnect(false) })
		be := &floorMemBackend{}
		containers := NewWithBackend(be)
		guests := NewWithBackend(be)
		guests.userChain = ChainAerolvmFC
		if err := containers.SetFloor(bridge, nil); err != nil {
			t.Fatal(err)
		}
		if err := guests.SetFloor(taps, nil); err != nil {
			t.Fatal(err)
		}
		if len(be.rules) != 0 {
			t.Fatalf("SB_SANDBOX_INTERCONNECT=true keeps no subnet drops, got %v", be.rules)
		}
	})
}

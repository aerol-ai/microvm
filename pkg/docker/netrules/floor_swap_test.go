package netrules

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// watchedBackend checks, after every rule operation, that a packet from
// the subnet to the metadata endpoint still meets a DROP: the user chain's
// first rule jumps to a floor chain that holds it.
type watchedBackend struct {
	*orderedBackend
	user, drop string
	armed      bool
	open       int // operations after which the endpoint was reachable
}

func (w *watchedBackend) check() {
	if !w.armed {
		return
	}
	first := w.first(w.user)
	floor, ok := strings.CutPrefix(first, "-j ")
	w.mu.Lock()
	defer w.mu.Unlock()
	if !ok || !containsRule(w.chains[floor], w.drop) {
		w.open++
	}
}

func containsRule(rules []string, r string) bool {
	for _, x := range rules {
		if x == r {
			return true
		}
	}
	return false
}

func (w *watchedBackend) Insert(table, chain string, pos int, spec ...string) error {
	err := w.orderedBackend.Insert(table, chain, pos, spec...)
	w.check()
	return err
}

func (w *watchedBackend) Delete(table, chain string, spec ...string) error {
	err := w.orderedBackend.Delete(table, chain, spec...)
	w.check()
	return err
}

func (w *watchedBackend) EnsureJumpChain(parent, child string) error {
	err := w.orderedBackend.EnsureJumpChain(parent, child)
	w.check()
	return err
}

func (w *watchedBackend) FlushChain(chain string) error {
	err := w.orderedBackend.FlushChain(chain)
	w.check()
	return err
}

// TestFloorReplaceNeverOpensMetadata (PR 5 review, R7): replacing a floor
// used to flush its chain and refill it, so while a long list went in the
// metadata endpoint was reachable. Now the new floor is filled in the
// other chain and the jump moved: from the first floor on, no operation
// leaves the endpoint reachable, through any number of replaces, and the
// user chain keeps exactly one jump to a floor.
func TestFloorReplaceNeverOpensMetadata(t *testing.T) {
	ResetFloorsForTest()
	t.Cleanup(ResetFloorsForTest)
	subnet := netip.MustParsePrefix("10.88.0.0/16")
	be := &watchedBackend{orderedBackend: &orderedBackend{chains: map[string][]string{}},
		drop: strings.Join(floorDropSpec(subnet.String(), "169.254.169.254/32"), " ")}
	m := NewWithBackend(be)
	be.user = m.filterChain()
	imds := netip.MustParsePrefix("169.254.169.254/32")
	list := func(n, base int) []netip.Prefix {
		out := []netip.Prefix{}
		for i := range n {
			out = append(out, netip.MustParsePrefix(fmt.Sprintf("%d.%d.%d.0/24", base, i/256, i%256)))
		}
		return append(out, imds)
	}
	if err := m.SetFloor(subnet, list(64, 11)); err != nil {
		t.Fatal(err)
	}
	be.armed = true
	for i := range 6 {
		if err := m.SetFloor(subnet, list(64, 12+i%2)); err != nil {
			t.Fatal(err)
		}
	}
	if be.open != 0 {
		t.Fatalf("the metadata endpoint was reachable after %d rule operations while the floor was replaced", be.open)
	}
	jumps := 0
	for _, r := range be.chains[be.user] {
		if strings.HasPrefix(r, "-j "+ChainAerolvmFloor+"-") {
			jumps++
		}
	}
	if jumps != 1 {
		t.Fatalf("the user chain holds %d floor jumps: %q", jumps, be.chains[be.user])
	}
	// The chain not in use is empty: a replace leaves nothing behind.
	active, _ := m.floorChain.Load().(string)
	for _, c := range []string{FloorChainFor(subnet), floorSlotB(FloorChainFor(subnet))} {
		if c != active && len(be.chains[c]) != 0 {
			t.Fatalf("the spare chain %s holds %d rules", c, len(be.chains[c]))
		}
	}
}

// TestFloorFoundAfterARestart: a manager that starts on a kernel an
// earlier process filled (the other chain in use) replaces into the spare
// chain, and no jump to the old chain is left.
func TestFloorFoundAfterARestart(t *testing.T) {
	ResetFloorsForTest()
	t.Cleanup(ResetFloorsForTest)
	subnet := netip.MustParsePrefix("10.88.0.0/16")
	be := &orderedBackend{chains: map[string][]string{}}
	first := NewWithBackend(be)
	for range 2 { // the second replace leaves slot B in use
		if err := first.SetFloor(subnet, nil); err != nil {
			t.Fatal(err)
		}
	}
	ResetFloorsForTest()
	second := NewWithBackend(be)
	if err := second.SetFloor(subnet, nil); err != nil {
		t.Fatal(err)
	}
	user := second.filterChain()
	if be.first(user) != "-j "+FloorChainFor(subnet) || containsRule(be.chains[user], "-j "+floorSlotB(FloorChainFor(subnet))) {
		t.Fatalf("after a restart the user chain is %q", be.chains[user])
	}
}

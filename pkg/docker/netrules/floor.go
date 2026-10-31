package netrules

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
)

// ChainAerolvmFloor names the deny floor (plans/egress-domain-filtering.md
// §5.10 PC-2): DROPs from a sandbox subnet to each floor address, jumped
// from the top of the user chain so they sit above every per-sandbox ACCEPT.
// A chain of its own because the floor is replaced as a whole when the
// operator file changes, and the rule backends cannot list rules to find
// the old ones.
//
// Each sandbox subnet gets its own chain, FloorChainFor(subnet). Docker,
// containerd and Firecracker each floor their own subnet from their own
// user chain; when they shared this one chain, every SetFloor flushed it,
// and on a node running more than one of them only the last subnet kept a
// floor. This name is now only the legacy chain an older daemon filled,
// emptied at the first floor so its leftover jump is a no-op.
const ChainAerolvmFloor = "AEROLVM-FLOOR"

// FloorChainFor is the floor chain for one sandbox subnet: the prefix plus
// eight hex digits of the subnet's hash, 22 characters, inside iptables'
// 28-character chain-name limit.
func FloorChainFor(subnet netip.Prefix) string {
	sum := sha256.Sum256([]byte(subnet.Masked().String()))
	return ChainAerolvmFloor + "-" + hex.EncodeToString(sum[:4])
}

// floorBackend is the optional chain management the floor needs.
type floorBackend interface {
	// EnsureJumpChain creates child if absent and makes the first rule of
	// parent a jump to it: a jump already there but lower down (a chain an
	// older daemon filled) moves to the top, with no moment without one.
	EnsureJumpChain(parent, child string) error
	// FlushChain removes every rule in chain.
	FlushChain(chain string) error
}

// ErrFloorUnsupported means the rule backend cannot manage the floor chain.
var ErrFloorUnsupported = errors.New("netrules: backend cannot manage the egress floor chain")

var floorMu sync.Mutex

// floorEntry is one runtime's floor: the manager whose user chain jumps to
// it, its sandbox subnet and the operator's floor addresses.
type floorEntry struct {
	m      *Manager
	fb     floorBackend
	subnet netip.Prefix
	cidrs  []netip.Prefix
}

// floors are every runtime's floor on this node, by chain. Each runtime knows
// only its own subnet, but with sandbox interconnect off a floor must drop
// traffic from its subnet to every sandbox subnet on the node: a per-subnet
// self-drop alone let a Firecracker guest open a connection to a container
// sandbox on the same node (bank-readiness UC-339 on cluster-bank-flagship).
// Guarded by floorMu.
var floors = map[string]*floorEntry{}

// ResetFloorsForTest forgets every registered floor. Test-only seam: the
// registry is process-wide, as a node's runtimes share one process.
func ResetFloorsForTest() {
	floorMu.Lock()
	defer floorMu.Unlock()
	floors = map[string]*floorEntry{}
}

// allowInterconnect lets sandboxes on one node reach each other
// (SB_SANDBOX_INTERCONNECT). Off by default: the floor also drops traffic
// from the sandbox subnet to the sandbox subnet, so one tenant's sandbox
// cannot connect to another's listeners. Traffic to the host's bridge
// address is input, not forward, so the toolbox and DNS are unaffected.
var allowInterconnect atomic.Bool

// SetSandboxInterconnect sets whether sandboxes on one node may connect to
// each other; the daemon sets it from config before the first floor.
func SetSandboxInterconnect(allow bool) { allowInterconnect.Store(allow) }

// SetFloor replaces the node-wide deny floor for sandboxes on subnet. An
// empty cidrs list clears the operator's part. The flush and refill are
// separate steps, so the floor is briefly empty while it is replaced; the
// egress gateway's own copy of the floor (its deny_floor set) stays in
// place throughout. A subnet seen for the first time also re-renders every
// other runtime's floor, so each drops traffic to it.
func (m *Manager) SetFloor(subnet netip.Prefix, cidrs []netip.Prefix) error {
	if !m.Enabled() || !subnet.IsValid() {
		return nil
	}
	fb, ok := m.ipt.(floorBackend)
	if !ok {
		return ErrFloorUnsupported
	}
	floorMu.Lock()
	defer floorMu.Unlock()
	chain := FloorChainFor(subnet)
	_, known := floors[chain]
	floors[chain] = &floorEntry{m: m, fb: fb, subnet: subnet.Masked(), cidrs: append([]netip.Prefix(nil), cidrs...)}
	if err := renderFloor(chain, floors[chain]); err != nil {
		return err
	}
	if known {
		return nil
	}
	others := make([]string, 0, len(floors))
	for other := range floors {
		if other != chain {
			others = append(others, other)
		}
	}
	sort.Strings(others)
	for _, other := range others {
		if err := renderFloor(other, floors[other]); err != nil {
			return fmt.Errorf("egress floor for %s after %s joined: %w", floors[other].subnet, subnet.Masked(), err)
		}
	}
	return nil
}

// renderFloor writes one floor chain: its manager's user chain jumps to it
// first, then DROPs from its subnet to each operator floor address and,
// with interconnect off, to every sandbox subnet registered on the node
// (its own included). Caller holds floorMu.
func renderFloor(chain string, e *floorEntry) error {
	m, fb := e.m, e.fb
	// Before the jump goes in: a rule inserted from here on lands below it.
	m.floorChain.Store(chain)
	m.floorFirst.Store(true)
	if err := fb.EnsureJumpChain(m.filterChain(), chain); err != nil {
		return fmt.Errorf("egress floor chain: %w", err)
	}
	if err := fb.FlushChain(chain); err != nil {
		return fmt.Errorf("flush egress floor: %w", err)
	}
	// The shared chain an older daemon filled: nothing writes it any more,
	// so emptying it cannot remove a floor this daemon installed. Absent on
	// a node that never ran one, which is not an error.
	if !m.legacyFloorEmptied.Swap(true) {
		_ = fb.FlushChain(ChainAerolvmFloor)
	}
	dsts := append([]netip.Prefix(nil), e.cidrs...)
	if !allowInterconnect.Load() {
		subnets := make([]netip.Prefix, 0, len(floors))
		for _, other := range floors {
			subnets = append(subnets, other.subnet)
		}
		sort.Slice(subnets, func(i, j int) bool { return subnets[i].String() < subnets[j].String() })
		dsts = append(dsts, subnets...)
	}
	src := e.subnet.String()
	seen := map[string]bool{}
	for _, c := range dsts {
		if !c.Addr().Is4() {
			continue
		}
		dst := c.Masked().String()
		if seen[dst] {
			continue
		}
		seen[dst] = true
		if err := m.ipt.Insert("filter", chain, 1, "-s", src, "-d", dst, "-j", "DROP"); err != nil {
			return fmt.Errorf("egress floor rule %s: %w", c, err)
		}
	}
	return nil
}

// BridgeSubnet returns the subnet set by SetBridgeSubnet (the containerd
// CNI bridge), or the zero prefix.
func (m *Manager) BridgeSubnet() netip.Prefix {
	if m == nil {
		return netip.Prefix{}
	}
	p, err := netip.ParsePrefix(m.bridgeSubnet)
	if err != nil {
		return netip.Prefix{}
	}
	return p.Masked()
}

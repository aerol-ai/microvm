package netrules

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
)

// ChainAerolvmFloor holds the operator's node-wide deny floor
// (plans/egress-domain-filtering.md §5.10 PC-2): DROPs from the sandbox
// bridge subnet to each deny_cidrs entry, jumped from the top of the user
// chain so they sit above every per-sandbox ACCEPT. A chain of its own
// because the floor is replaced as a whole when the operator file changes,
// and the rule backends cannot list rules to find the old ones.
const ChainAerolvmFloor = "AEROLVM-FLOOR"

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
// empty cidrs list clears it. The flush and refill are separate steps, so
// the floor is briefly empty while it is replaced; the egress gateway's own
// copy of the floor (its deny_floor set) stays in place throughout.
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
	// Before the jump goes in: a rule inserted from here on lands below it.
	m.floorFirst.Store(true)
	if err := fb.EnsureJumpChain(m.filterChain(), ChainAerolvmFloor); err != nil {
		return fmt.Errorf("egress floor chain: %w", err)
	}
	if err := fb.FlushChain(ChainAerolvmFloor); err != nil {
		return fmt.Errorf("flush egress floor: %w", err)
	}
	src := subnet.Masked().String()
	if !allowInterconnect.Load() {
		cidrs = append(append([]netip.Prefix(nil), cidrs...), subnet.Masked())
	}
	for _, c := range cidrs {
		if !c.Addr().Is4() {
			continue
		}
		if err := m.ipt.Insert("filter", ChainAerolvmFloor, 1, "-s", src, "-d", c.Masked().String(), "-j", "DROP"); err != nil {
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

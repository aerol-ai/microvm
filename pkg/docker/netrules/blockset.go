package netrules

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Block-all as set membership.
//
// A block-all used to be a per-address rule pair: `-s IP -j DROP` at the top
// of the user chain and an `sbx-input-block` drop in AEROLVM-INPUT. Lifting
// it (the last step of a hostname-filtered create, the egress gateway
// attach) deleted that pair, and on a 6.x kernel every nf_tables commit that
// deletes anything waits about one RCU grace period (5.7 ms measured on a
// bank flagship worker, 4 vCPU, kernel 6.8), on top of reading the chains to
// find the rules (6 ms at 300 restricted neighbours). Inserting the pair
// waited too, for the destructors of recent deletes (its xt comment match).
//
// Now a block-all is membership in two sets of the table `ip aerolvm_block`,
// whose forward and input base chains drop `ip saddr @blocked ip saddr !=
// @released` (input lets established and related replies through first, as
// AEROLVM-INPUT did, so sandboxd still reaches toolboxd):
//
//   - Block adds the address to @blocked: one element add, no rule, no
//     listing, no grace period. If @released holds the address, the same
//     transaction deletes it there first, so a release left behind (a
//     sandbox that held this address before) never opens a new owner.
//   - Lift, the create path's unblock, adds the address to @released: an
//     add again. The address stays in @blocked.
//   - Forget, when an address is let go (destroy, a failed create, a stop),
//     deletes it from @released and then from @blocked in one transaction.
//     That is where the grace period is paid now, off the create path.
//
// The table is its own, not rules in the iptables-nft chains, so `iptables
// -S` and the tooling around it keep their meaning; a drop in any base chain
// on a hook drops the packet, whatever the other tables say.
//
// What is in the sets is mirrored here, process-wide (every Manager writes
// the same two sets; their addresses never overlap): Block and Forget need
// to know whether to delete, as deleting an absent element fails the whole
// transaction. The mirror is read from the kernel when the sets are
// prepared at boot, so a sandboxd restart sees what it left (a create
// killed between its block and its release stays blocked; a stale release
// is known, and the next Block of that address deletes it). After an
// operation fails the address's entry is no longer trusted and the next
// operation on it reads the kernel first. If the table disappears (a
// ruleset flush), the next operation recreates it and puts the mirror back;
// a reboot leaves nothing running, and every create and start blocks again.
//
// Managers whose backend can't hold sets (the exec backend), or whose
// PrepareBlockSets failed, keep the per-address rules. For one release a
// manager also converts the per-address block rules an older daemon left
// (PrepareBlockSets), clears them on Forget, and, if that conversion didn't
// complete, on Lift too.

// The block table and its sets.
const (
	BlockTable  = "aerolvm_block"
	BlockedSet  = "blocked"
	ReleasedSet = "released"
)

// blockSetOp is one element change of a block-set transaction.
type blockSetOp struct {
	Set string // BlockedSet or ReleasedSet
	Add bool   // false deletes
	IP  string
}

// errBlockTableMissing marks a transaction that failed because the table or
// a set isn't there (a ruleset flush): the caller recreates it and retries.
var errBlockTableMissing = errors.New("netrules: block table missing")

// blockSetBackend is the kernel side of the block sets.
type blockSetBackend interface {
	// EnsureBlockTable creates the table, both sets, the base chains and
	// their rules if any is missing. Elements already there are kept.
	EnsureBlockTable() error
	// BlockSetElements reads both sets.
	BlockSetElements() (blocked, released []string, err error)
	// ApplyBlockSetOps applies ops as one transaction, in order. It wraps
	// errBlockTableMissing when the table or a set is gone.
	ApplyBlockSetOps(ops []blockSetOp) error
}

// legacyBlockLister finds the per-address block rules an older daemon left:
// the addresses whose spec(ip) rule is in chain.
type legacyBlockLister interface {
	LegacyBlockIPs(chain string, spec func(ip string) []string) ([]string, error)
}

// blockEntry is the mirror of one address.
type blockEntry struct{ blocked, released bool }

// blockSetMirror is what this process knows is in the two sets.
type blockSetMirror struct {
	// ops: an operation on an address holds it shared from its read of the
	// mirror to its update; ReassertBlockSets holds it exclusively, so it
	// never compares the kernel against an operation half done.
	ops     sync.RWMutex
	mu      sync.Mutex
	loaded  bool
	entries map[string]blockEntry
	// unsure: an operation on the address failed after it may have
	// reached the kernel; the next one reads the kernel first.
	unsure map[string]bool
	// lastReassert is the last ReassertBlockSets that ran (under ops).
	lastReassert time.Time
}

// blockReassertMinGap spaces ReassertBlockSets runs process-wide. A var so
// tests can run it back to back.
var blockReassertMinGap = 10 * time.Second

var blockSets = &blockSetMirror{}

// ResetBlockSetsForTest forgets the mirror. Test-only seam: the mirror is
// process-wide, as a node's runtimes share one process and one table.
func ResetBlockSetsForTest() {
	blockSets.mu.Lock()
	defer blockSets.mu.Unlock()
	blockSets.loaded = false
	blockSets.entries = nil
	blockSets.unsure = nil
	blockSets.lastReassert = time.Time{}
}

// fill replaces the mirror with the kernel's sets. Caller holds mu.
func (s *blockSetMirror) fillLocked(blocked, released []string) {
	s.entries = map[string]blockEntry{}
	for _, ip := range blocked {
		e := s.entries[ip]
		e.blocked = true
		s.entries[ip] = e
	}
	for _, ip := range released {
		e := s.entries[ip]
		e.released = true
		s.entries[ip] = e
	}
	s.unsure = map[string]bool{}
	s.loaded = true
}

// load reads the kernel's sets into the mirror once per process.
func (s *blockSetMirror) load(b blockSetBackend) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded {
		return nil
	}
	blocked, released, err := b.BlockSetElements()
	if err != nil {
		return err
	}
	s.fillLocked(blocked, released)
	return nil
}

// entry returns what the sets hold for ip, reading the kernel when the
// mirror isn't sure.
func (s *blockSetMirror) entry(b blockSetBackend, ip string) (blockEntry, error) {
	s.mu.Lock()
	if !s.unsure[ip] {
		e := s.entries[ip]
		s.mu.Unlock()
		return e, nil
	}
	s.mu.Unlock()
	blocked, released, err := readBlockSets(b)
	if err != nil {
		return blockEntry{}, fmt.Errorf("read block sets: %w", err)
	}
	e := blockEntry{blocked: slices.Contains(blocked, ip), released: slices.Contains(released, ip)}
	s.mu.Lock()
	s.setLocked(ip, e)
	delete(s.unsure, ip)
	s.mu.Unlock()
	return e, nil
}

func (s *blockSetMirror) setLocked(ip string, e blockEntry) {
	if s.entries == nil {
		s.entries = map[string]blockEntry{}
	}
	if !e.blocked && !e.released {
		delete(s.entries, ip)
		return
	}
	s.entries[ip] = e
}

func (s *blockSetMirror) set(ip string, e blockEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setLocked(ip, e)
	delete(s.unsure, ip)
}

func (s *blockSetMirror) markUnsure(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unsure == nil {
		s.unsure = map[string]bool{}
	}
	s.unsure[ip] = true
}

// restoreOps puts the mirror back into a recreated table: every element it
// knows of.
func (s *blockSetMirror) restoreOps() []blockSetOp {
	s.mu.Lock()
	defer s.mu.Unlock()
	ips := slices.Sorted(maps.Keys(s.entries))
	var ops []blockSetOp
	for _, ip := range ips {
		e := s.entries[ip]
		if e.blocked {
			ops = append(ops, blockSetOp{Set: BlockedSet, Add: true, IP: ip})
		}
		if e.released {
			ops = append(ops, blockSetOp{Set: ReleasedSet, Add: true, IP: ip})
		}
	}
	return ops
}

// blockSetsOf returns the manager's block-set backend once PrepareBlockSets
// has succeeded, nil otherwise (the per-address rules).
func (m *Manager) blockSetsOf() blockSetBackend {
	if m == nil || !m.setsReady.Load() {
		return nil
	}
	b, _ := m.ipt.(blockSetBackend)
	return b
}

// PrepareBlockSets moves this manager's block-alls into the block sets:
// it makes sure the table exists, reads it into the process's mirror (the
// first manager to prepare does), and converts the per-address block rules
// an older daemon left in this manager's chains (set element first, rule
// second, so the address is never open). A backend without sets, or a
// failure here, leaves the manager on the per-address rules, which stay
// correct, only slower; the error says why. Call once at boot, before the
// manager serves creates.
func (m *Manager) PrepareBlockSets() error {
	if !m.Enabled() {
		return nil
	}
	b, ok := m.ipt.(blockSetBackend)
	if !ok {
		return nil
	}
	if err := b.EnsureBlockTable(); err != nil {
		return fmt.Errorf("netrules: block table: %w", err)
	}
	if err := blockSets.load(b); err != nil {
		return fmt.Errorf("netrules: read block sets: %w", err)
	}
	m.setsReady.Store(true)
	if err := m.convertLegacyBlocks(b); err != nil {
		// The sets serve from now on; the old rules stay where they are,
		// still blocking, and Lift and Forget clear them as they go.
		return fmt.Errorf("netrules: convert per-address blocks: %w", err)
	}
	m.legacyConverted.Store(true)
	return nil
}

// convertLegacyBlocks turns the per-address block rules in this manager's
// chains into @blocked elements, then removes the rules.
func (m *Manager) convertLegacyBlocks(b blockSetBackend) error {
	lister, ok := m.ipt.(legacyBlockLister)
	if !ok {
		return nil
	}
	fwd, err := lister.LegacyBlockIPs(m.filterChain(), egressDropSpec)
	if err != nil {
		return err
	}
	var input []string
	if m.ensureInputChain() == nil {
		if input, err = lister.LegacyBlockIPs(ChainAerolvmInput, inputBlockSpec); err != nil {
			return err
		}
	}
	ips := slices.Compact(slices.Sorted(slices.Values(append(fwd, input...))))
	for _, ip := range ips {
		if err := m.convertLegacyBlock(b, ip); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) convertLegacyBlock(b blockSetBackend, ip string) error {
	unlock := m.lockIP(ip)
	defer unlock()
	if _, err := m.blockInSets(b, ip); err != nil {
		return err
	}
	return m.clearLegacyBlock(ip)
}

// clearLegacyBlock removes the per-address block-all rule pair, the way the
// per-address path clears it. Callers hold the IP lock.
func (m *Manager) clearLegacyBlock(ip string) error {
	if bb, ok := m.ipt.(batchBackend); ok {
		return m.clearBlockAllEgressBatch(bb, ip)
	}
	if err := m.deleteUntilGone("filter", m.filterChain(), egressDropSpec(ip)...); err != nil {
		return fmt.Errorf("delete egress rule: %w", err)
	}
	return m.deleteInputRules(inputBlockSpec(ip))
}

// readBlockSets reads both sets, recreating the table (and putting the
// mirror back) if it is gone.
func readBlockSets(b blockSetBackend) (blocked, released []string, err error) {
	blocked, released, err = b.BlockSetElements()
	if !errors.Is(err, errBlockTableMissing) {
		return blocked, released, err
	}
	if err := restoreBlockTable(b); err != nil {
		return nil, nil, err
	}
	return b.BlockSetElements()
}

// restoreBlockTable recreates the table and puts the mirror's elements
// back.
func restoreBlockTable(b blockSetBackend) error {
	if err := b.EnsureBlockTable(); err != nil {
		return fmt.Errorf("netrules: recreate block table: %w", err)
	}
	if restore := blockSets.restoreOps(); len(restore) > 0 {
		if err := b.ApplyBlockSetOps(restore); err != nil {
			return fmt.Errorf("netrules: refill block sets: %w", err)
		}
	}
	return nil
}

// applyBlockOps runs one transaction; if the table is gone it recreates it,
// puts the mirror back and runs it again. rebuilt reports that.
func applyBlockOps(b blockSetBackend, ops []blockSetOp) (rebuilt bool, err error) {
	err = b.ApplyBlockSetOps(ops)
	if !errors.Is(err, errBlockTableMissing) {
		return false, err
	}
	if err := restoreBlockTable(b); err != nil {
		return true, err
	}
	return true, b.ApplyBlockSetOps(ops)
}

// blockInSets makes ip blocked: in @blocked and not in @released. inserted
// reports that it wasn't (or the table had to be put back): the drift
// reconcile counts. Callers hold the IP lock.
func (m *Manager) blockInSets(b blockSetBackend, ip string) (bool, error) {
	blockSets.ops.RLock()
	defer blockSets.ops.RUnlock()
	e, err := blockSets.entry(b, ip)
	if err != nil {
		return false, err
	}
	var ops []blockSetOp
	if e.released {
		ops = append(ops, blockSetOp{Set: ReleasedSet, IP: ip})
	}
	// Always added: an element add is idempotent and cheap, and it puts back
	// one the kernel lost.
	ops = append(ops, blockSetOp{Set: BlockedSet, Add: true, IP: ip})
	rebuilt, err := applyBlockOps(b, ops)
	if err != nil {
		blockSets.markUnsure(ip)
		return false, fmt.Errorf("insert egress block: %w", err)
	}
	blockSets.set(ip, blockEntry{blocked: true})
	return rebuilt || !e.blocked || e.released, nil
}

// LiftBlockAllEgress lifts containerIP's block-all while the sandbox keeps
// its address (the gateway attach of a hostname-filtered create, a quota or
// policy that no longer blocks, a warm slot adopted without one): on the
// block sets it is one add to @released. The address stays in @blocked
// until Forget. On the per-address rules it is ClearBlockAllEgress.
func (m *Manager) LiftBlockAllEgress(containerIP string) error {
	if !m.Enabled() || containerIP == "" {
		return nil
	}
	b := m.setsFor(containerIP)
	if b == nil {
		return m.ClearBlockAllEgress(containerIP)
	}
	unlock := m.lockIP(containerIP)
	defer unlock()
	if err := m.releaseInSets(b, containerIP); err != nil {
		return err
	}
	if !m.legacyConverted.Load() {
		return m.clearLegacyBlock(containerIP)
	}
	return nil
}

// releaseInSets adds a blocked ip to @released. Callers hold the IP lock.
func (m *Manager) releaseInSets(b blockSetBackend, containerIP string) error {
	blockSets.ops.RLock()
	defer blockSets.ops.RUnlock()
	e, err := blockSets.entry(b, containerIP)
	if err != nil {
		return err
	}
	if e.blocked && !e.released {
		if _, err := applyBlockOps(b, []blockSetOp{{Set: ReleasedSet, Add: true, IP: containerIP}}); err != nil {
			blockSets.markUnsure(containerIP)
			return fmt.Errorf("release egress block: %w", err)
		}
		blockSets.set(containerIP, blockEntry{blocked: true, released: true})
	}
	return nil
}

// forgetInSets lets go of ip in both sets, @released first: one
// transaction, and the only one that pays the grace period. Callers hold
// the IP lock.
func (m *Manager) forgetInSets(b blockSetBackend, ip string) error {
	if err := m.forgetElements(b, ip); err != nil {
		return err
	}
	// One release of migration: an older daemon's rule pair may still be
	// at this address.
	return m.clearLegacyBlock(ip)
}

func (m *Manager) forgetElements(b blockSetBackend, ip string) error {
	blockSets.ops.RLock()
	defer blockSets.ops.RUnlock()
	e, err := blockSets.entry(b, ip)
	if err != nil {
		return err
	}
	var ops []blockSetOp
	if e.released {
		ops = append(ops, blockSetOp{Set: ReleasedSet, IP: ip})
	}
	if e.blocked {
		ops = append(ops, blockSetOp{Set: BlockedSet, IP: ip})
	}
	if len(ops) > 0 {
		if _, err := applyBlockOps(b, ops); err != nil {
			blockSets.markUnsure(ip)
			return fmt.Errorf("delete egress block: %w", err)
		}
		blockSets.set(ip, blockEntry{})
	}
	return nil
}

// ReassertBlockSets checks the table against the mirror: a missing table or
// element is put back (repaired reports it), and a release the kernel holds
// that this process never made is deleted, as nothing here would ever lift
// a block for it. A no-op on the per-address rules.
func (m *Manager) ReassertBlockSets() (repaired bool, err error) {
	b := m.blockSetsOf()
	if b == nil {
		return false, nil
	}
	blockSets.ops.Lock()
	defer blockSets.ops.Unlock()
	// Every prepared manager's chain tick calls this, and the sets are the
	// process's: once per interval is enough.
	now := time.Now()
	if now.Sub(blockSets.lastReassert) < blockReassertMinGap {
		return false, nil
	}
	blockSets.lastReassert = now
	if err := b.EnsureBlockTable(); err != nil {
		return false, fmt.Errorf("netrules: block table: %w", err)
	}
	blocked, released, err := readBlockSets(b)
	if err != nil {
		return false, fmt.Errorf("netrules: read block sets: %w", err)
	}
	inBlocked := map[string]bool{}
	for _, ip := range blocked {
		inBlocked[ip] = true
	}
	inReleased := map[string]bool{}
	for _, ip := range released {
		inReleased[ip] = true
	}
	var ops []blockSetOp
	blockSets.mu.Lock()
	for _, ip := range slices.Sorted(maps.Keys(inReleased)) {
		if e, ok := blockSets.entries[ip]; (!ok || !e.released) && !blockSets.unsure[ip] {
			ops = append(ops, blockSetOp{Set: ReleasedSet, IP: ip})
		}
	}
	for _, ip := range slices.Sorted(maps.Keys(blockSets.entries)) {
		e := blockSets.entries[ip]
		if blockSets.unsure[ip] {
			continue
		}
		if e.blocked && !inBlocked[ip] {
			ops = append(ops, blockSetOp{Set: BlockedSet, Add: true, IP: ip})
		}
		if e.released && !inReleased[ip] {
			ops = append(ops, blockSetOp{Set: ReleasedSet, Add: true, IP: ip})
		}
	}
	for _, ip := range slices.Sorted(maps.Keys(inBlocked)) {
		// Closed, so kept; known from now on, so a Forget removes it.
		if _, ok := blockSets.entries[ip]; !ok && !blockSets.unsure[ip] {
			blockSets.setLocked(ip, blockEntry{blocked: true})
		}
	}
	blockSets.mu.Unlock()
	if len(ops) == 0 {
		return false, nil
	}
	if err := b.ApplyBlockSetOps(ops); err != nil {
		return false, fmt.Errorf("netrules: repair block sets: %w", err)
	}
	return true, nil
}

// BlockedInSets reports what the mirror holds for ip, for tests and
// diagnostics.
func BlockedInSets(ip string) (blocked, released bool) {
	blockSets.mu.Lock()
	defer blockSets.mu.Unlock()
	e := blockSets.entries[ip]
	return e.blocked, e.released
}

// setsFor returns the manager's block sets for ip, nil when ip stays on the
// per-address rules: no sets, or an address the ip-family sets can't hold
// (sandboxes have no IPv6, #855; a v6 address keeps the old path).
func (m *Manager) setsFor(ip string) blockSetBackend {
	b := m.blockSetsOf()
	if b == nil {
		return nil
	}
	if a, err := netip.ParseAddr(ip); err != nil || !a.Is4() {
		return nil
	}
	return b
}

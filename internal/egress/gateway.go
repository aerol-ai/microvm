package egress

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// DefaultLearnedMax caps (ip, port) learned elements per sandbox
// (SB_EGRESS_LEARNED_MAX). Past it new names fail closed (EF-62).
const DefaultLearnedMax = 512

// ErrLearnedCap is returned when a sandbox's learned-element cap is reached.
var ErrLearnedCap = errors.New("egress: learned cap reached")

// ErrNotAttached is returned for an unknown sandbox or a source IP owned by
// another sandbox.
var ErrNotAttached = errors.New("egress: sandbox not attached")

// ConntrackFlusher deletes conntrack entries originating from a source IP, so
// established flows can't outlive a block or a narrowing (EF-13, D2).
type ConntrackFlusher interface {
	FlushSource(ip netip.Addr) error
}

// Options configures a Gateway.
type Options struct {
	Backend    Backend
	Layout     LayoutConfig
	Conntrack  ConntrackFlusher
	LearnedMax int
	Logger     *slog.Logger
	Now        func() time.Time
}

// entry is one attached sandbox.
type entry struct {
	spec    Spec
	pol     *egresspolicy.Policy
	rules   *egresspolicy.Rules
	mode    Mode
	allow   []netip.Prefix
	deny    []netip.Prefix
	blocked BlockReason
	hash    string
	// inBlockedSrc is whether @blocked_src holds the source right now, the
	// kernel's side of blocked. They differ after a failed write: the
	// in-memory reasons already deny (DNS filter, proxy) while the kernel
	// write is retried, and diffs start from what the kernel really has.
	inBlockedSrc bool
}

// kernelBlocked is the block state that belongs in @blocked_src. The restart
// block stays in memory (eng re-review D2).
func (e *entry) kernelBlocked() bool { return e.blocked&^BlockRestart != 0 }

type learnKey struct {
	dst  netip.Addr
	port uint16
	// bin: the element is in bin_learned, so the flow is redirected to the
	// proxy to be traced to its executable (P3-3), not accepted directly.
	bin bool
}

func (k learnKey) set() string {
	if k.bin {
		return SetBinLearned
	}
	return SetAllowLearned
}

// Gateway holds per-node gateway state and drives the Backend.
type Gateway struct {
	be     Backend
	layout LayoutConfig
	ct     ConntrackFlusher
	maxLrn int
	log    *slog.Logger
	now    func() time.Time

	// opMu makes Sync (and Restore) exclusive against every per-sandbox
	// state transition: Attach, Detach, SetBlocked, learning. Each of those
	// is a kernel write followed by a map update, and a Sync replacing the
	// sets between the two would leave a sandbox reported attached with no
	// kernel rules, unfiltered.
	opMu sync.RWMutex
	// Per-sandbox locks, reference counted so a destroyed sandbox's lock goes
	// away with its last holder.
	lockMu sync.Mutex
	locks  map[string]*sbLock

	mu    sync.RWMutex
	byID  map[string]*entry
	bySrc map[netip.Addr]string

	learnedMu sync.Mutex
	learned   map[string]map[learnKey]time.Time // shadow of allow_learned and bin_learned (D18)
	// binNames names each bin_learned destination, so the proxy knows which
	// host a redirected flow is for.
	binNames map[string]map[learnKey]string
	// pendingLearned holds learned elements whose delete failed, by source
	// IP, and pendingCT the sources whose conntrack flush failed. Both are
	// retried until they succeed: an element left behind keeps a revoked
	// destination open until its timeout, and the next owner of a recycled
	// IP would inherit it. Attach refuses to succeed for a source with
	// cleanup still pending.
	pendingLearned map[netip.Addr]map[string][]Elem
	pendingCT      map[netip.Addr]struct{}
	// sweepPending holds sources whose kernel learned elements a Sync
	// couldn't list: the elements are unknown, so the sweep is redone.
	sweepPending map[netip.Addr]bool

	connMu sync.Mutex
	conns  map[string]map[*TrackedConn]struct{}

	nwMu     sync.Mutex
	nodeWide NodeWide
}

// New builds a Gateway. Call Bootstrap before use.
func New(opts Options) *Gateway {
	g := &Gateway{
		be:             opts.Backend,
		layout:         opts.Layout,
		ct:             opts.Conntrack,
		maxLrn:         opts.LearnedMax,
		log:            opts.Logger,
		now:            opts.Now,
		byID:           map[string]*entry{},
		bySrc:          map[netip.Addr]string{},
		locks:          map[string]*sbLock{},
		learned:        map[string]map[learnKey]time.Time{},
		binNames:       map[string]map[learnKey]string{},
		pendingLearned: map[netip.Addr]map[string][]Elem{},
		pendingCT:      map[netip.Addr]struct{}{},
		sweepPending:   map[netip.Addr]bool{},
		conns:          map[string]map[*TrackedConn]struct{}{},
	}
	if g.maxLrn <= 0 {
		g.maxLrn = DefaultLearnedMax
	}
	if g.log == nil {
		g.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if g.now == nil {
		g.now = time.Now
	}
	return g
}

// Bootstrap creates (or confirms) the nft layout. It never flushes the
// contents of a matching layout (D13: kernel state outlives both processes).
func (g *Gateway) Bootstrap() error {
	if err := g.be.EnsureLayout(g.layout); err != nil {
		return fmt.Errorf("egress layout: %w", err)
	}
	if err := g.reapplyNodeWide(); err != nil {
		return fmt.Errorf("egress node-wide rules: %w", err)
	}
	return nil
}

// CheckLayout is the table-loss probe (CEO D17).
func (g *Gateway) CheckLayout() error { return g.be.CheckLayout() }

type sbLock struct {
	mu   sync.Mutex
	refs int
}

// lockSandbox serializes one sandbox's transitions. The entry is dropped
// when its last holder or waiter is done, so churn doesn't grow the map
// (the pkg/docker/netrules lockIP pattern).
func (g *Gateway) lockSandbox(id string) func() {
	g.lockMu.Lock()
	l := g.locks[id]
	if l == nil {
		l = &sbLock{}
		g.locks[id] = l
	}
	l.refs++
	g.lockMu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		g.lockMu.Lock()
		if l.refs--; l.refs == 0 {
			delete(g.locks, id)
		}
		g.lockMu.Unlock()
	}
}

// lockCount is the number of live per-sandbox locks (tests).
func (g *Gateway) lockCount() int {
	g.lockMu.Lock()
	defer g.lockMu.Unlock()
	return len(g.locks)
}

// compile validates a spec through pkg/egresspolicy, the one grammar every
// runtime shares, and derives the nft class from the compiled policy.
func compile(spec Spec) (*entry, error) {
	if strings.TrimSpace(spec.ID) == "" {
		return nil, errors.New("egress: spec without sandbox id")
	}
	if !spec.IP.Is4() {
		return nil, fmt.Errorf("egress: sandbox %s: gateway mode needs an IPv4 source, got %q", spec.ID, spec.IP)
	}
	mode := egresspolicy.ModeEnforce
	if spec.Learn {
		mode = egresspolicy.ModeLearn
	}
	// sandboxd sends the effective list (inline entries plus referenced
	// profiles), already held to the inline cap at the API.
	pol, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: spec.AllowOut, DenyOut: spec.DenyOut, Mode: mode, MaxHostnames: egresspolicy.MaxUnionHostnames})
	if err != nil {
		return nil, fmt.Errorf("egress: sandbox %s: %w", spec.ID, err)
	}
	if pol.BlockAll() {
		// Block-all wins and nothing is redirected (EF-14): sandboxd keeps such
		// a sandbox out of gateway mode entirely.
		return nil, fmt.Errorf("egress: sandbox %s: block-all is not a gateway-mode policy", spec.ID)
	}
	// sandboxd checked rule hosts against the allow list; one a profile
	// change has since dropped is inert, not an error.
	rules, err := egresspolicy.CompileRules(spec.Rules, nil)
	if err != nil {
		return nil, fmt.Errorf("egress: sandbox %s: %w", spec.ID, err)
	}
	e := &entry{spec: spec, pol: pol, rules: rules, blocked: spec.Blocked, hash: specHash(spec)}
	switch {
	case spec.Learn:
		e.mode = ModeLearn
	case pol.DefaultVerdict() == egresspolicy.VerdictDeny:
		e.mode = ModeAllowlist
	default:
		e.mode = ModeDenylist
	}
	for _, p := range pol.AllowCIDRs() {
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("egress: sandbox %s: %s: IPv6 is not supported in gateway mode", spec.ID, p)
		}
		e.allow = append(e.allow, p)
	}
	for _, p := range pol.DenyCIDRs() {
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("egress: sandbox %s: %s: IPv6 is not supported in gateway mode", spec.ID, p)
		}
		e.deny = append(e.deny, p)
	}
	return e, nil
}

func specHash(s Spec) string {
	s.Blocked = 0 // block state changes must not discard learned elements
	s.Secrets = nil
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	bits := p.Bits()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	if bits < 32 {
		v |= (uint32(1) << (32 - bits)) - 1
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// elements returns every managed-set element an entry contributes.
func (e *entry) elements() map[string][]Elem {
	src := e.spec.IP
	out := map[string][]Elem{SetFQDNSrc: {{Src: src}}}
	switch e.mode {
	case ModeAllowlist:
		out[SetSrcDenyDefault] = []Elem{{Src: src}}
	case ModeDenylist:
		out[SetSrcAccept] = []Elem{{Src: src}}
	case ModeLearn:
		out[SetLearnSrc] = []Elem{{Src: src}}
	}
	if e.kernelBlocked() {
		out[SetBlockedSrc] = []Elem{{Src: src}}
	}
	for _, p := range e.allow {
		out[SetAllowCIDR] = append(out[SetAllowCIDR], Elem{Src: src, Dst: p.Addr(), DstEnd: lastAddr(p)})
	}
	for _, p := range e.deny {
		out[SetDenyCIDR] = append(out[SetDenyCIDR], Elem{Src: src, Dst: p.Addr(), DstEnd: lastAddr(p)})
	}
	return out
}

// kernelElements is what the kernel holds for an entry: its elements, with
// @blocked_src as last applied rather than as wanted.
func (e *entry) kernelElements() map[string][]Elem {
	out := e.elements()
	delete(out, SetBlockedSrc)
	if e.inBlockedSrc {
		out[SetBlockedSrc] = []Elem{{Src: e.spec.IP}}
	}
	return out
}

// diffOps returns the ops that move the kernel from what old holds to nu's
// elements. Deletes come first in the batch; within one nft transaction the
// order only matters for readability, the commit is atomic.
func diffOps(old, nu *entry) []Op {
	var oldE, newE map[string][]Elem
	if old != nil {
		oldE = old.kernelElements()
	}
	if nu != nil {
		newE = nu.elements()
	}
	var dels, adds []Op
	sets := map[string]struct{}{}
	for k := range oldE {
		sets[k] = struct{}{}
	}
	for k := range newE {
		sets[k] = struct{}{}
	}
	names := make([]string, 0, len(sets))
	for k := range sets {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, name := range names {
		del := subtract(oldE[name], newE[name])
		add := subtract(newE[name], oldE[name])
		if len(del) > 0 {
			dels = append(dels, Op{Set: name, Del: true, Elems: del})
		}
		if len(add) > 0 {
			adds = append(adds, Op{Set: name, Elems: add})
		}
	}
	return append(dels, adds...)
}

func subtract(a, b []Elem) []Elem {
	var out []Elem
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// Attach installs (or re-installs) a sandbox. An IP still mapped to another
// sandbox is purged first: netns slots recycle IPs, and a late Detach for the
// old owner must never remove the new owner's entries (D5). The spec's
// Blocked reasons are applied in the same batch, so an Attach can't re-open a
// sandbox a concurrent quota block just closed (Section 4). It succeeds only
// once nothing a previous policy or owner of the source allowed is left in
// the kernel: a failed cleanup is an error, so sandboxd keeps the sandbox
// held, and the next Attach retries it.
func (g *Gateway) Attach(spec Spec) error {
	nu, err := compile(spec)
	if err != nil {
		return err
	}
	g.opMu.RLock()
	defer g.opMu.RUnlock()
	unlock := g.lockSandbox(spec.ID)
	defer unlock()

	g.mu.RLock()
	old := g.byID[spec.ID]
	prevOwner, owned := g.bySrc[spec.IP]
	g.mu.RUnlock()
	if old != nil {
		// Keep block reasons the gateway already holds (e.g. a hold set while
		// sandboxd computed this spec): blocks only lift via SetBlocked.
		nu.blocked |= old.blocked &^ (BlockRestart | BlockCleanup)
	}
	if owned && prevOwner != spec.ID {
		g.log.Warn("egress: attach purges previous owner of recycled ip", "ip", spec.IP, "previous", prevOwner, "sandbox_id", spec.ID)
		if err := g.purge(prevOwner); err != nil {
			return err
		}
	}
	var ops []Op
	if old != nil && old.spec.IP != spec.IP {
		ops = append(ops, diffOps(old, nil)...)
		ops = append(ops, diffOps(nil, nu)...)
	} else {
		ops = diffOps(old, nu)
	}
	if len(ops) > 0 {
		if err := g.be.Apply(ops); err != nil {
			return fmt.Errorf("%w: attach %s: %v", ErrUnavailable, spec.ID, err)
		}
	}
	nu.inBlockedSrc = nu.kernelBlocked()
	policyChanged := old != nil && (old.hash != nu.hash)
	g.mu.Lock()
	if old != nil && old.spec.IP != spec.IP && g.bySrc[old.spec.IP] == spec.ID {
		delete(g.bySrc, old.spec.IP)
	}
	g.byID[spec.ID] = nu
	g.bySrc[spec.IP] = spec.ID
	g.mu.Unlock()
	if policyChanged {
		// A narrowed policy must not keep serving through learned
		// (ip, port) pairs, established flows or proxied connections it no
		// longer allows (D2, §5.8 FQDN → FQDN′).
		g.CloseConnsWhere(spec.ID, func(host string, port uint16) bool { return !nu.permits(host, port) })
		g.flushLearned(spec.ID, old.spec.IP)
		g.flushConntrack(old.spec.IP)
	}
	if nu.kernelBlocked() && (old == nil || !old.kernelBlocked()) {
		g.closeConns(spec.ID)
		g.flushConntrack(spec.IP)
	}
	srcs := []netip.Addr{spec.IP}
	if old != nil && old.spec.IP != spec.IP {
		srcs = append(srcs, old.spec.IP)
	}
	if err := g.retryCleanup(srcs...); err != nil {
		// Shut it here too, not only through sandboxd's hold: the gateway
		// itself never serves a source with revoked entries left.
		if berr := g.setCleanupBlock(nu, true); berr != nil {
			g.log.Warn("egress: cleanup block not applied", "sandbox_id", spec.ID, "error", berr)
		}
		return fmt.Errorf("%w: attach %s: %v", ErrUnavailable, spec.ID, err)
	}
	return nil
}

// cleanupPending reports whether a source has revocation work left.
func (g *Gateway) cleanupPending(src netip.Addr) bool {
	g.learnedMu.Lock()
	defer g.learnedMu.Unlock()
	_, ct := g.pendingCT[src]
	return len(g.pendingLearned[src]) > 0 || ct || g.sweepPending[src]
}

// setCleanupBlock sets or clears BlockCleanup on an attached entry and
// writes @blocked_src if that changes it. Callers hold opMu (shared, with
// the sandbox's lock, or exclusive).
func (g *Gateway) setCleanupBlock(e *entry, on bool) error {
	g.mu.Lock()
	if on {
		e.blocked |= BlockCleanup
	} else {
		e.blocked &^= BlockCleanup
	}
	differs := e.inBlockedSrc != e.kernelBlocked()
	g.mu.Unlock()
	if on {
		g.closeConns(e.spec.ID)
	}
	if !differs {
		return nil
	}
	return g.applyBlockedLocked(e)
}

// Update replaces an attached sandbox's policy (FQDN → FQDN′). Same as Attach
// for an existing sandbox; kept as its own verb for the protocol.
func (g *Gateway) Update(spec Spec) error {
	g.mu.RLock()
	_, ok := g.byID[spec.ID]
	g.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotAttached, spec.ID)
	}
	return g.Attach(spec)
}

// Detach removes a sandbox, but only if ip is still its source (D5).
func (g *Gateway) Detach(id string, ip netip.Addr) error {
	g.opMu.RLock()
	defer g.opMu.RUnlock()
	unlock := g.lockSandbox(id)
	defer unlock()
	g.mu.RLock()
	owner, ok := g.bySrc[ip]
	g.mu.RUnlock()
	if ok && owner != id {
		g.log.Info("egress: detach skipped, ip owned by another sandbox", "ip", ip, "sandbox_id", id, "owner", owner)
		return nil
	}
	return g.purge(id)
}

// purge removes every trace of a sandbox: set elements, learned elements,
// tracked connections and conntrack entries. Callers hold opMu (shared) and
// its lock, or are purging a previous owner from inside another sandbox's
// Attach. Learned and conntrack cleanup that fails stays pending; the next
// Attach of that source must finish it first.
func (g *Gateway) purge(id string) error {
	g.mu.RLock()
	old := g.byID[id]
	g.mu.RUnlock()
	if old == nil {
		return nil
	}
	if ops := diffOps(old, nil); len(ops) > 0 {
		if err := g.be.Apply(ops); err != nil {
			return fmt.Errorf("%w: detach %s: %v", ErrUnavailable, id, err)
		}
	}
	g.mu.Lock()
	delete(g.byID, id)
	if g.bySrc[old.spec.IP] == id {
		delete(g.bySrc, old.spec.IP)
	}
	g.mu.Unlock()
	g.closeConns(id)
	g.flushLearned(id, old.spec.IP)
	g.flushConntrack(old.spec.IP)
	return nil
}

// SetBlocked sets or clears one block reason. The sandbox is in @blocked_src
// while any kernel reason is set; becoming blocked also closes its proxied
// connections and flushes its conntrack entries, so a sandbox at its quota
// can't keep downloading over flows already open (EF-13). The wanted reasons
// take effect in memory first, so the DNS filter and proxy deny at once, and
// the connections are closed even when the kernel write fails; a failed
// write leaves the kernel side marked unapplied, so an identical retry (or
// RetryDirty) writes it again instead of finding nothing to do.
func (g *Gateway) SetBlocked(id string, reason BlockReason, on bool) error {
	g.opMu.RLock()
	defer g.opMu.RUnlock()
	unlock := g.lockSandbox(id)
	defer unlock()
	g.mu.Lock()
	cur := g.byID[id]
	if cur == nil {
		g.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNotAttached, id)
	}
	want := cur.blocked
	if on {
		want |= reason
	} else {
		want &^= reason
	}
	newly := on && want != cur.blocked
	cur.blocked = want
	pending := cur.inBlockedSrc != cur.kernelBlocked()
	g.mu.Unlock()
	if on && (newly || pending) {
		g.closeConns(id)
		g.flushConntrack(cur.spec.IP)
	}
	if !pending {
		return nil
	}
	return g.applyBlockedLocked(cur)
}

// applyBlockedLocked writes an entry's wanted @blocked_src membership.
// Callers hold opMu (shared) and the sandbox's lock.
func (g *Gateway) applyBlockedLocked(e *entry) error {
	g.mu.RLock()
	want := e.kernelBlocked()
	g.mu.RUnlock()
	op := Op{Set: SetBlockedSrc, Del: !want, Elems: []Elem{{Src: e.spec.IP}}}
	if err := g.be.Apply([]Op{op}); err != nil {
		return fmt.Errorf("%w: set blocked %s: %v", ErrUnavailable, e.spec.ID, err)
	}
	g.mu.Lock()
	e.inBlockedSrc = want
	g.mu.Unlock()
	return nil
}

// Sync replaces the whole gateway state with sandboxd's (D13). Managed sets
// are replaced atomically. Learned elements and recordings survive for
// sandboxes whose policy is unchanged and are flushed for removed or changed
// ones. Sync also lifts the restart block. It runs alone: no Attach, Detach
// or SetBlocked is between its kernel write and its map swap.
func (g *Gateway) Sync(specs []Spec) error {
	next := map[string]*entry{}
	for _, s := range specs {
		e, err := compile(s)
		if err != nil {
			return err
		}
		next[s.ID] = e
	}
	contents := map[string][]Elem{}
	for _, name := range managedSets {
		contents[name] = nil
	}
	for _, e := range next {
		for name, elems := range e.elements() {
			contents[name] = append(contents[name], elems...)
		}
	}
	g.opMu.Lock()
	defer g.opMu.Unlock()
	if err := g.be.Replace(contents); err != nil {
		return fmt.Errorf("%w: sync: %v", ErrUnavailable, err)
	}
	g.mu.Lock()
	prev := g.byID
	g.byID = next
	g.bySrc = map[netip.Addr]string{}
	for id, e := range next {
		e.inBlockedSrc = e.kernelBlocked()
		g.bySrc[e.spec.IP] = id
	}
	g.mu.Unlock()
	changed := map[string]bool{}
	for id, old := range prev {
		nu, ok := next[id]
		if ok && nu.hash == old.hash && nu.spec.IP == old.spec.IP {
			continue
		}
		changed[id] = true
		if !ok {
			g.closeConns(id)
		} else {
			g.CloseConnsWhere(id, func(host string, port uint16) bool { return !nu.permits(host, port) })
		}
		g.flushLearned(id, old.spec.IP)
	}
	g.sweepLearned(next, changed)
	// A kept sandbox whose revoked entries the kernel still holds is shut
	// until they are deleted (BlockCleanup), the same invariant Attach
	// keeps: a Sync is never the acknowledgement of a revocation that
	// didn't happen.
	var errs []error
	for _, e := range next {
		if g.cleanupPending(e.spec.IP) {
			if err := g.setCleanupBlock(e, true); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: sync: shut sandboxes with pending cleanup: %v", ErrUnavailable, err)
	}
	return nil
}

// sweepLearned reconciles allow_learned and bin_learned against the synced
// state straight from the kernel. After a gateway restart the shadow map is
// empty, so the kernel is the only record: elements whose source no longer
// belongs to an attached, unchanged sandbox are deleted, and the rest seed
// the shadow with an already-due expiry (the next DNS answer refreshes them
// with one write, and gives a bin_learned element its name back; until then
// the proxy refuses its flows).
func (g *Gateway) sweepLearned(next map[string]*entry, changed map[string]bool) {
	owner := map[netip.Addr]string{}
	for id, e := range next {
		owner[e.spec.IP] = id
	}
	now := g.now()
	for _, set := range []string{SetAllowLearned, SetBinLearned} {
		elems, err := g.be.List(set)
		if err != nil {
			// The stale elements are unknown: every changed sandbox's source
			// is swept again until a listing succeeds, shut meanwhile.
			g.log.Warn("egress: list learned elements for sync failed", "set", set, "error", err)
			g.learnedMu.Lock()
			for id := range changed {
				if e := next[id]; e != nil {
					g.sweepPending[e.spec.IP] = true
				}
			}
			g.learnedMu.Unlock()
			continue
		}
		var stale []Elem
		g.learnedMu.Lock()
		for _, el := range elems {
			id, ok := owner[el.Src]
			if !ok || changed[id] {
				stale = append(stale, Elem{Src: el.Src, Dst: el.Dst, Port: el.Port})
				continue
			}
			if g.learned[id] == nil {
				g.learned[id] = map[learnKey]time.Time{}
			}
			k := learnKey{dst: el.Dst, port: el.Port, bin: set == SetBinLearned}
			if _, known := g.learned[id][k]; !known {
				g.learned[id][k] = now
			}
		}
		g.learnedMu.Unlock()
		if len(stale) > 0 {
			if err := g.be.Apply([]Op{{Set: set, Del: true, Elems: stale}}); err != nil {
				// Kept until deleted: retried, and Attach of the source (a
				// new owner included) waits for it.
				g.log.Warn("egress: delete stale learned elements failed; retrying", "set", set, "error", err)
				g.learnedMu.Lock()
				for _, el := range stale {
					p := g.pendingLearned[el.Src]
					if p == nil {
						p = map[string][]Elem{}
						g.pendingLearned[el.Src] = p
					}
					if !slices.Contains(p[set], el) {
						p[set] = append(p[set], el)
					}
				}
				g.learnedMu.Unlock()
			}
		}
	}
}

// resweep redoes a failed Sync sweep for one source: every learned element
// of it that the shadow doesn't know is stale (the shadow of a changed
// sandbox was cleared), and goes to pendingLearned.
func (g *Gateway) resweep(src netip.Addr) error {
	g.mu.RLock()
	id := g.bySrc[src]
	g.mu.RUnlock()
	for _, set := range []string{SetAllowLearned, SetBinLearned} {
		elems, err := g.be.List(set)
		if err != nil {
			return err
		}
		g.learnedMu.Lock()
		for _, el := range elems {
			if el.Src != src {
				continue
			}
			if _, known := g.learned[id][learnKey{dst: el.Dst, port: el.Port, bin: set == SetBinLearned}]; known && id != "" {
				continue
			}
			p := g.pendingLearned[src]
			if p == nil {
				p = map[string][]Elem{}
				g.pendingLearned[src] = p
			}
			e := Elem{Src: el.Src, Dst: el.Dst, Port: el.Port}
			if !slices.Contains(p[set], e) {
				p[set] = append(p[set], e)
			}
		}
		g.learnedMu.Unlock()
	}
	g.learnedMu.Lock()
	delete(g.sweepPending, src)
	g.learnedMu.Unlock()
	return nil
}

// Lookup resolves a source IP to its sandbox, for the DNS filter and proxy.
func (g *Gateway) Lookup(src netip.Addr) (Spec, BlockReason, bool) {
	s, ok := g.Source(src)
	return s.Spec, s.Blocked, ok
}

// Source is one attached sandbox as the data path sees it.
type Source struct {
	Spec    Spec
	Policy  *egresspolicy.Policy
	Rules   *egresspolicy.Rules
	Mode    Mode
	Blocked BlockReason
}

// Source resolves a source IP to its sandbox and compiled policy.
func (g *Gateway) Source(src netip.Addr) (Source, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	id, ok := g.bySrc[src]
	if !ok {
		return Source{}, false
	}
	e := g.byID[id]
	return Source{Spec: e.spec, Policy: e.pol, Rules: e.rules, Mode: e.mode, Blocked: e.blocked}, true
}

// IsBlocked reports the in-memory block bit (including the restart block).
// The DNS filter and proxy check it in addition to @blocked_src, in case of
// races or a failed nft write.
func (g *Gateway) IsBlocked(id string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	e := g.byID[id]
	return e == nil || e.blocked != 0
}

// Specs returns the attached specs with their current block reasons
// (snapshotting, metrics).
func (g *Gateway) Specs() []Spec {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]Spec, 0, len(g.byID))
	for _, e := range g.byID {
		s := e.spec
		s.Blocked = e.blocked
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b Spec) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Restore loads snapshot specs into memory with the restart block set and
// touches no kernel state: with a snapshot the gateway can answer DNS and
// proxy lookups (denying) until Sync; with none it leaves the sets as they
// are (D13, eng re-review D2).
func (g *Gateway) Restore(specs []Spec) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	// Which sources the kernel already blocks (a matching layout keeps the
	// sets; a migrated one blocks every carried source). Unknown counts as
	// not blocked: the next write then adds rather than deletes, and an add
	// of an element already there is harmless while a delete of a missing
	// one fails.
	inBlocked := map[netip.Addr]bool{}
	if elems, err := g.be.List(SetBlockedSrc); err == nil {
		for _, e := range elems {
			inBlocked[e.Src] = true
		}
	}
	next := map[string]*entry{}
	bySrc := map[netip.Addr]string{}
	for _, s := range specs {
		e, err := compile(s)
		if err != nil {
			return err
		}
		e.blocked |= BlockRestart
		e.inBlockedSrc = inBlocked[s.IP]
		next[s.ID] = e
		bySrc[s.IP] = s.ID
	}
	g.mu.Lock()
	g.byID, g.bySrc = next, bySrc
	g.mu.Unlock()
	return nil
}

// AddLearned opens (src, dst, port) for a host:port rule's DNS answer, with a
// TTL. The shadow map skips the netlink write while the element has more than
// half its timeout left (D18); the per-sandbox cap fails closed (EF-62).
func (g *Gateway) AddLearned(id string, dst netip.Addr, port uint16, ttl time.Duration) error {
	return g.LearnFor(id, "", dst, port, ttl)
}

// LearnFor is AddLearned for an answer to name. When a rule traces name's
// port to executables (P3-3), the element goes to bin_learned instead: the
// flow is redirected to the proxy, which checks the binary before dialing.
func (g *Gateway) LearnFor(id, name string, dst netip.Addr, port uint16, ttl time.Duration) error {
	if !dst.Is4() {
		return fmt.Errorf("egress: learned destination %s is not IPv4", dst)
	}
	// Serialized with the sandbox's transitions and checked against the
	// policy in force at the write: an answer the DNS filter admitted under
	// a policy that has since been narrowed must not put the revoked
	// destination back (review 2 finding 6).
	g.opMu.RLock()
	defer g.opMu.RUnlock()
	unlock := g.lockSandbox(id)
	defer unlock()
	g.mu.RLock()
	e := g.byID[id]
	g.mu.RUnlock()
	if e == nil {
		return fmt.Errorf("%w: %s", ErrNotAttached, id)
	}
	if name != "" {
		if ok, _ := e.pol.MatchHostPort(name, port); !ok {
			return fmt.Errorf("%w: %s:%d", ErrNotPermitted, name, port)
		}
	}
	now := g.now()
	k := learnKey{dst: dst, port: port, bin: name != "" && port != 80 && port != 443 && e.rules.NeedsBinary(name, port)}
	g.learnedMu.Lock()
	shadow := g.learned[id]
	if exp, ok := shadow[k]; ok && exp.Sub(now) > ttl/2 {
		g.learnedMu.Unlock()
		return nil
	}
	if _, ok := shadow[k]; !ok && g.liveLearnedLocked(id, now) >= g.maxLrn {
		g.learnedMu.Unlock()
		return ErrLearnedCap
	}
	g.learnedMu.Unlock()
	if err := g.be.Apply([]Op{{Set: k.set(), Elems: []Elem{{Src: e.spec.IP, Dst: dst, Port: port, Timeout: ttl}}}}); err != nil {
		return fmt.Errorf("%w: learned %s: %v", ErrUnavailable, id, err)
	}
	g.learnedMu.Lock()
	if g.learned[id] == nil {
		g.learned[id] = map[learnKey]time.Time{}
	}
	g.learned[id][k] = now.Add(ttl)
	if k.bin {
		if g.binNames[id] == nil {
			g.binNames[id] = map[learnKey]string{}
		}
		g.binNames[id][k] = name
	}
	g.learnedMu.Unlock()
	return nil
}

// BinName returns the name a bin_learned destination was answered for, for
// the proxy to decide a redirected flow (P3-3).
func (g *Gateway) BinName(id string, dst netip.AddrPort) (string, bool) {
	g.learnedMu.Lock()
	defer g.learnedMu.Unlock()
	name, ok := g.binNames[id][learnKey{dst: dst.Addr(), port: dst.Port(), bin: true}]
	return name, ok
}

func (g *Gateway) liveLearnedLocked(id string, now time.Time) int {
	n := 0
	for k, exp := range g.learned[id] {
		if exp.After(now) {
			n++
		} else {
			delete(g.learned[id], k)
			delete(g.binNames[id], k)
		}
	}
	return n
}

// flushLearned deletes a sandbox's learned elements exactly (the shadow map
// knows them) and forgets the shadow. The elements move to pendingLearned
// first and leave it only once the kernel delete succeeds.
func (g *Gateway) flushLearned(id string, src netip.Addr) {
	g.learnedMu.Lock()
	shadow := g.learned[id]
	delete(g.learned, id)
	delete(g.binNames, id)
	if len(shadow) > 0 {
		p := g.pendingLearned[src]
		if p == nil {
			p = map[string][]Elem{}
			g.pendingLearned[src] = p
		}
		for k := range shadow {
			e := Elem{Src: src, Dst: k.dst, Port: k.port}
			if !slices.Contains(p[k.set()], e) {
				p[k.set()] = append(p[k.set()], e)
			}
		}
	}
	g.learnedMu.Unlock()
	if err := g.retryLearnedFlush(src); err != nil {
		g.log.Warn("egress: flush learned elements failed; retrying", "sandbox_id", id, "src", src, "error", err)
	}
}

// retryLearnedFlush deletes src's pending learned elements. An element can
// expire on its own before the delete, and a delete of a missing element
// fails the whole nft transaction, so a failed batch is narrowed to what the
// kernel still holds and tried once more.
func (g *Gateway) retryLearnedFlush(src netip.Addr) error {
	g.learnedMu.Lock()
	pend := g.pendingLearned[src]
	g.learnedMu.Unlock()
	if len(pend) == 0 {
		return nil
	}
	ops := learnedDeleteOps(pend)
	err := g.be.Apply(ops)
	if err != nil {
		still := map[string][]Elem{}
		for set, elems := range pend {
			cur, lerr := g.be.List(set)
			if lerr != nil {
				return err
			}
			for _, e := range elems {
				if slices.ContainsFunc(cur, func(c Elem) bool { return key(c) == key(e) }) {
					still[set] = append(still[set], e)
				}
			}
		}
		if ops := learnedDeleteOps(still); len(ops) > 0 {
			if err = g.be.Apply(ops); err != nil {
				g.learnedMu.Lock()
				g.pendingLearned[src] = still
				g.learnedMu.Unlock()
				return err
			}
		}
	}
	g.learnedMu.Lock()
	delete(g.pendingLearned, src)
	g.learnedMu.Unlock()
	return nil
}

func learnedDeleteOps(bySet map[string][]Elem) []Op {
	var ops []Op
	for _, set := range []string{SetAllowLearned, SetBinLearned} {
		if elems := bySet[set]; len(elems) > 0 {
			ops = append(ops, Op{Set: set, Del: true, Elems: elems})
		}
	}
	return ops
}

// flushConntrack deletes established flows from ip. A failure is kept and
// retried, like a learned flush.
func (g *Gateway) flushConntrack(ip netip.Addr) {
	if g.ct == nil || !ip.IsValid() {
		return
	}
	g.learnedMu.Lock()
	g.pendingCT[ip] = struct{}{}
	g.learnedMu.Unlock()
	if err := g.retryConntrackFlush(ip); err != nil {
		g.log.Warn("egress: conntrack flush failed; retrying", "ip", ip, "error", err)
	}
}

func (g *Gateway) retryConntrackFlush(ip netip.Addr) error {
	g.learnedMu.Lock()
	_, pending := g.pendingCT[ip]
	g.learnedMu.Unlock()
	if !pending || g.ct == nil {
		return nil
	}
	if err := g.ct.FlushSource(ip); err != nil {
		return err
	}
	g.learnedMu.Lock()
	delete(g.pendingCT, ip)
	g.learnedMu.Unlock()
	return nil
}

// retryCleanup finishes the pending learned and conntrack cleanup of the
// given sources.
func (g *Gateway) retryCleanup(srcs ...netip.Addr) error {
	var errs []error
	for _, src := range srcs {
		if err := g.retryLearnedFlush(src); err != nil {
			errs = append(errs, fmt.Errorf("learned elements of %s: %w", src, err))
		}
		if err := g.retryConntrackFlush(src); err != nil {
			errs = append(errs, fmt.Errorf("conntrack of %s: %w", src, err))
		}
	}
	return errors.Join(errs...)
}

// RetryDirty re-drives every kernel write that failed: @blocked_src
// membership that differs from the wanted reasons, and pending learned and
// conntrack cleanup. The gateway's heartbeat runs it, so a transient nft or
// netlink failure is repaired without waiting for sandboxd.
func (g *Gateway) RetryDirty() error {
	g.opMu.RLock()
	defer g.opMu.RUnlock()
	g.mu.RLock()
	var dirty []string
	for id, e := range g.byID {
		if e.inBlockedSrc != e.kernelBlocked() {
			dirty = append(dirty, id)
		}
	}
	g.mu.RUnlock()
	var errs []error
	for _, id := range dirty {
		unlock := g.lockSandbox(id)
		g.mu.RLock()
		e := g.byID[id]
		g.mu.RUnlock()
		if e != nil && e.inBlockedSrc != e.kernelBlocked() {
			if err := g.applyBlockedLocked(e); err != nil {
				errs = append(errs, err)
			}
		}
		unlock()
	}
	g.learnedMu.Lock()
	set := map[netip.Addr]bool{}
	for src := range g.pendingLearned {
		set[src] = true
	}
	for src := range g.pendingCT {
		set[src] = true
	}
	for src := range g.sweepPending {
		set[src] = true
	}
	g.learnedMu.Unlock()
	for src := range set {
		if g.sweepPendingFor(src) {
			if err := g.resweep(src); err != nil {
				errs = append(errs, fmt.Errorf("sweep learned elements of %s: %w", src, err))
				continue
			}
		}
		if err := g.retryCleanup(src); err != nil {
			errs = append(errs, err)
			continue
		}
		// Clean now: lift the gateway's own block from the source's owner.
		g.mu.RLock()
		id := g.bySrc[src]
		g.mu.RUnlock()
		if id == "" {
			continue
		}
		unlock := g.lockSandbox(id)
		g.mu.RLock()
		e := g.byID[id]
		g.mu.RUnlock()
		if e != nil && e.blocked&BlockCleanup != 0 && !g.cleanupPending(src) {
			if err := g.setCleanupBlock(e, false); err != nil {
				errs = append(errs, err)
			}
		}
		unlock()
	}
	return errors.Join(errs...)
}

func (g *Gateway) sweepPendingFor(src netip.Addr) bool {
	g.learnedMu.Lock()
	defer g.learnedMu.Unlock()
	return g.sweepPending[src]
}

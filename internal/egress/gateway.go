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
	mode    Mode
	allow   []netip.Prefix
	deny    []netip.Prefix
	blocked BlockReason
	hash    string
}

// kernelBlocked is the block state reflected in @blocked_src. The restart
// block stays in memory (eng re-review D2).
func (e *entry) kernelBlocked() bool { return e.blocked&^BlockRestart != 0 }

type learnKey struct {
	dst  netip.Addr
	port uint16
}

// Gateway holds per-node gateway state and drives the Backend.
type Gateway struct {
	be      Backend
	layout  LayoutConfig
	ct      ConntrackFlusher
	maxLrn  int
	log     *slog.Logger
	now     func() time.Time
	sbLocks sync.Map // sandbox id -> *sync.Mutex (per-sandbox serialization)

	mu    sync.RWMutex
	byID  map[string]*entry
	bySrc map[netip.Addr]string

	learnedMu sync.Mutex
	learned   map[string]map[learnKey]time.Time // shadow of allow_learned (D18)

	connMu sync.Mutex
	conns  map[string]map[*TrackedConn]struct{}

	nwMu     sync.Mutex
	nodeWide NodeWide
}

// New builds a Gateway. Call Bootstrap before use.
func New(opts Options) *Gateway {
	g := &Gateway{
		be:      opts.Backend,
		layout:  opts.Layout,
		ct:      opts.Conntrack,
		maxLrn:  opts.LearnedMax,
		log:     opts.Logger,
		now:     opts.Now,
		byID:    map[string]*entry{},
		bySrc:   map[netip.Addr]string{},
		learned: map[string]map[learnKey]time.Time{},
		conns:   map[string]map[*TrackedConn]struct{}{},
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

func (g *Gateway) lockSandbox(id string) func() {
	v, _ := g.sbLocks.LoadOrStore(id, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
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
	pol, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: spec.AllowOut, DenyOut: spec.DenyOut, Mode: mode})
	if err != nil {
		return nil, fmt.Errorf("egress: sandbox %s: %w", spec.ID, err)
	}
	if pol.BlockAll() {
		// Block-all wins and nothing is redirected (EF-14): sandboxd keeps such
		// a sandbox out of gateway mode entirely.
		return nil, fmt.Errorf("egress: sandbox %s: block-all is not a gateway-mode policy", spec.ID)
	}
	e := &entry{spec: spec, pol: pol, blocked: spec.Blocked, hash: specHash(spec)}
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

// diffOps returns the ops that move the kernel from old's elements to nu's.
// Deletes come first in the batch; within one nft transaction the order only
// matters for readability, the commit is atomic.
func diffOps(old, nu *entry) []Op {
	var oldE, newE map[string][]Elem
	if old != nil {
		oldE = old.elements()
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
// sandbox a concurrent quota block just closed (Section 4).
func (g *Gateway) Attach(spec Spec) error {
	nu, err := compile(spec)
	if err != nil {
		return err
	}
	unlock := g.lockSandbox(spec.ID)
	defer unlock()

	g.mu.RLock()
	old := g.byID[spec.ID]
	prevOwner, owned := g.bySrc[spec.IP]
	g.mu.RUnlock()
	if old != nil {
		// Keep block reasons the gateway already holds (e.g. a hold set while
		// sandboxd computed this spec): blocks only lift via SetBlocked.
		nu.blocked |= old.blocked &^ BlockRestart
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
		g.flushLearned(spec.ID, old.spec.IP)
		g.flushConntrack(old.spec.IP)
		g.CloseConnsWhere(spec.ID, func(host string, port uint16) bool { return !nu.permits(host, port) })
	}
	if nu.kernelBlocked() && (old == nil || !old.kernelBlocked()) {
		g.closeConns(spec.ID)
		g.flushConntrack(spec.IP)
	}
	return nil
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
// tracked connections and conntrack entries. Callers hold its lock or are
// purging a previous owner from inside another sandbox's Attach.
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
	g.flushLearned(id, old.spec.IP)
	g.closeConns(id)
	g.flushConntrack(old.spec.IP)
	return nil
}

// SetBlocked sets or clears one block reason. The sandbox is in @blocked_src
// while any kernel reason is set; becoming blocked also closes its proxied
// connections and flushes its conntrack entries, so a sandbox at its quota
// can't keep downloading over flows already open (EF-13).
func (g *Gateway) SetBlocked(id string, reason BlockReason, on bool) error {
	unlock := g.lockSandbox(id)
	defer unlock()
	g.mu.RLock()
	cur := g.byID[id]
	g.mu.RUnlock()
	if cur == nil {
		return fmt.Errorf("%w: %s", ErrNotAttached, id)
	}
	nu := *cur
	if on {
		nu.blocked |= reason
	} else {
		nu.blocked &^= reason
	}
	if nu.blocked == cur.blocked {
		return nil
	}
	if cur.kernelBlocked() != nu.kernelBlocked() {
		op := Op{Set: SetBlockedSrc, Del: !nu.kernelBlocked(), Elems: []Elem{{Src: cur.spec.IP}}}
		if err := g.be.Apply([]Op{op}); err != nil {
			// The in-memory bit still makes the DNS filter and proxy deny.
			g.mu.Lock()
			if on {
				cur.blocked |= reason
			}
			g.mu.Unlock()
			return fmt.Errorf("%w: set blocked %s: %v", ErrUnavailable, id, err)
		}
	}
	g.mu.Lock()
	cur.blocked = nu.blocked
	g.mu.Unlock()
	if on {
		g.closeConns(id)
		g.flushConntrack(cur.spec.IP)
	}
	return nil
}

// Sync replaces the whole gateway state with sandboxd's (D13). Managed sets
// are replaced atomically. Learned elements and recordings survive for
// sandboxes whose policy is unchanged and are flushed for removed or changed
// ones. Sync also lifts the restart block.
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
	if err := g.be.Replace(contents); err != nil {
		return fmt.Errorf("%w: sync: %v", ErrUnavailable, err)
	}
	g.mu.Lock()
	prev := g.byID
	g.byID = next
	g.bySrc = map[netip.Addr]string{}
	for id, e := range next {
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
		g.flushLearned(id, old.spec.IP)
		if !ok {
			g.closeConns(id)
		}
	}
	g.sweepLearned(next, changed)
	return nil
}

// sweepLearned reconciles allow_learned against the synced state straight
// from the kernel. After a gateway restart the shadow map is empty, so the
// kernel is the only record: elements whose source no longer belongs to an
// attached, unchanged sandbox are deleted, and the rest seed the shadow with
// an already-due expiry (the next DNS answer refreshes them with one write).
func (g *Gateway) sweepLearned(next map[string]*entry, changed map[string]bool) {
	elems, err := g.be.List(SetAllowLearned)
	if err != nil {
		g.log.Warn("egress: list learned elements for sync failed", "error", err)
		return
	}
	owner := map[netip.Addr]string{}
	for id, e := range next {
		owner[e.spec.IP] = id
	}
	now := g.now()
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
		k := learnKey{dst: el.Dst, port: el.Port}
		if _, known := g.learned[id][k]; !known {
			g.learned[id][k] = now
		}
	}
	g.learnedMu.Unlock()
	if len(stale) > 0 {
		if err := g.be.Apply([]Op{{Set: SetAllowLearned, Del: true, Elems: stale}}); err != nil {
			g.log.Warn("egress: delete stale learned elements failed", "error", err)
		}
	}
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
	return Source{Spec: e.spec, Policy: e.pol, Mode: e.mode, Blocked: e.blocked}, true
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
	next := map[string]*entry{}
	bySrc := map[netip.Addr]string{}
	for _, s := range specs {
		e, err := compile(s)
		if err != nil {
			return err
		}
		e.blocked |= BlockRestart
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
	if !dst.Is4() {
		return fmt.Errorf("egress: learned destination %s is not IPv4", dst)
	}
	g.mu.RLock()
	e := g.byID[id]
	g.mu.RUnlock()
	if e == nil {
		return fmt.Errorf("%w: %s", ErrNotAttached, id)
	}
	now := g.now()
	k := learnKey{dst: dst, port: port}
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
	if err := g.be.Apply([]Op{{Set: SetAllowLearned, Elems: []Elem{{Src: e.spec.IP, Dst: dst, Port: port, Timeout: ttl}}}}); err != nil {
		return fmt.Errorf("%w: learned %s: %v", ErrUnavailable, id, err)
	}
	g.learnedMu.Lock()
	if g.learned[id] == nil {
		g.learned[id] = map[learnKey]time.Time{}
	}
	g.learned[id][k] = now.Add(ttl)
	g.learnedMu.Unlock()
	return nil
}

func (g *Gateway) liveLearnedLocked(id string, now time.Time) int {
	n := 0
	for k, exp := range g.learned[id] {
		if exp.After(now) {
			n++
		} else {
			delete(g.learned[id], k)
		}
	}
	return n
}

// flushLearned deletes a sandbox's learned elements exactly (the shadow map
// knows them) and forgets the shadow.
func (g *Gateway) flushLearned(id string, src netip.Addr) {
	g.learnedMu.Lock()
	shadow := g.learned[id]
	delete(g.learned, id)
	g.learnedMu.Unlock()
	if len(shadow) == 0 {
		return
	}
	elems := make([]Elem, 0, len(shadow))
	for k := range shadow {
		elems = append(elems, Elem{Src: src, Dst: k.dst, Port: k.port})
	}
	if err := g.be.Apply([]Op{{Set: SetAllowLearned, Del: true, Elems: elems}}); err != nil {
		// Elements expire on their own timeout; log and move on.
		g.log.Warn("egress: flush learned elements failed", "sandbox_id", id, "error", err)
	}
}

func (g *Gateway) flushConntrack(ip netip.Addr) {
	if g.ct == nil || !ip.IsValid() {
		return
	}
	if err := g.ct.FlushSource(ip); err != nil {
		g.log.Warn("egress: conntrack flush failed", "ip", ip, "error", err)
	}
}

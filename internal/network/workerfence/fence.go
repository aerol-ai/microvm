// Package workerfence keeps dropped WASM workers off the node's own
// services: loopback, the node's own addresses, link-local, the cloud
// metadata endpoints and the egress deny floor.
//
// A WASM worker runs tenant modules. It drops from root to a uid of its own
// (pkg/wasm/worker Confine), but the network is the node's: a worker that
// escaped its engine could still talk to whatever listens on loopback, and
// Caddy's admin API (127.0.0.1:2019, no auth) rewrites every route on the
// node or serves any file Caddy can read. The guest's own dials never get
// there (the egress dial guard refuses loopback, link-local and metadata
// for every policy), so the kernel has to refuse what the worker uid sends
// itself.
//
// One nftables table, inet TableName, with one base chain on the output
// hook. For packets a socket of the worker uid sends, in order:
//
//  1. replies from the guest listen host (GuestListenHost) on loopback
//     connections someone else opened are let through (ct direction
//     reply). Only root opens connections to a guest's listener
//     (sandboxd's readiness check and its exposed-port proxy); a worker
//     never opens one, so no worker can reach another tenant's listener,
//     whatever address it binds. Replies from any other loopback address
//     are dropped, so a worker that binds a port a node service uses on
//     127.0.0.1 (while that service restarts) cannot answer its clients.
//  2. a short list of exceptions the workers need (Allow): the audit
//     ingest, a name server, an upstream proxy, each one address and port.
//  3. drops for every range no egress policy can open (Blocked plus the
//     deny floor, Spec.Floor).
//  4. the node ports guests may reach on the node's own addresses
//     (Spec.NodePorts), then a drop for every other local address and
//     for the node's broadcast addresses (fib daddr type local and
//     broadcast: the node IP and every address the node has, kept current
//     by the kernel).
//
// nft's meta skuid is the uid of the process that made the socket, not of
// the one using it: a socket another uid made and handed to a worker is
// that uid's to the fence. So sandboxd never hands a worker a socket it
// made (pkg/wasm/worker guest_conn.go).
//
// Each Apply replaces the table in one netlink transaction; Check reads it
// back so the Fence can put back a table a firewall reload took away. The
// table is the whole fence: deleting it removes it.
package workerfence

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// TableName names the fence's table (`nft list table inet aerolvm_wasm_workers`).
const TableName = "aerolvm_wasm_workers"

// ChainName is its one base chain, on the output hook.
const ChainName = "output"

// GuestListenHost is where workers bind the guests' listeners while the
// fence is on, instead of 127.0.0.1. Only root connects to them (sandboxd's
// readiness check and its exposed-port proxy, which relays each request
// itself); the fence lets the worker uid answer those connections from
// this address only, and send nothing else on loopback. Every 127/8
// address is local on Linux: nothing has to configure it.
const GuestListenHost = "127.0.97.1"

// ReassertInterval paces the check that the table is still in the kernel,
// as the other host firewall tables are checked.
const ReassertInterval = 30 * time.Second

// ErrUnsupported means this platform has no nftables.
var ErrUnsupported = errors.New("wasm worker fence: nftables is not available on this platform")

// Blocked are the destinations the worker uid may not reach, beyond the
// exceptions, that no egress policy can open: the node over loopback,
// 0.0.0.0/8 (Linux connects it to the node), link-local (169.254/16 holds
// the metadata endpoints and fe80::/10 the node's own link addresses),
// multicast and broadcast, and every cloud metadata endpoint the dial
// guards refuse, wherever it sits.
func Blocked() []netip.Prefix {
	out := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("ff00::/8"),
	}
	return withPrefixes(out, egresspolicy.MetadataPrefixes)
}

// withPrefixes adds each of add that no prefix of out already covers.
func withPrefixes(out, add []netip.Prefix) []netip.Prefix {
	for _, p := range add {
		if !p.IsValid() || p.Bits() == 0 {
			// A /0 would cut the worker off from everything, the guests'
			// egress included: the floor never means that.
			continue
		}
		p = p.Masked()
		if !slices.ContainsFunc(out, func(b netip.Prefix) bool { return b.Overlaps(p) && b.Bits() <= p.Bits() }) {
			out = append(out, p)
		}
	}
	return out
}

// replyTo is where the worker uid may send replies from the guest listen
// host (rule 1 of the chain). Guest listeners are IPv4 only, so there is
// no IPv6 reply rule.
var replyTo = netip.MustParsePrefix("127.0.0.0/8")

// Allow is one exception: proto ("tcp" or "udp") to Prefix, on ports
// PortLo..PortHi. Why names it in the rule's comment.
type Allow struct {
	Proto  string
	Prefix netip.Prefix
	PortLo uint16
	PortHi uint16
	Why    string
}

// Spec is what the fence covers: the worker uid, its exceptions, and what
// else no sandbox may reach.
type Spec struct {
	UID   int
	Allow []Allow
	// Floor is the egress deny floor: the operator's deny_cidrs, the node's
	// extra floor and the floor file (egresspolicy). Only ranges no policy
	// can open belong here. The private ranges (RFC 1918 and the node's
	// extra private ranges) stay in the workers' Go dial guard alone: a
	// policy may open one of them for one sandbox, and this table is keyed
	// by the one uid every worker shares, so it cannot tell that sandbox's
	// worker from the others.
	Floor []netip.Prefix
	// NodePorts are the TCP ports guests may still reach on the node's own
	// non-loopback addresses (egresspolicy.NodeAllowedPorts: Caddy's 80 and
	// 443 on an ingress node, SB_SANDBOX_NODE_PORTS_ALLOW).
	NodePorts []uint16
	// Local are the node's own addresses with their prefix lengths, read
	// when the plan is made. The chain finds them itself (nft fib) where
	// the kernel can; NoFib, set by the Fence for a kernel without nft fib,
	// has Plan list each address and its subnet's broadcast address
	// instead, so the list is as fresh as the last sync.
	Local []netip.Prefix
	NoFib bool
}

// RuleKind is what a rule matches and does.
type RuleKind uint8

const (
	// KindDrop drops the uid's packets to Prefix.
	KindDrop RuleKind = iota
	// KindReply accepts the uid's replies from From to Prefix on
	// connections someone else opened.
	KindReply
	// KindAllow accepts Proto to the one address Prefix on PortLo..PortHi.
	KindAllow
	// KindAllowNAT accepts Proto on a connection the worker opened to the
	// one address Prefix on PortLo..PortHi that a NAT rule then sent
	// elsewhere: a resolver behind a port redirect (Docker's embedded DNS
	// turns 127.0.0.11:53 into 127.0.0.11:<port>) still answers the
	// worker. It matches the connection's original destination, so a NAT
	// rule that lands other traffic on an allowed address opens nothing.
	KindAllowNAT
	// KindLocalPort accepts TCP to any of the node's own addresses on
	// PortLo (a node port guests may reach).
	KindLocalPort
	// KindLocalDrop drops the uid's packets to any of the node's own
	// addresses.
	KindLocalDrop
	// KindBroadcastDrop drops the uid's packets to any of the node's
	// broadcast addresses (a subnet broadcast reaches the node's own UDP
	// services).
	KindBroadcastDrop
)

// Rule is one rule of the chain, in order.
type Rule struct {
	UID    int
	Kind   RuleKind
	From   netip.Addr // KindReply: the source address
	Proto  string     // KindAllow, KindAllowNAT: "tcp" or "udp"
	Prefix netip.Prefix
	PortLo uint16
	PortHi uint16
	Why    string
}

// Accepts reports whether the rule lets its packets through.
func (r Rule) Accepts() bool {
	return r.Kind != KindDrop && r.Kind != KindLocalDrop && r.Kind != KindBroadcastDrop
}

// Comment is the rule's nft comment; Check compares the kernel's rules by it.
func (r Rule) Comment() string {
	var b strings.Builder
	fmt.Fprintf(&b, "uid %d ", r.UID)
	switch r.Kind {
	case KindDrop:
		b.WriteString("drop " + r.Prefix.String())
	case KindReply:
		b.WriteString("accept reply " + r.From.String() + " -> " + r.Prefix.String())
	case KindAllow, KindAllowNAT:
		b.WriteString("accept " + r.Proto + " " + r.Prefix.String())
		if r.Kind == KindAllowNAT {
			b.WriteString(" nat")
		}
		if r.PortLo == r.PortHi {
			fmt.Fprintf(&b, " port %d", r.PortLo)
		} else {
			fmt.Fprintf(&b, " ports %d-%d", r.PortLo, r.PortHi)
		}
	case KindLocalPort:
		fmt.Fprintf(&b, "accept local tcp port %d", r.PortLo)
	case KindLocalDrop:
		b.WriteString("drop local")
	case KindBroadcastDrop:
		b.WriteString("drop broadcast")
	}
	if r.Why != "" {
		b.WriteString(" (" + r.Why + ")")
	}
	return b.String()
}

// Plan is the chain for spec, in the order the package comment gives:
// replies on loopback, every valid exception (sorted, once each), a drop
// per blocked or floor range, the node ports, then the drop for every
// local address. An exception with a bad protocol, address or ports, or
// one that names more than one address, is left out: it opens nothing.
func Plan(spec Spec) ([]Rule, error) {
	if spec.UID <= 0 {
		return nil, fmt.Errorf("wasm worker fence: uid %d is not a worker uid", spec.UID)
	}
	out := []Rule{{UID: spec.UID, Kind: KindReply, From: netip.MustParseAddr(GuestListenHost), Prefix: replyTo}}
	var allows []Rule
	for _, a := range spec.Allow {
		if a.Proto != "tcp" && a.Proto != "udp" || !a.Prefix.IsValid() || a.Prefix.Bits() != a.Prefix.Addr().BitLen() || a.PortLo == 0 || a.PortHi < a.PortLo {
			continue
		}
		p := netip.PrefixFrom(a.Prefix.Addr().Unmap(), a.Prefix.Addr().Unmap().BitLen())
		allows = append(allows,
			Rule{UID: spec.UID, Kind: KindAllow, Proto: a.Proto, Prefix: p, PortLo: a.PortLo, PortHi: a.PortHi, Why: a.Why},
			Rule{UID: spec.UID, Kind: KindAllowNAT, Proto: a.Proto, Prefix: p, PortLo: a.PortLo, PortHi: a.PortHi, Why: a.Why})
	}
	slices.SortFunc(allows, func(a, b Rule) int { return strings.Compare(a.Comment(), b.Comment()) })
	out = append(out, slices.CompactFunc(allows, func(a, b Rule) bool { return a.Comment() == b.Comment() })...)
	for _, p := range withPrefixes(Blocked(), spec.Floor) {
		out = append(out, Rule{UID: spec.UID, Kind: KindDrop, Prefix: p})
	}
	ports := slices.Clone(spec.NodePorts)
	slices.Sort(ports)
	ports = slices.DeleteFunc(slices.Compact(ports), func(p uint16) bool { return p == 0 })
	if spec.NoFib {
		return append(out, localByAddress(spec, ports)...), nil
	}
	for _, port := range ports {
		out = append(out, Rule{UID: spec.UID, Kind: KindLocalPort, PortLo: port, PortHi: port, Why: "node port"})
	}
	return append(out, Rule{UID: spec.UID, Kind: KindLocalDrop}, Rule{UID: spec.UID, Kind: KindBroadcastDrop}), nil
}

// localByAddress is the node-port, node-address and broadcast part of the
// chain for a kernel without nft fib: the same rules, one per address of
// spec.Local (loopback and link-local are dropped above already), and a
// drop for each IPv4 subnet's broadcast address and its network address.
// A kernel that still adds "broadcast <network>" to the local table (5.10
// does) delivers a datagram to the network address to the node's own UDP
// services on 0.0.0.0, as it does one to the broadcast address.
func localByAddress(spec Spec, ports []uint16) []Rule {
	var addrs, nets, bcasts []netip.Prefix
	for _, l := range spec.Local {
		a := l.Addr().Unmap()
		if !l.IsValid() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
			continue
		}
		addrs = append(addrs, netip.PrefixFrom(a, a.BitLen()))
		if n, b, ok := broadcastOf(netip.PrefixFrom(a, l.Bits())); ok {
			nets = append(nets, netip.PrefixFrom(n, 32))
			bcasts = append(bcasts, netip.PrefixFrom(b, 32))
		}
	}
	sortAddrs := func(ps []netip.Prefix) []netip.Prefix {
		slices.SortFunc(ps, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
		return slices.Compact(ps)
	}
	addrs, nets, bcasts = sortAddrs(addrs), sortAddrs(nets), sortAddrs(bcasts)
	var out []Rule
	for _, port := range ports {
		for _, p := range addrs {
			out = append(out, Rule{UID: spec.UID, Kind: KindAllow, Proto: "tcp", Prefix: p, PortLo: port, PortHi: port, Why: "node port"})
		}
	}
	for _, p := range addrs {
		out = append(out, Rule{UID: spec.UID, Kind: KindDrop, Prefix: p, Why: "node address"})
	}
	for _, p := range nets {
		out = append(out, Rule{UID: spec.UID, Kind: KindDrop, Prefix: p, Why: "node network address"})
	}
	for _, p := range bcasts {
		out = append(out, Rule{UID: spec.UID, Kind: KindDrop, Prefix: p, Why: "node broadcast"})
	}
	return out
}

// broadcastOf is an IPv4 subnet's network and broadcast addresses; none
// for IPv6, or for a /31 or /32, which have neither.
func broadcastOf(p netip.Prefix) (network, broadcast netip.Addr, ok bool) {
	if !p.Addr().Is4() || p.Bits() > 30 || p.Bits() < 1 {
		return netip.Addr{}, netip.Addr{}, false
	}
	b := p.Addr().As4()
	host := ^uint32(0) >> p.Bits()
	for i := range 4 {
		b[i] |= byte(host >> (24 - 8*i))
	}
	return p.Masked().Addr(), netip.AddrFrom4(b), true
}

// usesFib reports whether rules need the kernel's nft fib.
func usesFib(rules []Rule) bool {
	return slices.ContainsFunc(rules, func(r Rule) bool {
		return r.Kind == KindLocalPort || r.Kind == KindLocalDrop || r.Kind == KindBroadcastDrop
	})
}

// missingExpr reports an install the kernel refused for an expression it
// does not have (the module is absent): the only failure that falls back
// to listing the node's addresses.
func missingExpr(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EOPNOTSUPP)
}

// Key is a stable string for a plan, for change checks and logs.
func Key(rules []Rule) string {
	parts := make([]string, len(rules))
	for i, r := range rules {
		parts[i] = r.Comment()
	}
	return strings.Join(parts, "; ")
}

// Backend installs, checks and removes the table.
type Backend interface {
	Apply(rules []Rule) error
	Check(rules []Rule) (bool, error)
	Remove() error
}

// ready is 1 while the fence is in the kernel (/debug/vars
// aerolvm_wasm_worker_fence_ready).
var ready = expvar.NewInt("aerolvm_wasm_worker_fence_ready")

// Fence installs the table and keeps it there. Ensure is the gate a worker
// start asks (pkg/wasm/worker SetConfineGate): one atomic load once the
// fence is in, else one install attempt at a time. Run re-plans and checks
// it every tick.
type Fence struct {
	be     Backend
	plan   func() (Spec, error)
	logger *slog.Logger
	now    func() time.Time

	ok        atomic.Bool
	mu        sync.Mutex
	applied   string
	lastErr   string
	checkedAt time.Time
	reassert  time.Duration
	// noFib is set once an install with nft fib failed and the same plan
	// listing the node's addresses went in: this kernel has no fib.
	noFib bool
}

// New returns a fence over be; plan is asked for the spec on every sync,
// so an exception that moved (a new ingest port, an edited resolv.conf) is
// picked up by the next one.
func New(be Backend, plan func() (Spec, error), logger *slog.Logger) *Fence {
	if logger == nil {
		logger = slog.Default()
	}
	return &Fence{be: be, plan: plan, logger: logger, now: time.Now, reassert: ReassertInterval}
}

// Ensure installs the fence unless it is in already. It is the
// EnsureLayer4Ready pattern: a latch for the steady state, a mutex so
// concurrent callers make one attempt, and a failure leaves the latch open
// for the next caller to retry.
func (f *Fence) Ensure() error {
	if f.ok.Load() {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ok.Load() {
		return nil
	}
	return f.syncLocked(true)
}

// Ready reports whether the fence is in, without trying to install it.
func (f *Fence) Ready() bool { return f.ok.Load() }

// Run syncs every tick until ctx ends.
func (f *Fence) Run(ctx context.Context, tick time.Duration) {
	if tick <= 0 {
		tick = 5 * time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = f.Sync()
		}
	}
}

// Sync installs the fence when its plan changed or it is not in, and
// checks the kernel when the reassert is due, putting back a table
// something took away.
func (f *Fence) Sync() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.syncLocked(false)
}

func (f *Fence) syncLocked(force bool) error {
	now := f.now()
	spec, err := f.plan()
	var rules []Rule
	if err == nil {
		// Always the plan with nft fib first: a kernel that lacked it may
		// have it now (the module was loaded), and fib follows the node's
		// addresses at once where a listed plan is a sync behind.
		rules, err = Plan(spec)
	}
	key := Key(rules)
	repaired := false
	switch {
	case err != nil:
	case force || !f.ok.Load() || key != f.applied:
		err = f.be.Apply(rules)
		switch {
		case err == nil && f.noFib:
			f.noFib = false
			f.logger.Info("wasm worker fence: the kernel has nft fib now; the fence follows the node's addresses itself again", "table", "inet "+TableName)
		case err != nil && usesFib(rules) && missingExpr(err):
			rules, key, repaired, err = f.syncWithoutFib(spec, err, force, now)
		}
	case now.Sub(f.checkedAt) >= f.reassert:
		var in bool
		if in, err = f.be.Check(rules); err == nil && !in {
			err = f.be.Apply(rules)
			repaired = err == nil
		}
		f.checkedAt = now
	}
	if err != nil {
		err = fmt.Errorf("wasm worker fence: %w", err)
		f.ok.Store(false)
		ready.Set(0)
		f.applied = ""
		if err.Error() != f.lastErr {
			f.logger.Error("wasm worker fence not installed: workers that drop their privileges could reach the node's loopback services (Caddy's admin API) and the cloud metadata endpoints, so they are not started until it is",
				"table", "inet "+TableName, "error", err)
		}
		f.lastErr = err.Error()
		return err
	}
	if !f.ok.Load() || repaired || key != f.applied {
		msg := "wasm worker fence installed: the worker uid reaches none of the node's own addresses, link-local, metadata or deny-floor addresses beyond its exceptions, and opens no loopback connection"
		if repaired {
			msg = "wasm worker fence was missing and has been put back; something rewrote the host firewall"
		}
		f.logger.Info(msg, "table", "inet "+TableName, "uid", spec.UID, "rules", key)
	}
	f.applied, f.lastErr = key, ""
	if force || f.checkedAt.IsZero() {
		f.checkedAt = now
	}
	f.ok.Store(true)
	ready.Set(1)
	return nil
}

// syncWithoutFib is the sync for a kernel that refused the plan with nft
// fib (the fib expression is a module of its own, and some kernels lack
// it): the same plan with the node's own addresses listed. It is applied
// when it differs from what is in (an address came or went), and checked
// on the reassert schedule otherwise. When it cannot go in either, fib was
// not the problem and the first error stands. The caller holds mu.
func (f *Fence) syncWithoutFib(spec Spec, first error, force bool, now time.Time) ([]Rule, string, bool, error) {
	spec.NoFib = true
	rules, err := Plan(spec)
	if err != nil {
		return nil, "", false, first
	}
	key := Key(rules)
	repaired := false
	switch {
	case force || !f.ok.Load() || key != f.applied:
		if err := f.be.Apply(rules); err != nil {
			return nil, "", false, first
		}
	case now.Sub(f.checkedAt) >= f.reassert:
		in, cerr := f.be.Check(rules)
		if cerr == nil && !in {
			cerr = f.be.Apply(rules)
			repaired = cerr == nil
		}
		f.checkedAt = now
		if cerr != nil {
			return nil, "", false, cerr
		}
	}
	if !f.noFib {
		f.logger.Warn("wasm worker fence: this kernel has no nft fib; the fence lists the node's own addresses itself, refreshed on every sync",
			"table", "inet "+TableName, "fib_error", first)
	}
	f.noFib = true
	return rules, key, repaired, nil
}

// Nameservers are the addresses of resolv.conf's nameserver lines, the
// servers Go's resolver asks (workers resolve with it).
func Nameservers(resolvConf []byte) []netip.Addr {
	var out []netip.Addr
	for _, line := range strings.Split(string(resolvConf), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		host, _, _ := strings.Cut(f[1], "%") // fe80::1%eth0
		if a, err := netip.ParseAddr(host); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// HostAddrs is the addresses a proxy host names when it is an address
// literal or "localhost"; nil for a name, which the fence cannot follow.
func HostAddrs(host string) []netip.Addr {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}
	}
	return nil
}

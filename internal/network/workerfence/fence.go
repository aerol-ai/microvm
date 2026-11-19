// Package workerfence keeps dropped WASM workers off the node's own
// services: loopback, link-local and the cloud metadata endpoints.
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
// hook: packets a socket of the worker uid sends to Blocked are dropped,
// after a short list of exceptions the workers need (Allow): the audit
// ingest, the guests' own listeners, a loopback name server, a loopback
// upstream proxy. Each Apply replaces the table in one netlink transaction;
// Check reads it back so the Fence can put back a table a firewall reload
// took away. The table is the whole fence: deleting it removes it.
package workerfence

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// TableName names the fence's table (`nft list table inet aerolvm_wasm_workers`).
const TableName = "aerolvm_wasm_workers"

// ChainName is its one base chain, on the output hook.
const ChainName = "output"

// GuestListenHost is where workers bind the guests' listeners while the
// fence is on, instead of 127.0.0.1. A worker reaches its own guest's
// listener over loopback (it proxies an exposed port's requests), so the
// fence must let the worker uid reach the listeners and nothing else on
// loopback. A service bound to 127.0.0.1 (Caddy's admin API, a runtime's
// stream server) does not answer on another loopback address, so allowing
// this one address, on the ephemeral ports listeners get, opens no service
// that trusts loopback. Every 127/8 address is local on Linux: nothing has
// to configure it.
const GuestListenHost = "127.0.97.1"

// ReassertInterval paces the check that the table is still in the kernel,
// as the other host firewall tables are checked.
const ReassertInterval = 30 * time.Second

// ErrUnsupported means this platform has no nftables.
var ErrUnsupported = errors.New("wasm worker fence: nftables is not available on this platform")

// Blocked are the destinations the worker uid may not reach, beyond the
// exceptions: the node over loopback, link-local (169.254/16 holds the
// metadata endpoints and fe80::/10 the node's own link addresses), and
// every cloud metadata endpoint the dial guards refuse, wherever it sits.
func Blocked() []netip.Prefix {
	out := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("fe80::/10"),
	}
	for _, p := range egresspolicy.MetadataPrefixes {
		if !slices.ContainsFunc(out, func(b netip.Prefix) bool { return b.Overlaps(p) && b.Bits() <= p.Bits() }) {
			out = append(out, p)
		}
	}
	return out
}

// Allow is one exception: proto ("tcp" or "udp") to Prefix, on ports
// PortLo..PortHi. Why names it in the rule's comment.
type Allow struct {
	Proto  string
	Prefix netip.Prefix
	PortLo uint16
	PortHi uint16
	Why    string
}

// Spec is what the fence covers: the worker uid and its exceptions.
type Spec struct {
	UID   int
	Allow []Allow
}

// Rule is one rule of the chain, in order.
type Rule struct {
	UID    int
	Accept bool
	Proto  string // "" for any (drops)
	Prefix netip.Prefix
	PortLo uint16
	PortHi uint16
	Why    string
}

// Comment is the rule's nft comment; Check compares the kernel's rules by it.
func (r Rule) Comment() string {
	verdict := "drop"
	if r.Accept {
		verdict = "accept"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "uid %d %s", r.UID, verdict)
	if r.Proto != "" {
		b.WriteString(" " + r.Proto)
	}
	b.WriteString(" " + r.Prefix.String())
	if r.Proto != "" {
		if r.PortLo == r.PortHi {
			fmt.Fprintf(&b, " port %d", r.PortLo)
		} else {
			fmt.Fprintf(&b, " ports %d-%d", r.PortLo, r.PortHi)
		}
	}
	if r.Why != "" {
		b.WriteString(" (" + r.Why + ")")
	}
	return b.String()
}

// Plan is the chain for spec: every valid exception that lies inside a
// blocked range (one outside needs none), sorted and once each, then a drop
// per blocked range. An exception with a bad protocol, prefix or ports is
// left out: it opens nothing.
func Plan(spec Spec) ([]Rule, error) {
	if spec.UID <= 0 {
		return nil, fmt.Errorf("wasm worker fence: uid %d is not a worker uid", spec.UID)
	}
	blocked := Blocked()
	var allows []Rule
	for _, a := range spec.Allow {
		if a.Proto != "tcp" && a.Proto != "udp" || !a.Prefix.IsValid() || a.PortLo == 0 || a.PortHi < a.PortLo {
			continue
		}
		p := a.Prefix.Masked()
		if !slices.ContainsFunc(blocked, func(b netip.Prefix) bool { return b.Overlaps(p) }) {
			continue
		}
		allows = append(allows, Rule{UID: spec.UID, Accept: true, Proto: a.Proto, Prefix: p, PortLo: a.PortLo, PortHi: a.PortHi, Why: a.Why})
	}
	slices.SortFunc(allows, func(a, b Rule) int { return strings.Compare(a.Comment(), b.Comment()) })
	allows = slices.CompactFunc(allows, func(a, b Rule) bool { return a.Comment() == b.Comment() })
	out := allows
	for _, p := range blocked {
		out = append(out, Rule{UID: spec.UID, Prefix: p})
	}
	return out, nil
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
		rules, err = Plan(spec)
	}
	key := Key(rules)
	repaired := false
	switch {
	case err != nil:
	case force || !f.ok.Load() || key != f.applied:
		err = f.be.Apply(rules)
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
		msg := "wasm worker fence installed: the worker uid reaches no loopback, link-local or metadata address beyond its exceptions"
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

// PortRange parses /proc/sys/net/ipv4/ip_local_port_range ("32768\t60999"),
// the ports a listener bound to port 0 gets.
func PortRange(raw []byte) (uint16, uint16, error) {
	f := strings.Fields(string(raw))
	if len(f) != 2 {
		return 0, 0, fmt.Errorf("ip_local_port_range %q", strings.TrimSpace(string(raw)))
	}
	lo, err1 := strconv.ParseUint(f[0], 10, 16)
	hi, err2 := strconv.ParseUint(f[1], 10, 16)
	if err1 != nil || err2 != nil || lo == 0 || hi < lo {
		return 0, 0, fmt.Errorf("ip_local_port_range %q", strings.TrimSpace(string(raw)))
	}
	return uint16(lo), uint16(hi), nil
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

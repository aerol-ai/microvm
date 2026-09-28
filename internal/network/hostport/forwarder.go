// Package hostport forwards raw-TCP host ports in the kernel
// (plans/ingress-proxy-routing.md §3.5, task T7, decision "kernel DNAT").
//
// Raw-TCP exposures used to be one Caddy layer4 server per host port. Every
// expose, unexpose, stop and failover was a Caddy config write, and each write
// reloads Caddy's whole config. Moving them into sandboxd userspace would have
// reset every TCP session on each sandboxd restart, because an accepted socket
// dies with its process. Kernel forwarding avoids both: bytes never touch
// sandboxd, sessions live in conntrack and survive any sandboxd restart, and
// sandboxd only programs rules.
//
//	nat    PREROUTING / OUTPUT (dst-type LOCAL) ─▶ AEROLVM-HOSTPORT
//	         -p tcp --dport HP  -j DNAT --to ip:port    owner → container
//	                                                    ingress → owner:HP
//	         -p tcp --dport HP  -j REDIRECT --to-ports R  wake / WASM / isolate
//	                                                    (sandboxd splices; it
//	                                                    reads SO_ORIGINAL_DST)
//	nat    POSTROUTING ─▶ AEROLVM-HOSTPORT-POST
//	         -p tcp -d ip --dport port -j MASQUERADE    ingress → owner hop only,
//	                                                    so replies return here
//	filter FORWARD (pos 1) ─▶ AEROLVM-HOSTPORT-FWD
//	         -p tcp -m conntrack --ctstate DNAT --ctorigdstport HP -j ACCEPT
//	         both directions of the DNAT'd connection, ahead of any DROP policy
//
// net.ipv4.ip_forward is switched on at bootstrap. A pure ingress node runs
// no sandbox runtime, so nothing else enables it, and the kernel silently
// dropped every DNAT'd packet bound for a remote owner. Found live on
// cluster-hetero-lite-routing: every raw-TCP dial through the ingress-only
// node timed out.
//
// Every rule carries the comment "aerolvm-hp-<HP>", so Reconcile can find
// drift after a restart without trusting in-memory state. Removing a port
// also flushes its conntrack entries: without that, DNAT'd sessions outlive
// the rule and an unexpose would not actually cut access.
package hostport

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	ChainNAT  = "AEROLVM-HOSTPORT"
	ChainPost = "AEROLVM-HOSTPORT-POST"
	ChainFwd  = "AEROLVM-HOSTPORT-FWD"

	commentPrefix = "aerolvm-hp-"
)

// Backend is the iptables subset the forwarder needs. It is implemented by
// NewIPTablesBackend in production and by an in-memory table in tests.
type Backend interface {
	ChainExists(table, chain string) (bool, error)
	NewChain(table, chain string) error
	Exists(table, chain string, spec ...string) (bool, error)
	Insert(table, chain string, pos int, spec ...string) error
	Append(table, chain string, spec ...string) error
	Delete(table, chain string, spec ...string) error
	// List returns a chain's rules in iptables-save form ("-A CHAIN ...").
	List(table, chain string) ([]string, error)
}

// ConntrackFlusher drops tracked TCP connections whose original destination
// port is hostPort. Linux uses netlink; elsewhere it is a no-op.
type ConntrackFlusher func(hostPort int) error

// Kind is how a host port is forwarded.
type Kind int

const (
	// DNAT rewrites to Addr. Masquerade is set for a remote target (the
	// ingress → owner hop), so the owner replies to this node.
	DNAT Kind = iota
	// Redirect delivers to the local sandboxd listener on RedirectPort, for
	// targets the kernel can't reach directly: stopped/wake sandboxes, and
	// WASM/isolate loopback mediators.
	Redirect
)

// Target is where one host port goes.
type Target struct {
	Kind         Kind
	Addr         netip.AddrPort
	Masquerade   bool
	RedirectPort int
}

func (t Target) valid() error {
	switch t.Kind {
	case DNAT:
		if !t.Addr.IsValid() || t.Addr.Port() == 0 {
			return fmt.Errorf("hostport: DNAT target needs ip:port")
		}
		if t.Addr.Addr().IsLoopback() {
			return fmt.Errorf("hostport: cannot DNAT external traffic to loopback %s; use Redirect", t.Addr)
		}
	case Redirect:
		if t.RedirectPort <= 0 || t.RedirectPort > 65535 {
			return fmt.Errorf("hostport: invalid redirect port %d", t.RedirectPort)
		}
	default:
		return fmt.Errorf("hostport: unknown kind %d", t.Kind)
	}
	return nil
}

// Forwarder owns the three chains and the per-port rules.
type Forwarder struct {
	b     Backend
	flush ConntrackFlusher

	ready  atomic.Bool
	bootMu sync.Mutex

	mu    sync.Mutex
	rules map[int]Target
}

func New(b Backend, flush ConntrackFlusher) *Forwarder {
	return &Forwarder{b: b, flush: flush, rules: map[int]Target{}}
}

func comment(hp int) []string {
	return []string{"-m", "comment", "--comment", commentPrefix + strconv.Itoa(hp)}
}

// ensureChains creates the chains and their jumps once. The atomic.Bool fast
// path plus mutex single-flight follows the EnsureLayer4Ready pattern.
func (f *Forwarder) ensureChains() error {
	if f.ready.Load() {
		return nil
	}
	f.bootMu.Lock()
	defer f.bootMu.Unlock()
	if f.ready.Load() {
		return nil
	}
	for _, c := range []struct{ table, chain string }{{"nat", ChainNAT}, {"nat", ChainPost}, {"filter", ChainFwd}} {
		ok, err := f.b.ChainExists(c.table, c.chain)
		if err != nil {
			return fmt.Errorf("hostport: check chain %s/%s: %w", c.table, c.chain, err)
		}
		if !ok {
			if err := f.b.NewChain(c.table, c.chain); err != nil {
				return fmt.Errorf("hostport: create chain %s/%s: %w", c.table, c.chain, err)
			}
		}
	}
	local := []string{"-m", "addrtype", "--dst-type", "LOCAL", "-j", ChainNAT}
	jumps := []struct {
		table, chain string
		spec         []string
	}{
		{"nat", "PREROUTING", local},
		{"nat", "OUTPUT", local},
		{"nat", "POSTROUTING", []string{"-j", ChainPost}},
		{"filter", "FORWARD", []string{"-j", ChainFwd}},
	}
	for _, j := range jumps {
		ok, err := f.b.Exists(j.table, j.chain, j.spec...)
		if err != nil {
			return fmt.Errorf("hostport: check jump %s/%s: %w", j.table, j.chain, err)
		}
		if !ok {
			// Position 1: ahead of Docker/CNI chains, which may DROP or
			// DNAT the same traffic first.
			if err := f.b.Insert(j.table, j.chain, 1, j.spec...); err != nil {
				return fmt.Errorf("hostport: insert jump %s/%s: %w", j.table, j.chain, err)
			}
		}
	}
	if err := enableIPForward(); err != nil {
		return fmt.Errorf("hostport: enable net.ipv4.ip_forward (DNAT to a remote owner needs it): %w", err)
	}
	f.ready.Store(true)
	return nil
}

// enableIPForward is a seam over the platform sysctl write (tests replace it).
var enableIPForward = platformEnableIPForward

func natSpec(hp int, t Target) []string {
	s := []string{"-p", "tcp", "--dport", strconv.Itoa(hp)}
	s = append(s, comment(hp)...)
	if t.Kind == Redirect {
		return append(s, "-j", "REDIRECT", "--to-ports", strconv.Itoa(t.RedirectPort))
	}
	return append(s, "-j", "DNAT", "--to-destination", t.Addr.String())
}

// fwdSpec accepts BOTH directions of hp's DNAT'd connections. The conntrack
// match keys on the connection's original destination port (the host port),
// so replies from the owner pass too. Matching "-d target --dport port"
// covered only the original direction, and relied on some other rule to
// accept the replies. A pure ingress node has no such rule.
func fwdSpec(hp int, _ Target) []string {
	s := []string{"-p", "tcp", "-m", "conntrack", "--ctstate", "DNAT", "--ctorigdstport", strconv.Itoa(hp)}
	return append(append(s, comment(hp)...), "-j", "ACCEPT")
}

func postSpec(hp int, t Target) []string {
	s := []string{"-p", "tcp", "-d", t.Addr.Addr().String(), "--dport", strconv.Itoa(int(t.Addr.Port()))}
	return append(append(s, comment(hp)...), "-j", "MASQUERADE")
}

// Ensure forwards hp to t, idempotently. A changed target replaces the old
// rules. Sessions already tracked keep their original mapping until they
// end; that is how a sandbox wake (Redirect → DNAT) keeps the connection
// that woke it.
func (f *Forwarder) Ensure(hp int, t Target) error {
	if hp <= 0 || hp > 65535 {
		return fmt.Errorf("hostport: invalid host port %d", hp)
	}
	if err := t.valid(); err != nil {
		return err
	}
	if err := f.ensureChains(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur, ok := f.rules[hp]; ok {
		if cur == t {
			return f.ensureRulesLocked(hp, t) // re-assert (someone may have flushed)
		}
		if err := f.deleteRulesLocked(hp, cur); err != nil {
			return err
		}
	}
	if err := f.ensureRulesLocked(hp, t); err != nil {
		return err
	}
	f.rules[hp] = t
	return nil
}

func (f *Forwarder) ensureRulesLocked(hp int, t Target) error {
	add := func(table, chain string, spec []string) error {
		ok, err := f.b.Exists(table, chain, spec...)
		if err != nil {
			return fmt.Errorf("hostport: check %s/%s hp=%d: %w", table, chain, hp, err)
		}
		if ok {
			return nil
		}
		if err := f.b.Append(table, chain, spec...); err != nil {
			return fmt.Errorf("hostport: append %s/%s hp=%d: %w", table, chain, hp, err)
		}
		return nil
	}
	// Accept/masquerade before the DNAT, so the moment traffic is rewritten
	// it is already allowed through.
	if t.Kind == DNAT {
		if err := add("filter", ChainFwd, fwdSpec(hp, t)); err != nil {
			return err
		}
		if t.Masquerade {
			if err := add("nat", ChainPost, postSpec(hp, t)); err != nil {
				return err
			}
		}
	}
	return add("nat", ChainNAT, natSpec(hp, t))
}

func (f *Forwarder) deleteRulesLocked(hp int, t Target) error {
	del := func(table, chain string, spec []string) error {
		ok, err := f.b.Exists(table, chain, spec...)
		if err != nil {
			return fmt.Errorf("hostport: check %s/%s hp=%d: %w", table, chain, hp, err)
		}
		if !ok {
			return nil
		}
		if err := f.b.Delete(table, chain, spec...); err != nil {
			return fmt.Errorf("hostport: delete %s/%s hp=%d: %w", table, chain, hp, err)
		}
		return nil
	}
	// DNAT first: once it is gone no new traffic is rewritten, so removing
	// the accept/masquerade next cannot strand a half-forwarded flow.
	if err := del("nat", ChainNAT, natSpec(hp, t)); err != nil {
		return err
	}
	if t.Kind == DNAT {
		if err := del("filter", ChainFwd, fwdSpec(hp, t)); err != nil {
			return err
		}
		if t.Masquerade {
			if err := del("nat", ChainPost, postSpec(hp, t)); err != nil {
				return err
			}
		}
	}
	return nil
}

// Remove stops forwarding hp and flushes its tracked connections, so an
// unexpose actually cuts access. It is idempotent.
func (f *Forwarder) Remove(hp int) error {
	f.mu.Lock()
	cur, ok := f.rules[hp]
	if ok {
		if err := f.deleteRulesLocked(hp, cur); err != nil {
			f.mu.Unlock()
			return err
		}
		delete(f.rules, hp)
	}
	f.mu.Unlock()
	if !ok {
		// Not ours in memory. After a restart a stale rule may still exist
		// in the kernel; Reconcile is the authority for those.
		return nil
	}
	if f.flush != nil {
		if err := f.flush(hp); err != nil {
			return fmt.Errorf("hostport: flush conntrack hp=%d: %w", hp, err)
		}
	}
	return nil
}

// Reconcile makes the kernel match desired exactly. Rules this forwarder owns
// (by comment) that are not desired, or no longer match, are deleted, and
// their conntrack entries flushed. Every desired rule is ensured. It runs at
// boot and periodically, so drift from a restart, a manual flush or a
// crashed apply heals, and nothing is inferred from in-memory state alone.
func (f *Forwarder) Reconcile(desired map[int]Target) error {
	for hp, t := range desired {
		if hp <= 0 || hp > 65535 {
			return fmt.Errorf("hostport: invalid host port %d", hp)
		}
		if err := t.valid(); err != nil {
			return fmt.Errorf("hostport: hp=%d: %w", hp, err)
		}
	}
	if err := f.ensureChains(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reconcileLocked(desired)
}

// PruneUnasserted is Reconcile with desired = every rule asserted through
// Ensure since this process started. Call it after the boot re-assert pass
// (owner reconcile + ingress reconcile) has replayed every live exposure:
// what's left in the kernel belongs to exposures that went away while
// sandboxd was down. Stale rules are dangerous: a reused container IP
// would expose the new sandbox's port. The desired set is taken under the
// same lock, so a concurrent Ensure is never pruned.
func (f *Forwarder) PruneUnasserted() error {
	if err := f.ensureChains(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	desired := make(map[int]Target, len(f.rules))
	for hp, t := range f.rules {
		desired[hp] = t
	}
	return f.reconcileLocked(desired)
}

func (f *Forwarder) reconcileLocked(desired map[int]Target) error {
	stale := map[int]bool{}
	for _, c := range []struct{ table, chain string }{{"nat", ChainNAT}, {"nat", ChainPost}, {"filter", ChainFwd}} {
		rules, err := f.b.List(c.table, c.chain)
		if err != nil {
			return fmt.Errorf("hostport: list %s/%s: %w", c.table, c.chain, err)
		}
		for _, r := range rules {
			spec, hp, ours := parseRule(r, c.chain)
			if !ours {
				continue
			}
			// Compare by MEANING, not text: iptables normalizes what it lists
			// ("-m tcp" after "-p tcp", "-d 10.0.0.5/32"), so a textual
			// compare would call every rule stale and churn it, leaving a
			// window with no forwarding for new connections.
			if t, ok := desired[hp]; ok && ruleMatches(c.chain, spec, hp, t) {
				continue
			}
			if err := f.b.Delete(c.table, c.chain, spec...); err != nil {
				return fmt.Errorf("hostport: delete stale %s/%s %q: %w", c.table, c.chain, r, err)
			}
			if _, keep := desired[hp]; !keep {
				stale[hp] = true
			}
		}
	}
	next := make(map[int]Target, len(desired))
	for hp, t := range desired {
		if err := f.ensureRulesLocked(hp, t); err != nil {
			return err
		}
		next[hp] = t
	}
	f.rules = next
	if f.flush != nil {
		ports := make([]int, 0, len(stale))
		for hp := range stale {
			ports = append(ports, hp)
		}
		sort.Ints(ports)
		for _, hp := range ports {
			if err := f.flush(hp); err != nil {
				return fmt.Errorf("hostport: flush conntrack hp=%d: %w", hp, err)
			}
		}
	}
	return nil
}

// ruleMatches reports whether a listed rule in chain is exactly what target t
// needs, read semantically from its spec.
func ruleMatches(chain string, spec []string, hp int, t Target) bool {
	val := func(flag string) string {
		for i := 0; i+1 < len(spec); i++ {
			if spec[i] == flag {
				return strings.TrimSuffix(spec[i+1], "/32")
			}
		}
		return ""
	}
	jump := val("-j")
	switch chain {
	case ChainNAT:
		if t.Kind == Redirect {
			return jump == "REDIRECT" && val("--to-ports") == strconv.Itoa(t.RedirectPort)
		}
		return jump == "DNAT" && val("--to-destination") == t.Addr.String()
	case ChainFwd:
		return t.Kind == DNAT && jump == "ACCEPT" &&
			val("--ctstate") == "DNAT" && val("--ctorigdstport") == strconv.Itoa(hp)
	case ChainPost:
		return t.Kind == DNAT && t.Masquerade && jump == "MASQUERADE" &&
			val("-d") == t.Addr.Addr().String() && val("--dport") == strconv.Itoa(int(t.Addr.Port()))
	}
	return false
}

// parseRule reads an iptables-save line ("-A CHAIN <spec>"). It reports
// whether the rule is ours (it carries our comment) and for which host port.
func parseRule(line, chain string) (spec []string, hp int, ours bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "-A" || fields[1] != chain {
		return nil, 0, false
	}
	spec = fields[2:]
	for i := 0; i+1 < len(spec); i++ {
		if spec[i] == "--comment" {
			c := strings.Trim(spec[i+1], `"`)
			spec[i+1] = c
			if n, ok := strings.CutPrefix(c, commentPrefix); ok {
				if v, err := strconv.Atoi(n); err == nil {
					return spec, v, true
				}
			}
		}
	}
	return spec, 0, false
}

// Ports lists the host ports currently forwarded (in memory), sorted.
func (f *Forwarder) Ports() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]int, 0, len(f.rules))
	for hp := range f.rules {
		out = append(out, hp)
	}
	sort.Ints(out)
	return out
}

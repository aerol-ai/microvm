package netrules

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
)

// ruleNotExist reports whether a delete failed only because the rule was
// already absent. The message differs by iptables flavor: legacy says
// "No chain/target/match by that name", iptables-nft (Ubuntu 22.04's
// default) says "Bad rule (does a matching rule exist in that chain?)".
// go-iptables' typed error knows every flavor; the string fallback covers
// backends that return plain errors (the RuleBackend test seam). Matching
// only the legacy string here is exactly the bug that made every warm-pool
// adopt fail on iptables-nft hosts: the duplicate-sweep loop's terminating
// "rule gone" probe read as a fatal error.
func ruleNotExist(err error) bool {
	if err == nil {
		return false
	}
	var iptErr *iptables.Error
	if errors.As(err, &iptErr) {
		return iptErr.IsNotExist()
	}
	msg := err.Error()
	return strings.Contains(msg, "No chain/target/match") ||
		strings.Contains(msg, "does a matching rule exist") ||
		strings.Contains(msg, "does not exist")
}

// RuleBackend is the subset of iptables operations the Manager drives.
// Production always wraps *go-iptables' IPTables; tests substitute an
// in-memory backend so rule-state semantics (which rules survive an adopt,
// a clear, a reapply) are assertable without root or a linux host.
type RuleBackend interface {
	Exists(table, chain string, rulespec ...string) (bool, error)
	Insert(table, chain string, pos int, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
}

type Manager struct {
	enabled bool
	ipt     RuleBackend
	// userChain is the filter-table chain for per-IP rules (DOCKER-USER on
	// dockerd hosts, AEROLVM-USER under containerd). Empty defaults to
	// ChainDockerUser so existing docker-only wiring is unchanged.
	userChain string
	// ipMu guards ipLocks. Per-IP mutexes serialize Exists+Insert for one
	// container IP (poller / reconcile / SetNetworkLimits / Destroy can all
	// drive the same IP concurrently). Without per-IP exclusion, two callers
	// can both pass Exists and both Insert, leaving a duplicate that a
	// single Delete in Clear* won't fully remove.
	//
	// Sharding by IP (vs one global mu) lets concurrent creates for different
	// sandboxes proceed in parallel so netrules does not head-of-line-block
	// warm-create p99 under burst. Same-IP mutual exclusion is preserved.
	ipMu    sync.Mutex
	ipLocks map[string]*ipLock
}

// ipLock is a refcounted per-IP mutex. Refs track in-flight holders so idle
// entries can be dropped — docker bridge IPs churn over a daemon lifetime.
type ipLock struct {
	mu   sync.Mutex
	refs int
}

// Backend names for SB_NETRULES_BACKEND.
const (
	BackendExec    = "exec"
	BackendNetlink = "netlink"

	ChainDockerUser  = "DOCKER-USER"
	ChainAerolvmUser = "AEROLVM-USER"
)

func (m *Manager) filterChain() string {
	if m == nil || strings.TrimSpace(m.userChain) == "" {
		return ChainDockerUser
	}
	return m.userChain
}

func New(enabled bool) (*Manager, error) {
	return NewWithOptions(enabled, BackendExec, "")
}

// NewWithOptions builds a Manager with the chosen RuleBackend. userChain
// selects the filter chain for per-IP rules; empty defaults to DOCKER-USER.
// Unknown backend names fall back to exec with an error so misconfig is loud.
func NewWithOptions(enabled bool, backend, userChain string) (*Manager, error) {
	if strings.TrimSpace(userChain) == "" {
		userChain = ChainDockerUser
	}
	if !enabled || runtime.GOOS != "linux" {
		recordBackendSelected("disabled")
		return &Manager{enabled: false, userChain: userChain}, nil
	}

	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "", BackendExec:
		ipt, err := iptables.New()
		if err != nil {
			return nil, fmt.Errorf("create iptables client: %w", err)
		}
		recordBackendSelected(BackendExec)
		return &Manager{enabled: true, ipt: ipt, userChain: userChain}, nil
	case BackendNetlink:
		nl, err := NewNetlinkBackend()
		if err != nil {
			return nil, fmt.Errorf("create netlink netrules backend: %w", err)
		}
		recordBackendSelected(BackendNetlink)
		return &Manager{enabled: true, ipt: nl, userChain: userChain}, nil
	default:
		return nil, fmt.Errorf("unknown netrules backend %q (want exec|netlink)", backend)
	}
}

// NewWithBackend builds an enabled Manager over an injected backend. Test
// seam only — production wiring goes through New.
func NewWithBackend(backend RuleBackend) *Manager {
	return &Manager{enabled: backend != nil, ipt: backend}
}

func (m *Manager) Enabled() bool {
	return m != nil && m.enabled
}

// lockIP acquires the per-container-IP mutex and returns the unlock func.
// Callers must defer the result. Empty IP is a no-op (public methods already
// short-circuit before locking).
func (m *Manager) lockIP(ip string) func() {
	if m == nil || ip == "" {
		return func() {}
	}
	m.ipMu.Lock()
	if m.ipLocks == nil {
		m.ipLocks = make(map[string]*ipLock)
	}
	l := m.ipLocks[ip]
	if l == nil {
		l = &ipLock{}
		m.ipLocks[ip] = l
	}
	l.refs++
	m.ipMu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		m.ipMu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(m.ipLocks, ip)
		}
		m.ipMu.Unlock()
	}
}

// BlockAllEgress installs a DROP rule for traffic originating from
// containerIP. The rule lives in DOCKER-USER, the chain Docker explicitly
// reserves for operator-defined firewall rules. DOCKER-USER is jumped from
// FORWARD *before* DOCKER-FORWARD, so our DROP fires before Docker's
// blanket "iifname docker0 accept" rule that would otherwise short-circuit
// any rule appended directly to FORWARD. This works on iptables-legacy and
// on Docker 28+/iptables-nft (which writes through to nftables) alike.
func (m *Manager) BlockAllEgress(containerIP string) error {
	if !m.Enabled() || containerIP == "" {
		return nil
	}
	unlock := m.lockIP(containerIP)
	defer unlock()

	exists, err := m.ipt.Exists("filter", m.filterChain(), "-s", containerIP, "-j", "DROP")
	if err != nil {
		return fmt.Errorf("check existing egress rule: %w", err)
	}
	if exists {
		return nil
	}

	if err := m.ipt.Insert("filter", m.filterChain(), 1, "-s", containerIP, "-j", "DROP"); err != nil {
		return fmt.Errorf("insert egress rule: %w", err)
	}

	return nil
}

func (m *Manager) ClearBlockAllEgress(containerIP string) error {
	if !m.Enabled() || containerIP == "" {
		return nil
	}
	unlock := m.lockIP(containerIP)
	defer unlock()

	if err := m.deleteUntilGone("filter", m.filterChain(), "-s", containerIP, "-j", "DROP"); err != nil {
		return fmt.Errorf("delete egress rule: %w", err)
	}
	return nil
}

// BlockAllIngress installs a DROP rule for traffic destined for containerIP,
// the mirror of BlockAllEgress on the destination axis. Used by the network
// quota enforcer when net_bytes_in_limit is crossed. The honest caveat (also
// documented in plans/network-usage-tracking.md): host-side ingress is
// counted after the NIC has accepted the packet, so the meter is "what the
// container would have seen" rather than "bytes spent on the wire." Same
// chain (DOCKER-USER) and idempotency check pattern as the egress mirror.
func (m *Manager) BlockAllIngress(containerIP string) error {
	if !m.Enabled() || containerIP == "" {
		return nil
	}
	unlock := m.lockIP(containerIP)
	defer unlock()

	exists, err := m.ipt.Exists("filter", m.filterChain(), "-d", containerIP, "-j", "DROP")
	if err != nil {
		return fmt.Errorf("check existing ingress rule: %w", err)
	}
	if exists {
		return nil
	}

	if err := m.ipt.Insert("filter", m.filterChain(), 1, "-d", containerIP, "-j", "DROP"); err != nil {
		return fmt.Errorf("insert ingress rule: %w", err)
	}

	return nil
}

func (m *Manager) ClearBlockAllIngress(containerIP string) error {
	if !m.Enabled() || containerIP == "" {
		return nil
	}
	unlock := m.lockIP(containerIP)
	defer unlock()

	if err := m.deleteUntilGone("filter", m.filterChain(), "-d", containerIP, "-j", "DROP"); err != nil {
		return fmt.Errorf("delete ingress rule: %w", err)
	}
	return nil
}

// egressPolicyComment tags every selective-egress rule (allowlist/blocklist) so
// it is distinguishable from the blanket BlockAllEgress / quota DROP, which
// carry no comment. This matters because an allowlist's catch-all is also
// "-s IP -j DROP": without the comment it would be the *same* iptables rule as
// the full-block DROP, and a quota-driven ClearBlockAllEgress would silently
// punch a hole in the allowlist. The comment keeps the two mechanisms disjoint.
const egressPolicyComment = "sbx-egress"

// ApplyEgressPolicy installs a per-container selective egress policy in
// DOCKER-USER, scoped by source IP and comment-tagged (see egressPolicyComment).
// Exactly one mode is expected (callers validate mutual exclusivity):
//   - allowCIDRs non-empty → allowlist: ACCEPT each CIDR, DROP everything else.
//   - denyCIDRs non-empty  → blocklist: DROP each CIDR, leave the rest to
//     Docker's default ACCEPT.
//
// Re-apply is idempotent: every rule is Exists-checked before Insert, so the
// start/reconcile reapply paths can call this repeatedly without duplicating.
func (m *Manager) ApplyEgressPolicy(containerIP string, allowCIDRs, denyCIDRs []string) error {
	if !m.Enabled() || containerIP == "" {
		return nil
	}
	unlock := m.lockIP(containerIP)
	defer unlock()

	if len(allowCIDRs) > 0 {
		// The catch-all DROP must sit BELOW the per-CIDR ACCEPTs. Insert the
		// DROP first, then each ACCEPT at position 1 so it lands above the DROP.
		if err := m.ensurePolicyRule("-s", containerIP, "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP"); err != nil {
			return err
		}
		for _, cidr := range allowCIDRs {
			if err := m.ensurePolicyRule("-s", containerIP, "-d", cidr, "-m", "comment", "--comment", egressPolicyComment, "-j", "ACCEPT"); err != nil {
				return err
			}
		}
		return nil
	}
	for _, cidr := range denyCIDRs {
		if err := m.ensurePolicyRule("-s", containerIP, "-d", cidr, "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP"); err != nil {
			return err
		}
	}
	return nil
}

// ClearEgressPolicy removes the rules ApplyEgressPolicy would have installed for
// the same (containerIP, allowCIDRs, denyCIDRs). The caller passes the policy
// persisted on the sandbox row so cleanup is exact and comment-scoped — the
// blanket BlockAllEgress DROP (no comment) is left untouched.
func (m *Manager) ClearEgressPolicy(containerIP string, allowCIDRs, denyCIDRs []string) error {
	if !m.Enabled() || containerIP == "" {
		return nil
	}
	unlock := m.lockIP(containerIP)
	defer unlock()

	var specs [][]string
	for _, cidr := range allowCIDRs {
		specs = append(specs, []string{"-s", containerIP, "-d", cidr, "-m", "comment", "--comment", egressPolicyComment, "-j", "ACCEPT"})
	}
	if len(allowCIDRs) > 0 {
		specs = append(specs, []string{"-s", containerIP, "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP"})
	}
	for _, cidr := range denyCIDRs {
		specs = append(specs, []string{"-s", containerIP, "-d", cidr, "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP"})
	}
	for _, spec := range specs {
		if err := m.deletePolicyRule(spec...); err != nil {
			return err
		}
	}
	return nil
}

// ensurePolicyRule inserts a DOCKER-USER rule at the top if it is not already
// present. Insert-at-1 plus the Exists guard is the same idempotency contract
// the BlockAll* methods use.
func (m *Manager) ensurePolicyRule(spec ...string) error {
	exists, err := m.ipt.Exists("filter", m.filterChain(), spec...)
	if err != nil {
		return fmt.Errorf("check egress policy rule: %w", err)
	}
	if exists {
		return nil
	}
	if err := m.ipt.Insert("filter", m.filterChain(), 1, spec...); err != nil {
		return fmt.Errorf("insert egress policy rule: %w", err)
	}
	return nil
}

// deletePolicyRule deletes a DOCKER-USER rule, looping to clear any duplicate a
// prior race may have left (Delete removes one match per call), and tolerating
// an already-absent rule.
func (m *Manager) deletePolicyRule(spec ...string) error {
	if err := m.deleteUntilGone("filter", m.filterChain(), spec...); err != nil {
		return fmt.Errorf("delete egress policy rule: %w", err)
	}
	return nil
}

// deleteUntilGone sweeps Delete until the rule is confirmed gone. The exec
// (iptables) path short-circuits on ruleNotExist after the terminating probe
// (2 Deletes, 0 Exists for a single present rule). The netlink path returns
// unrecognized errors (e.g. ENOENT) that ruleNotExist does not classify — the
// Exists fallback confirms absence without teaching ruleNotExist new strings.
// That Exists path is exactly the manager.go:13 memorialized adopt-breakage
// bug on a new backend.
func (m *Manager) deleteUntilGone(table, chain string, spec ...string) error {
	for {
		err := m.ipt.Delete(table, chain, spec...)
		if err == nil {
			continue // swept one, retry (dup-sweep intact)
		}
		if ruleNotExist(err) {
			return nil // exec path: recognized, UNCHANGED cost
		}
		ex, e := m.ipt.Exists(table, chain, spec...)
		if e == nil && !ex {
			return nil // netlink: confirm gone
		}
		return err
	}
}

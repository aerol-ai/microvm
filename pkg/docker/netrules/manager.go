package netrules

import (
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
)

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
	// mu serializes Block/Clear pairs. iptables Exists+Insert is not atomic,
	// and the poller, reconcile, SetNetworkLimits, and Destroy paths can all
	// drive the same IP concurrently. Without this lock, two callers can both
	// pass Exists and both Insert, leaving a duplicate that a single Delete
	// in Clear* won't fully remove.
	mu sync.Mutex
}

func New(enabled bool) (*Manager, error) {
	if !enabled || runtime.GOOS != "linux" {
		return &Manager{enabled: false}, nil
	}

	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("create iptables client: %w", err)
	}

	return &Manager{
		enabled: true,
		ipt:     ipt,
	}, nil
}

// NewWithBackend builds an enabled Manager over an injected backend. Test
// seam only — production wiring goes through New.
func NewWithBackend(backend RuleBackend) *Manager {
	return &Manager{enabled: backend != nil, ipt: backend}
}

func (m *Manager) Enabled() bool {
	return m != nil && m.enabled
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
	m.mu.Lock()
	defer m.mu.Unlock()

	exists, err := m.ipt.Exists("filter", "DOCKER-USER", "-s", containerIP, "-j", "DROP")
	if err != nil {
		return fmt.Errorf("check existing egress rule: %w", err)
	}
	if exists {
		return nil
	}

	if err := m.ipt.Insert("filter", "DOCKER-USER", 1, "-s", containerIP, "-j", "DROP"); err != nil {
		return fmt.Errorf("insert egress rule: %w", err)
	}

	return nil
}

func (m *Manager) ClearBlockAllEgress(containerIP string) error {
	if !m.Enabled() || containerIP == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Loop in case a prior race left a duplicate row — Delete only removes
	// one match per call. Stop on the first "no such rule" return.
	for {
		err := m.ipt.Delete("filter", "DOCKER-USER", "-s", containerIP, "-j", "DROP")
		if err == nil {
			continue
		}
		if strings.Contains(err.Error(), "No chain/target/match") {
			return nil
		}
		return fmt.Errorf("delete egress rule: %w", err)
	}
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
	m.mu.Lock()
	defer m.mu.Unlock()

	exists, err := m.ipt.Exists("filter", "DOCKER-USER", "-d", containerIP, "-j", "DROP")
	if err != nil {
		return fmt.Errorf("check existing ingress rule: %w", err)
	}
	if exists {
		return nil
	}

	if err := m.ipt.Insert("filter", "DOCKER-USER", 1, "-d", containerIP, "-j", "DROP"); err != nil {
		return fmt.Errorf("insert ingress rule: %w", err)
	}

	return nil
}

func (m *Manager) ClearBlockAllIngress(containerIP string) error {
	if !m.Enabled() || containerIP == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for {
		err := m.ipt.Delete("filter", "DOCKER-USER", "-d", containerIP, "-j", "DROP")
		if err == nil {
			continue
		}
		if strings.Contains(err.Error(), "No chain/target/match") {
			return nil
		}
		return fmt.Errorf("delete ingress rule: %w", err)
	}
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
	m.mu.Lock()
	defer m.mu.Unlock()

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
	m.mu.Lock()
	defer m.mu.Unlock()

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
	exists, err := m.ipt.Exists("filter", "DOCKER-USER", spec...)
	if err != nil {
		return fmt.Errorf("check egress policy rule: %w", err)
	}
	if exists {
		return nil
	}
	if err := m.ipt.Insert("filter", "DOCKER-USER", 1, spec...); err != nil {
		return fmt.Errorf("insert egress policy rule: %w", err)
	}
	return nil
}

// deletePolicyRule deletes a DOCKER-USER rule, looping to clear any duplicate a
// prior race may have left (Delete removes one match per call), and tolerating
// an already-absent rule.
func (m *Manager) deletePolicyRule(spec ...string) error {
	for {
		err := m.ipt.Delete("filter", "DOCKER-USER", spec...)
		if err == nil {
			continue
		}
		if strings.Contains(err.Error(), "No chain/target/match") {
			return nil
		}
		return fmt.Errorf("delete egress policy rule: %w", err)
	}
}

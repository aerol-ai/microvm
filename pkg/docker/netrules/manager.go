package netrules

import (
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
)

type Manager struct {
	enabled bool
	ipt     *iptables.IPTables
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

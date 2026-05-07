package netrules

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

type Manager struct {
	enabled bool
	ipt     *iptables.IPTables
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

	err := m.ipt.Delete("filter", "DOCKER-USER", "-s", containerIP, "-j", "DROP")
	if err != nil && !strings.Contains(err.Error(), "No chain/target/match") {
		return fmt.Errorf("delete egress rule: %w", err)
	}

	return nil
}

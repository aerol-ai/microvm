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

func (m *Manager) BlockAllEgress(containerIP string) error {
	if !m.Enabled() || containerIP == "" {
		return nil
	}

	exists, err := m.ipt.Exists("filter", "FORWARD", "-s", containerIP, "-j", "DROP")
	if err != nil {
		return fmt.Errorf("check existing egress rule: %w", err)
	}
	if exists {
		return nil
	}

	if err := m.ipt.Append("filter", "FORWARD", "-s", containerIP, "-j", "DROP"); err != nil {
		return fmt.Errorf("append egress rule: %w", err)
	}

	return nil
}

func (m *Manager) ClearBlockAllEgress(containerIP string) error {
	if !m.Enabled() || containerIP == "" {
		return nil
	}

	err := m.ipt.Delete("filter", "FORWARD", "-s", containerIP, "-j", "DROP")
	if err != nil && !strings.Contains(err.Error(), "No chain/target/match") {
		return fmt.Errorf("delete egress rule: %w", err)
	}

	return nil
}

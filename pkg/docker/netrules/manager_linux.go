//go:build linux

package netrules

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

// newEnabledManager wires the production RuleBackend on Linux hosts.
func newEnabledManager(backend, userChain string) (*Manager, error) {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "", BackendExec:
		ipt, err := iptables.New()
		if err != nil {
			return nil, fmt.Errorf("create iptables client: %w", err)
		}
		recordBackendSelected(BackendExec)
		return &Manager{enabled: true, ipt: newExecBackend(ipt), userChain: userChain}, nil
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

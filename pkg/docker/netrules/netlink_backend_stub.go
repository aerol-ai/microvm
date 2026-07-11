//go:build !linux

package netrules

import "fmt"

// NewNetlinkBackend is unavailable off linux — netlink AF_NETLINK is
// linux-only. Production wiring never selects netlink on non-linux hosts
// (New already disables the Manager there).
func NewNetlinkBackend() (RuleBackend, error) {
	return nil, fmt.Errorf("netrules netlink backend requires linux")
}

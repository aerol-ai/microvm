//go:build !linux

package rootd

import "errors"

// openFirewall: the host firewall is netfilter, and the helper runs on
// Linux only.
func openFirewall(Config, NetworkHost) (FirewallHost, error) {
	return nil, errors.New("the host firewall needs Linux")
}

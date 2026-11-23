//go:build !linux

package rootd

import "errors"

// openFirewall: the host firewall is netfilter, and the helper runs on
// Linux only.
func openFirewall(Config, NetworkHost) (FirewallHost, error) {
	return nil, errors.New("the host firewall needs Linux")
}

// openGuestFirewall: so is the Firecracker guests' firewall.
func openGuestFirewall(Config, *FirecrackerHostsConfig) (FirewallHost, error) {
	return nil, errors.New("the Firecracker guests' firewall needs Linux")
}

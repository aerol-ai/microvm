//go:build !linux

package rootd

import "errors"

// Host-port forwarding is Linux's (iptables); elsewhere it is not
// available, and the call says so.
func openHostPorts() (HostPortHost, error) {
	return nil, errors.New("host-port forwarding needs Linux")
}

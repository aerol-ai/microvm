//go:build !linux

package worker

import "errors"

// checkTCPListenerKind: off Linux no worker hands sandboxd a listener
// (hostDialSupported), and the socket options that tell TCP from SCTP and
// name a bound device are Linux's; refuse.
func checkTCPListenerKind(int) error {
	return errors.New("guest listeners are checked on Linux only")
}

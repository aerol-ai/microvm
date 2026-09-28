//go:build !linux

package service

import (
	"errors"
	"net"
)

// platformOriginalDstPort needs netfilter (Linux); REDIRECT never happens
// elsewhere.
func platformOriginalDstPort(net.Conn) (int, error) {
	return 0, errors.New("SO_ORIGINAL_DST is Linux-only")
}

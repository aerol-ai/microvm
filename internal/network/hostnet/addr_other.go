//go:build !linux

package hostnet

import "errors"

// netnsIPv4Addrs has no namespace to read off Linux. The netns pool only
// runs on Linux; a caller here treats the error as "cannot confirm".
func netnsIPv4Addrs(string) ([]string, error) {
	return nil, errors.New("read netns addresses: network namespaces are Linux-only")
}

//go:build !linux

package rootd

import "errors"

// openNetwork: sandbox networks are Linux namespaces, and the helper runs
// on Linux only.
func openNetwork(Config) (NetworkHost, error) {
	return nil, errors.New("sandbox network namespaces need Linux")
}

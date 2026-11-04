//go:build !linux

package procid

import "errors"

// resolveInRoot needs openat2; the gateway only runs on Linux.
func resolveInRoot(string, string) (FileID, error) {
	return FileID{}, errors.New("procid: per-binary rules need Linux")
}

//go:build linux

package tap

import (
	"os"
	"path/filepath"
)

// setStrictRPFilter sets net.ipv4.conf.<tap>.rp_filter=1. The effective
// value is the max of conf.all and the interface's, so 1 here is strict
// whatever the host default.
func setStrictRPFilter(tap string) error {
	return os.WriteFile(filepath.Join("/proc/sys/net/ipv4/conf", tap, "rp_filter"), []byte("1\n"), 0o644)
}

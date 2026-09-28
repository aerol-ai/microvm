//go:build linux

package hostport

import (
	"os"
	"strings"
)

var ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// platformEnableIPForward sets net.ipv4.ip_forward=1, writing only when it
// is not already on.
func platformEnableIPForward() error {
	if cur, err := os.ReadFile(ipForwardPath); err == nil && strings.TrimSpace(string(cur)) == "1" {
		return nil
	}
	return os.WriteFile(ipForwardPath, []byte("1\n"), 0o644)
}

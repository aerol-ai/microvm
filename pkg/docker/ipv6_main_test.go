package docker

import (
	"os"
	"testing"

	"github.com/aerol-ai/microvm/internal/network/hostnet"
)

// TestMain runs the package as on a Linux host with IPv6, whatever the test
// machine is, so every create and park in these tests carries the sysctls
// production sends. Tests about a host without IPv6 swap it themselves.
func TestMain(m *testing.M) {
	sandboxIPv6Sysctls = func() map[string]string {
		return map[string]string{hostnet.SysctlAllDisableIPv6: "1", hostnet.SysctlDefaultDisableIPv6: "1"}
	}
	os.Exit(m.Run())
}

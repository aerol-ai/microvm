package worker

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// TestMain stands in a node that owns none of the test host's addresses:
// this package's echo and proxy servers listen on loopback and on the
// host's own address, and the node guard refuses the node's addresses. The
// guard's own tests (nodeguard_test.go) put the real check back.
func TestMain(m *testing.M) {
	nodeCheck = func(netip.AddrPort) error { return nil }
	egresspolicy.SetNodeAddrsSource(func() ([]net.Addr, error) { return nil, nil })
	os.Exit(m.Run())
}

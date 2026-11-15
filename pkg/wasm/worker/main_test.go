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
	// One wazero compile cache for the stream tests (stream_test.go), which
	// compile the stdio guest on two engines per test.
	if dir, err := os.MkdirTemp("", "aerol-wasm-stream-cache-"); err == nil {
		streamCompileCacheDir = dir
	}
	code := m.Run()
	if streamCompileCacheDir != "" {
		_ = os.RemoveAll(streamCompileCacheDir)
	}
	os.Exit(code)
}

var streamCompileCacheDir string

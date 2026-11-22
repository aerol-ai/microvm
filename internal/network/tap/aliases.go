package tap

import "github.com/aerol-ai/microvm/internal/network/tap/taphost"

// The TAP devices' realization (the device, its address, NAT and the
// guests' isolation) lives in taphost, which needs no store: the root
// helper (privilege mode split, M1 PR 9b) runs it too and is built
// without cgo. These names keep this package's API as it was.
type (
	Slot             = taphost.Slot
	Host             = taphost.Host
	Owner            = taphost.Owner
	HostManager      = taphost.HostManager
	NATBackend       = taphost.NATBackend
	IsolationBackend = taphost.IsolationBackend
)

// IsolationChain is the guests' isolation chain in the mangle table.
const IsolationChain = taphost.IsolationChain

// NewHost, EnsureNAT and EnsureIsolation are taphost's.
func NewHost(ipCmd string) *Host { return taphost.NewHost(ipCmd) }

func EnsureNAT(be NATBackend, baseCIDR string) error { return taphost.EnsureNAT(be, baseCIDR) }

func EnsureIsolation(be IsolationBackend, baseCIDR string) error {
	return taphost.EnsureIsolation(be, baseCIDR)
}

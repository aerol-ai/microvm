//go:build !linux

package ipv6fence

// NewBackend returns a backend that refuses: there is no nftables here, and
// no sandbox bridge or TAP either (the daemon wires the fence on Linux only).
func NewBackend() Backend { return unsupported{} }

type unsupported struct{}

func (unsupported) Apply([]Rule) error         { return ErrUnsupported }
func (unsupported) Check([]Rule) (bool, error) { return false, ErrUnsupported }

//go:build !linux

package workerfence

type unsupported struct{}

// NewBackend has no nftables to drive off Linux, where workers do not drop.
func NewBackend() Backend { return unsupported{} }

func (unsupported) Apply([]Rule) error         { return ErrUnsupported }
func (unsupported) Check([]Rule) (bool, error) { return false, ErrUnsupported }
func (unsupported) Remove() error              { return ErrUnsupported }

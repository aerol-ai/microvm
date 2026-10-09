//go:build !linux

package egress

// NewProbeNet returns nil off Linux: there is no gateway to self-test.
func NewProbeNet() ProbeNet { return nil }

//go:build !linux

package tap

// setStrictRPFilter is a no-op off Linux, where there are no TAP devices.
func setStrictRPFilter(string) error { return nil }

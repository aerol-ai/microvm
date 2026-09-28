//go:build !linux

package hostport

// FlushConntrack is a no-op off Linux, where there is no conntrack.
func FlushConntrack(int) error { return nil }

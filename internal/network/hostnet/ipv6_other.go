//go:build !linux

package hostnet

// disableIPv6InNetns is unreachable off Linux in production (HostHasIPv6 is
// false without /proc); it writes the current namespace's files so the
// shared write path stays testable everywhere.
func disableIPv6InNetns(string) error { return writeNetnsDisableIPv6() }

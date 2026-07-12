package hostnet

// EnsureForwardingSysctls enables host forwarding/filter sysctls required for
// containerd native CNI networking (Phase 2). No-op on platforms without them.
func EnsureForwardingSysctls() error {
	return ensureForwardingSysctls()
}

// FlushConntrackForIP drops conntrack entries for an IP on slot release (Phase 2).
func FlushConntrackForIP(ip string) error {
	return flushConntrackForIP(ip)
}

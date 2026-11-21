package hostnet

import "context"

// EnsureForwardingSysctls enables host forwarding/filter sysctls required for
// containerd native CNI networking (Phase 2). No-op on platforms without them.
func EnsureForwardingSysctls() error {
	return ensureForwardingSysctls()
}

// FlushConntrackForIP drops conntrack entries for an IP on slot release (Phase 2).
func FlushConntrackForIP(ip string) error {
	return flushConntrackForIP(ip)
}

// FlushConntrackContext is FlushConntrackForIP for the root helper: each
// conntrack run is in a process group of its own that ends with ctx
// (internal/procgroup), so none outlives the call that started it. Like
// FlushConntrackForIP it is best-effort; it fails only when ctx ended.
func FlushConntrackContext(ctx context.Context, ip string) error {
	return flushConntrackContext(ctx, ip)
}

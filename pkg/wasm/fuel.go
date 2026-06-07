package wasm

import (
	"context"
	"time"
)

// DefaultWallTimeout is the invocation budget when Capabilities.WallTimeoutNs is zero.
const DefaultWallTimeout = 5 * time.Minute

// WallTimeoutFromCaps returns the wall-clock budget for one guest invocation.
func WallTimeoutFromCaps(caps Capabilities) time.Duration {
	if caps.WallTimeoutNs > 0 {
		return time.Duration(caps.WallTimeoutNs)
	}
	return DefaultWallTimeout
}

// WithInvocationDeadline wraps ctx with the caps wall timeout (epoch-style on wazero).
func WithInvocationDeadline(ctx context.Context, caps Capabilities) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, WallTimeoutFromCaps(caps))
}

// MemoryLimitPages converts a MiB cap to WASM pages (64KiB each). Zero means no limit.
func MemoryLimitPages(memoryMB int) uint32 {
	if memoryMB <= 0 {
		return 0
	}
	const pageSize = 64 * 1024
	bytes := uint64(memoryMB) * 1024 * 1024
	pages := bytes / pageSize
	if pages == 0 {
		return 1
	}
	if pages > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(pages)
}

// CapsFromResourceLimits projects host limits into engine capabilities.
func CapsFromResourceLimits(base Capabilities, memoryMB int, wallTimeout time.Duration) Capabilities {
	if memoryMB > 0 {
		base.MemoryMB = memoryMB
	}
	if wallTimeout > 0 {
		base.WallTimeoutNs = wallTimeout.Nanoseconds()
	}
	return base
}

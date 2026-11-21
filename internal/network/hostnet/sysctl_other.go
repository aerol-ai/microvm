//go:build !linux

package hostnet

import "context"

func ensureForwardingSysctls() error { return nil }

func flushConntrackForIP(string) error { return nil }

func flushConntrackContext(ctx context.Context, _ string) error { return ctx.Err() }

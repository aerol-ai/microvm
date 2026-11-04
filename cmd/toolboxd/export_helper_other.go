//go:build !linux

package main

import "log/slog"

// runExportHelper never runs off Linux: the helper is a Firecracker VM.
func runExportHelper(logger *slog.Logger) int {
	logger.Error("export helper: Linux only")
	return 1
}

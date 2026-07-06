//go:build !linux

package main

import "log/slog"

func runParkedReadyHandshake(_ *slog.Logger, _ *server, _, _, _ string) {}

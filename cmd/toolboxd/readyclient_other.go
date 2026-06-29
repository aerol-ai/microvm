//go:build !linux

package main

import "log/slog"

func announceReady(_ *slog.Logger, _, _, _, _ string) {}

func scrubReadyEnv() {}

package main

import (
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/pkg/gvisorpids"
)

// gvisorPidsApplyFn is a seam for tests: the real write needs gVisor's
// cgroupfs at /sys/fs/cgroup.
var gvisorPidsApplyFn = gvisorpids.Apply

// applyGvisorPidsLimit caps this gVisor sandbox's tasks inside the sentry
// (pkg/gvisorpids explains why runsc does not do it from the spec). main runs
// it before toolboxd reports ready and before the user command starts, so no
// exec can fork ahead of the cap. A failure is logged, not fatal: the host
// cgroup still bounds the sandbox, and an image whose USER is not root cannot
// write pids.max, which would otherwise fail every create on that image.
func applyGvisorPidsLimit(logger *slog.Logger) {
	raw := strings.TrimSpace(os.Getenv(gvisorpids.EnvVar))
	// The cap is toolboxd's to set; the user's commands need not see it.
	os.Unsetenv(gvisorpids.EnvVar)
	if raw == "" {
		return
	}
	limit, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || limit <= 0 {
		logger.Warn("gvisor pids limit ignored: not a positive number", "value", raw)
		return
	}
	path, err := gvisorPidsApplyFn("/", limit)
	if err != nil {
		logger.Warn("gvisor pids limit not applied: a fork bomb can stop this sandbox",
			"limit", limit, "path", path, "error", err)
		return
	}
	logger.Info("gvisor pids limit applied", "limit", limit, "path", path)
}

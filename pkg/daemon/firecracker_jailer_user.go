package daemon

import (
	"os"

	"github.com/aerol-ai/microvm/internal/config"
	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
)

// jailerUserFiles are the host's user and group files the start check
// reads; tests point them at their own.
var jailerUserFiles = struct{ passwd, group string }{"/etc/passwd", "/etc/group"}

// checkFirecrackerJailerUser refuses to start Firecracker when the jailer
// would run every VM as a user that is not one of its own
// (fcruntime.CheckJailerUser). It runs once, at start: no create pays for
// it. Without the jailer (SB_FIRECRACKER_USE_JAILER=false, single mode
// only) there is no such user. In split the root helper always runs the
// jailer, and sandboxd's own user is the agent's.
func checkFirecrackerJailerUser(cfg config.Config, split bool) error {
	if !cfg.UseJailer && !split {
		return nil
	}
	return fcruntime.CheckJailerUser(fcruntime.JailerUserCheck{
		UID: cfg.JailerUID, GID: cfg.JailerGID, AgentUID: os.Geteuid(),
		PasswdPath: jailerUserFiles.passwd, GroupPath: jailerUserFiles.group,
	})
}

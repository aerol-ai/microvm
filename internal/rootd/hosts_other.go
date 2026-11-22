//go:build !linux

package rootd

import (
	"errors"
	"os/exec"
)

// startInGroup: host processes need cgroup v2, which is Linux's.
func startInGroup(*exec.Cmd, string) error {
	return errors.New("root helper: host processes need Linux cgroups")
}

// setOwnPIDNamespace: hosts start only on Linux (startInGroup).
func setOwnPIDNamespace(*exec.Cmd) {}

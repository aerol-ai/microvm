//go:build !linux

package worker

import (
	"os/exec"
	"testing"
)

// No PID namespaces off Linux.
func assertOwnPIDNamespace(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if cmd.SysProcAttr != nil {
		t.Fatalf("SysProcAttr set off linux: %+v", cmd.SysProcAttr)
	}
}

//go:build linux

package worker

import (
	"os/exec"
	"syscall"
	"testing"
)

func assertOwnPIDNamespace(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWPID == 0 {
		t.Fatalf("worker not given a PID namespace: %+v", cmd.SysProcAttr)
	}
}

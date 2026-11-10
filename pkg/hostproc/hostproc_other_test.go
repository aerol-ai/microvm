//go:build !linux

package hostproc

import (
	"errors"
	"os/exec"
	"testing"
)

// inCgroup: off Linux a start never asks for a cgroup.
func inCgroup(*exec.Cmd) bool { return false }

// TestOpenUnsupportedOffLinux: a process cannot be held off Linux, so
// nothing is ever adopted there.
func TestOpenUnsupportedOffLinux(t *testing.T) {
	stat := "42 (x) S 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 555 1000 10\n"
	fakeProc(t, 42, stat, "")
	if _, _, err := OpenPID(42); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("OpenPID = %v, want ErrUnsupported", err)
	}
}

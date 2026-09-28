//go:build linux

package isolate

import (
	"syscall"
	"testing"
)

func TestJailCloneflagsIsNewPID(t *testing.T) {
	if got := jailCloneflags(); got != uintptr(syscall.CLONE_NEWPID) {
		t.Fatalf("jailCloneflags() = %#x, want CLONE_NEWPID %#x", got, syscall.CLONE_NEWPID)
	}
}

//go:build !windows

package main

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestOSTerminalNotifyResize(t *testing.T) {
	changes, stop := osTerminal{}.NotifyResize()
	defer stop()
	// A terminal resize is SIGWINCH to the foreground process group.
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changes:
	case <-time.After(2 * time.Second):
		t.Fatal("SIGWINCH was not reported as a resize")
	}
}

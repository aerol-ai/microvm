package main

import (
	"errors"
	"os/exec"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// waitSignal names the signal that ended a buffered exec's process, in the
// "SIGKILL" form callers and docs use (plan E3), or "" when it exited on its
// own. It reads the same two shapes interpretWaitResult does: Go's
// ExitError, and the status the reaper collected when it won the race.
// interpretWaitResult's own signal text ("killed") stays as it is: the exec
// stream and sessions already send that to clients.
func waitSignal(err error) string {
	var status syscall.WaitStatus
	var exitErr *exec.ExitError
	var reaped *reapedExit
	switch {
	case errors.As(err, &exitErr):
		ws, ok := exitErr.Sys().(syscall.WaitStatus)
		if !ok {
			return ""
		}
		status = ws
	case errors.As(err, &reaped):
		status = reaped.status
	default:
		return ""
	}
	if !status.Signaled() {
		return ""
	}
	return signalName(status.Signal())
}

// signalName is sig's conventional name, or SIG<n> for one without a name
// (a real-time signal).
func signalName(sig syscall.Signal) string {
	if name := unix.SignalName(sig); name != "" {
		return name
	}
	return "SIG" + strconv.Itoa(int(sig))
}

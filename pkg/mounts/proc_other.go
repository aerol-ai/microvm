//go:build !linux

package mounts

import "syscall"

// Adopting a running helper needs a pidfd (Linux); elsewhere every mount is
// mounted afresh, as before.

func openHelperPidfd(int, []string) (liveProcess, error) { return nil, errAdoptionUnsupported }

// signalListed has no pidfd here: still is checked, then the pid signalled.
func signalListed(pid int, sig syscall.Signal, still func() bool) error {
	return signalListedPlain(pid, sig, still)
}

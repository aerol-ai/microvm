//go:build !linux

package mounts

// Adopting a running helper needs a pidfd (Linux); elsewhere every mount is
// mounted afresh, as before.

func openHelperPidfd(int, []string) (liveProcess, error) { return nil, errAdoptionUnsupported }

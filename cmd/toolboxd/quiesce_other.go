//go:build !linux

package main

// quiesce_other.go is the non-Linux stub for the kernel-state resync
// layer. Toolboxd compiles on darwin (CI runs unit tests there) but
// never runs there in production — the AF_VSOCK socket setup in
// vsock_other.go is the canonical "this binary only does real work on
// Linux" boundary; we mirror it here so cross-platform builds stay
// green. A handler that hits these stubs at runtime logs and
// continues, matching the quiesce handler's best-effort contract.

import "errors"

// otherQuiesceOps is the no-op implementation used on darwin and other
// non-Linux build targets.
type otherQuiesceOps struct{}

func (otherQuiesceOps) ReseedRandom() error {
	return errors.New("quiesce: linux-only (build tag !linux)")
}

func (otherQuiesceOps) SetWallclock(int64) error {
	return errors.New("quiesce: linux-only (build tag !linux)")
}

func (otherQuiesceOps) ConfigureNetwork(guestNetworkConfig) error {
	return errors.New("quiesce: linux-only (build tag !linux)")
}

// newQuiesceOps returns the platform-specific quiesce implementation.
// Non-Linux gets the stub above; Linux gets real syscalls from
// quiesce_linux.go.
func newQuiesceOps() quiesceOps { return otherQuiesceOps{} }

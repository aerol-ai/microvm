package containerd

import (
	"context"
	"testing"
)

// NewHangUpDriver hands the external test package a driver on the hang-up
// fake (create_hangup_test.go), so it can run keyed creates through the
// service on it, and the arm that makes the next create's client hang up at
// the named step ("new container", "new task", "task start" or "readiness
// wait").
func NewHangUpDriver(t *testing.T, at string) (*Driver, func(context.CancelFunc)) {
	h := newHangUpHarness(t, hangUpPoint(at))
	return h.d, h.arm
}

// NewLeftoverSnapshotDriver hands the external test package a driver on the
// hang-up fake that holds a snapshot named id and no container: what a create
// whose client hung up inside NewContainer leaves when containerd finishes
// preparing the snapshot after the create's undo has looked.
func NewLeftoverSnapshotDriver(t *testing.T, id string) *Driver {
	h := newHangUpHarness(t, "")
	h.snapshots[id] = true
	return h.d
}

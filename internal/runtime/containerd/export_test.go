package containerd

import (
	"context"
	"testing"
)

// NewHangUpDriver hands the external test package a driver on the hang-up
// fake (create_hangup_test.go), so it can run keyed creates through the
// service on it, and the arm that makes the next create's client hang up at
// the named step ("new task", "task start" or "readiness wait").
func NewHangUpDriver(t *testing.T, at string) (*Driver, func(context.CancelFunc)) {
	h := newHangUpHarness(t, hangUpPoint(at))
	return h.d, h.arm
}

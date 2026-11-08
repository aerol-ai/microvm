//go:build !linux

package netns

import (
	"context"
	"errors"
	"testing"
)

// Off Linux the Host's own namespace steps refuse plainly instead of
// pretending; tests stub the seams.
func TestHostNamespaceStepsNeedLinux(t *testing.T) {
	ctx := context.Background()
	h := &Host{NetnsRoot: t.TempDir()}
	for name, err := range map[string]error{
		"create":   h.createNetns(ctx, "sb-1"),
		"loopback": h.bringLoopbackUp(ctx, "sb-1"),
		"delete":   h.deleteNetns(ctx, "sb-1"),
	} {
		if !errors.Is(err, errNetnsNeedsLinux) {
			t.Errorf("%s: %v, want %v", name, err, errNetnsNeedsLinux)
		}
	}
}

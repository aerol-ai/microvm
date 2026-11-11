//go:build !linux

package supervisor

import (
	"errors"
	"sync/atomic"
	"testing"
)

func TestProcessCallsNeedLinux(t *testing.T) {
	_, startErr := StartInGroup("/x", []string{"true"})
	for name, err := range map[string]error{"BecomeReaper": BecomeReaper(), "StartInGroup": startErr, "LowerOwnOOMScore": LowerOwnOOMScore(), "Unmount": Unmount("/x")} {
		if !errors.Is(err, errNeedsLinux) {
			t.Errorf("%s = %v", name, err)
		}
	}
	Terminate(1)
	Reap(&atomic.Int64{}, nil, quiet())
}

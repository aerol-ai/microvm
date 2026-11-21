//go:build !linux

package nsbuild

import (
	"errors"
	"testing"
)

// Off Linux the namespace steps refuse plainly instead of pretending.
func TestStepsNeedLinux(t *testing.T) {
	for name, err := range map[string]error{
		"create":   CreateNamed(t.TempDir(), "sb-1"),
		"loopback": LoopbackUp("/run/netns/sb-1"),
		"delete":   DeleteNamed(t.TempDir(), "sb-1"),
	} {
		if !errors.Is(err, ErrNeedsLinux) {
			t.Errorf("%s: %v, want %v", name, err, ErrNeedsLinux)
		}
	}
}

//go:build !linux

package containerd

import (
	"context"
	"errors"
	"testing"
)

// prepareUnpackChild has nothing to do off Linux: there is no child.
func prepareUnpackChild() error { return nil }

// runUnpackTestHelper has no helpers to run off Linux.
func runUnpackTestHelper(string) int { return 2 }

// Off Linux the child path is off, and its two halves say why if reached.
func TestContextUnpackOffLinux(t *testing.T) {
	if unpackInChild() {
		t.Fatal("unpackInChild must be false off Linux")
	}
	if err := unpackContextInChild(context.Background(), nil, t.TempDir(), 1, 1); !errors.Is(err, errContextUnpackNeedsLinux) {
		t.Fatalf("unpackContextInChild = %v", err)
	}
	if err := RunContextUnpack(nil); !errors.Is(err, errContextUnpackNeedsLinux) {
		t.Fatalf("RunContextUnpack = %v", err)
	}
	if err := checkContextUnpacker(); !errors.Is(err, errContextUnpackNeedsLinux) {
		t.Fatalf("checkContextUnpacker = %v", err)
	}
	// Nothing to sweep: the channel is closed at once.
	<-NewBuildKitBuilder("", "", nil).SweepBuildDirs()
}

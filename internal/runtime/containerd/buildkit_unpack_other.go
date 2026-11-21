//go:build !linux

package containerd

import (
	"context"
	"errors"
	"os"
)

// unpackInChild is false off Linux, so build contexts unpack in process
// there. The containerd engine, and so this builder, runs only on Linux;
// other builds of sandboxd exist for development and tests. The child's
// guards (no-new-privs, PR_SET_DUMPABLE) are Linux calls with nothing to
// stand in for them elsewhere.
var unpackInChild = func() bool { return false }

var errContextUnpackNeedsLinux = errors.New("build context unpacker: requires linux")

// unpackContextInChild is never reached off Linux (unpackInChild is false).
func unpackContextInChild(context.Context, []byte, string, int, int) error {
	return errContextUnpackNeedsLinux
}

// removeBuildDir is os.RemoveAll off Linux: with no child, the only trees
// are ones extractTarStream made, within its depth cap.
var removeBuildDir = os.RemoveAll

// SweepBuildDirs has nothing to sweep off Linux, where no child can leave a
// tree behind; the channel is closed.
func (b *BuildKitBuilder) SweepBuildDirs() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

// checkContextUnpacker is never reached off Linux (unpackInChild is false).
func checkContextUnpacker() error { return errContextUnpackNeedsLinux }

// RunContextUnpack cannot run off Linux; no parent there starts it.
func RunContextUnpack([]string) error {
	return errContextUnpackNeedsLinux
}

//go:build !linux

package firecracker

// vsock_dial_other.go is the non-Linux stub for the VsockDialer. Firecracker
// is Linux/KVM-only; on darwin the daemon never runs production sandboxes, but
// the driver and its tests must still compile. Returning a clear error from
// Dial — rather than failing the build — lets the test binary swap in a fake
// dialer and exercise everything else.

import (
	"context"
	"errors"
	"io"
)

type unsupportedVsockDialer struct{}

// NewLinuxVsockDialer returns a no-op dialer on non-Linux builds. The
// name matches the Linux constructor so cmd/sandboxd/main.go can call
// it unconditionally; the runtime-error surface stays the same shape
// as Ping's "binary not configured" error.
func NewLinuxVsockDialer() VsockDialer { return &unsupportedVsockDialer{} }

func (d *unsupportedVsockDialer) Dial(_ context.Context, _ string, _, _ uint32) (io.ReadWriteCloser, error) {
	return nil, errors.New("vsock dial: Firecracker is Linux-only; this binary was built for a non-Linux target")
}

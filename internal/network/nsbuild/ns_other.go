//go:build !linux

package nsbuild

import "errors"

// Network namespaces exist only on Linux, the one place the containerd
// engine runs. These keep the package building elsewhere; unit tests stub
// the steps instead.
var ErrNeedsLinux = errors.New("netns: network namespaces need Linux")

// CreateNamed needs Linux.
func CreateNamed(string, string) error { return ErrNeedsLinux }

// LoopbackUp needs Linux.
func LoopbackUp(string) error { return ErrNeedsLinux }

// DeleteNamed needs Linux.
func DeleteNamed(string, string) error { return ErrNeedsLinux }

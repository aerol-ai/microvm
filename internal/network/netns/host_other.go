//go:build !linux

package netns

import "errors"

// Network namespaces exist only on Linux, the one place the containerd
// engine runs. These keep the package building elsewhere; unit tests stub
// the Host seams instead.
var errNetnsNeedsLinux = errors.New("netns: network namespaces need Linux")

func createNamedNetns(string, string) error { return errNetnsNeedsLinux }

func loopbackUpIn(string) error { return errNetnsNeedsLinux }

func deleteNamedNetns(string, string) error { return errNetnsNeedsLinux }

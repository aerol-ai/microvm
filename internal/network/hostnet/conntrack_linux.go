//go:build linux

package hostnet

import "os/exec"

// execConntrack is a test seam over the conntrack CLI.
var execConntrack = func(args ...string) error {
	cmd := exec.Command("conntrack", args...)
	return cmd.Run()
}

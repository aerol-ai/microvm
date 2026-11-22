//go:build !linux

package worker

import (
	"fmt"
	"os/exec"
)

// confinementSupported: workers cannot drop here.
const confinementSupported = false

// applyConfinement cannot drop off Linux. sandboxd never asks there (it
// confines workers only as root on Linux), so a request is a mistake and
// the worker refuses to serve rather than run unconfined.
func applyConfinement(Confinement) error {
	return fmt.Errorf("wasm worker: dropping privileges is Linux only")
}

// setOwnPIDNamespace has no PID namespaces to use off Linux.
func setOwnPIDNamespace(*exec.Cmd) {}

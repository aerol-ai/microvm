//go:build !linux

package isolate

import "fmt"

// RunJailShim cannot run off Linux; the parent never spawns it there because
// applyJail refuses first.
func RunJailShim([]string) error {
	return fmt.Errorf("isolate jail shim: requires linux")
}

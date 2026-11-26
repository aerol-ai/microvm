package config

import "fmt"

// Firecracker backends (SB_FIRECRACKER_BACKEND) and Nitro modes
// (SB_FIRECRACKER_NITRO_MODE). plans/security-gaps-m1-m4.md §4.3.
const (
	FirecrackerBackendKVM   = "kvm"
	FirecrackerBackendNitro = "nitro"

	FirecrackerNitroModeDirect       = "direct"
	FirecrackerNitroModeConfidential = "confidential"
)

// validateFirecrackerBackend checks the two settings at start, so a typo
// fails there and not on the first create. The Nitro backend is refused for
// now: nothing in this build can run a Nitro VM, and a node that took the
// setting would offer a runtime it cannot run. The driver PR lifts this.
func validateFirecrackerBackend(backend, nitroMode string) error {
	switch nitroMode {
	case FirecrackerNitroModeDirect, FirecrackerNitroModeConfidential:
	default:
		return fmt.Errorf("SB_FIRECRACKER_NITRO_MODE=%q: must be %s or %s",
			nitroMode, FirecrackerNitroModeDirect, FirecrackerNitroModeConfidential)
	}
	switch backend {
	case FirecrackerBackendKVM:
		return nil
	case FirecrackerBackendNitro:
		return fmt.Errorf("SB_FIRECRACKER_BACKEND=%s: the Nitro backend is not in this build yet; leave it at %s",
			FirecrackerBackendNitro, FirecrackerBackendKVM)
	default:
		return fmt.Errorf("SB_FIRECRACKER_BACKEND=%q: must be %s or %s",
			backend, FirecrackerBackendKVM, FirecrackerBackendNitro)
	}
}

package config

import (
	"fmt"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Firecracker backends (SB_FIRECRACKER_BACKEND) and Nitro modes
// (SB_FIRECRACKER_NITRO_MODE). plans/security-gaps-m1-m4.md §4.3.
const (
	FirecrackerBackendKVM   = "kvm"
	FirecrackerBackendNitro = "nitro"

	FirecrackerNitroModeDirect       = "direct"
	FirecrackerNitroModeConfidential = "confidential"
)

// FirecrackerRuntime is the runtime this node's Firecracker VMs are created
// as: firecracker-nitro on the Nitro backend, firecracker otherwise. A node
// offers one or the other, never both.
func (c Config) FirecrackerRuntime() string {
	if c.FirecrackerBackend == FirecrackerBackendNitro {
		return models.RuntimeFirecrackerNitro
	}
	return models.RuntimeFirecracker
}

// validateFirecrackerBackend checks the two settings at start, so a typo
// fails there and not on the first create, and refuses the Firecracker
// settings a Nitro node cannot honour: it would otherwise take them and
// quietly do without.
func validateFirecrackerBackend(c Config) error {
	switch c.FirecrackerNitroMode {
	case FirecrackerNitroModeDirect, FirecrackerNitroModeConfidential:
	default:
		return fmt.Errorf("SB_FIRECRACKER_NITRO_MODE=%q: must be %s or %s",
			c.FirecrackerNitroMode, FirecrackerNitroModeDirect, FirecrackerNitroModeConfidential)
	}
	switch c.FirecrackerBackend {
	case FirecrackerBackendKVM:
		return nil
	case FirecrackerBackendNitro:
	default:
		return fmt.Errorf("SB_FIRECRACKER_BACKEND=%q: must be %s or %s",
			c.FirecrackerBackend, FirecrackerBackendKVM, FirecrackerBackendNitro)
	}
	// A Nitro VM gets no CPU template, so nothing can show or hide
	// virtualization extensions, and AWS runs no hypervisor inside it.
	if c.FirecrackerNestedVirt {
		return fmt.Errorf("SB_FIRECRACKER_NESTED_VIRT=true cannot work with SB_FIRECRACKER_BACKEND=%s: a Nitro VM cannot run VMs of its own", FirecrackerBackendNitro)
	}
	// The warm VMM pool restores memory snapshots; a Nitro VM has none.
	if c.FirecrackerVMMPoolEnabled {
		return fmt.Errorf("SB_FIRECRACKER_VMM_POOL_ENABLED=true cannot work with SB_FIRECRACKER_BACKEND=%s: the pool restores memory snapshots, and a Nitro VM has none", FirecrackerBackendNitro)
	}
	return nil
}

package service

import (
	"errors"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/models"
)

// IPv6Fence is what the create gate asks: nil when the node's IPv6 fence
// covers a runtime's sandboxes (ipv6fence.Supervisor). Container, gVisor
// and Firecracker sandboxes sit on a host bridge or TAP, and every host
// rule between them is IPv4, so without the fence a sandbox that gets IPv6
// up reaches its neighbours and the node over link-local addresses.
type IPv6Fence interface {
	Ready(runtime string) error
}

// ErrIPv6FenceNotReady refuses a container or Firecracker create while the
// node's IPv6 fence is not installed for its runtime (503,
// ipv6_fence_not_ready; the node retries every few seconds).
var ErrIPv6FenceNotReady = errors.New("this node cannot keep IPv6 off its sandbox networks right now; creates on this runtime are refused until it can")

// SetIPv6Fence wires the fence the create gate asks. The daemon calls it
// after the fence's first sync, before the API serves.
func (s *Service) SetIPv6Fence(f IPv6Fence) { s.ipv6Fence = f }

// requireIPv6Fence is the create gate. One map read. Nothing to ask where
// no fence is wired: tests, non-Linux, and a node with the host firewall
// off (pkg/daemon wireIPv6Fence says why).
func (s *Service) requireIPv6Fence(chosenRuntime string) error {
	if s.ipv6Fence == nil {
		return nil
	}
	name := ipv6FenceRuntime(chosenRuntime, s.cfg.ContainerEngine)
	if name == "" {
		return nil
	}
	if err := s.ipv6Fence.Ready(name); err != nil {
		return fmt.Errorf("%w (runtime %s: %v)", ErrIPv6FenceNotReady, name, err)
	}
	return nil
}

// ipv6FenceRuntime maps a create's runtime to the fence source that covers
// it: Firecracker guests are on the TAPs, runc and gVisor containers on the
// container engine's bridge; WASM and isolate sandboxes have no interface
// on the node.
func ipv6FenceRuntime(chosenRuntime, engine string) string {
	switch chosenRuntime {
	case models.RuntimeFirecracker:
		return models.RuntimeFirecracker
	case models.RuntimeWasm, models.RuntimeIsolate:
		return ""
	}
	if engine == models.ContainerEngineContainerd {
		return models.ContainerEngineContainerd
	}
	return models.ContainerEngineDocker
}

package containerd

import (
	"context"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// NetnsHandoff provisions a prepaid network namespace for containerd creates.
// When nil, the driver uses containerd's default network namespace (host/default).
type NetnsHandoff interface {
	Provision(ctx context.Context, sandboxID string) (netnsPath, containerIP string, err error)
	Release(ctx context.Context, sandboxID string) error
	// ReassignOwner moves adopted slot ownership from a park slot id to the
	// real sandbox id after warm adopt (rename-free).
	ReassignOwner(ctx context.Context, fromSandboxID, toSandboxID string) error
}

// withNetworkNamespace pins the OCI spec to an existing netns path produced by
// the native netns pool (Phase 2).
func withNetworkNamespace(path string) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *specs.Spec) error {
		if path == "" {
			return nil
		}
		if s.Linux == nil {
			s.Linux = &specs.Linux{}
		}
		for i, ns := range s.Linux.Namespaces {
			if ns.Type == specs.NetworkNamespace {
				s.Linux.Namespaces[i].Path = path
				return nil
			}
		}
		s.Linux.Namespaces = append(s.Linux.Namespaces, specs.LinuxNamespace{
			Type: specs.NetworkNamespace,
			Path: path,
		})
		return nil
	}
}

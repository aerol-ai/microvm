package containerd

import (
	"context"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
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

// SandboxContainerExists reports whether sandboxID still has a containerd
// container on this node, running or stopped. It is the netns pool's
// ownership test at boot: a slot belongs to its sandbox for as long as the
// container exists, because the container's spec pins the slot's netns path
// and a later Start rejoins it. Unlike Inspect it never fails on a healthy
// sandbox: Inspect also reads the IP out of the netns, which a gVisor sandbox
// does not expose there. A warm-adopted sandbox keeps its park container id,
// so a miss by id falls back to the sandbox-id label. Any error other than
// NotFound is returned, and the caller must treat it as "still owned".
func (d *Driver) SandboxContainerExists(ctx context.Context, sandboxID string) (bool, error) {
	client, err := d.ensureClient()
	if err != nil {
		return false, err
	}
	if _, err := client.LoadContainer(ctx, sandboxID); err == nil {
		return true, nil
	} else if !errdefs.IsNotFound(err) {
		return false, err
	}
	c, err := d.findContainerBySandboxID(ctx, client, sandboxID)
	if err != nil {
		return false, err
	}
	return c != nil, nil
}

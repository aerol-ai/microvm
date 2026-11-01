package containerd

import (
	"context"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/network/hostnet"
)

// sandboxIPv6Sysctls is a var so tests can stand in a host with or without
// IPv6.
var sandboxIPv6Sysctls = hostnet.SandboxIPv6Sysctls

// withNewSpec is cntr.WithNewSpec, a var so tests can read the spec options
// a create or a park assembled (the fake client cannot generate a spec).
var withNewSpec = cntr.WithNewSpec

// withSandboxIPv6Off starts every sandbox with IPv6 off in its own network
// namespace: runc writes the sysctls before the first process runs, and
// runsc (gVisor, whose own network stack does not read the namespace's
// sysctls) reads net.ipv6.conf.all.disable_ipv6 from the spec and copies no
// IPv6 address or route into its stack. Every create gets it, pooled netns
// or not, runc or runsc, privileged or not: a pooled netns already has IPv6
// off (netns.Host.Realize), and writing it again is a no-op. Nothing on a
// host without IPv6, where runc would fail on the missing /proc/sys entry.
func withSandboxIPv6Off() oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		sysctls := sandboxIPv6Sysctls()
		if len(sysctls) == 0 {
			return nil
		}
		if s.Linux == nil {
			s.Linux = &specs.Linux{}
		}
		if s.Linux.Sysctl == nil {
			s.Linux.Sysctl = make(map[string]string, len(sysctls))
		}
		for k, v := range sysctls {
			s.Linux.Sysctl[k] = v
		}
		return nil
	}
}

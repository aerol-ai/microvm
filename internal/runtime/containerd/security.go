package containerd

import (
	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/pkg/oci"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// securitySpecOpts assembles the default non-privileged security envelope
// matching dockerd's runc defaults as closely as contrib/seccomp allows.
// The data (capabilities, masked and read-only paths) comes from
// internal/rootpolicy, which the root helper's containerd gate checks every
// spec against, so the builder and the checker cannot drift apart.
func securitySpecOpts() []oci.SpecOpts {
	return []oci.SpecOpts{
		seccomp.WithDefaultProfile(),
		oci.WithAddedCapabilities(defaultCapabilities()),
		// containerd's base spec already grants CAP_NET_RAW, so leaving it out
		// of the added set is not enough; it has to be dropped explicitly.
		oci.WithDroppedCapabilities(droppedCapabilities()),
		oci.WithMaskedPaths(defaultMaskedPaths()),
		oci.WithReadonlyPaths(defaultReadonlyPaths()),
		oci.WithNoNewPrivileges,
	}
}

func defaultCapabilities() []string { return rootpolicy.SandboxCapabilities() }

// droppedCapabilities are removed from every non-privileged sandbox; see
// rootpolicy.DroppedCapabilities for why CAP_NET_RAW is one.
func droppedCapabilities() []string { return rootpolicy.DroppedCapabilities() }

func defaultMaskedPaths() []string { return rootpolicy.MaskedPaths() }

func defaultReadonlyPaths() []string { return rootpolicy.ReadonlyPaths() }

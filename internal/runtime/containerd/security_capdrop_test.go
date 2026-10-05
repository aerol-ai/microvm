package containerd

import (
	"context"
	"slices"
	"testing"

	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// TestSecuritySpecDropsNetRaw applies the security envelope to a spec that
// already carries containerd's base capability set (which includes NET_RAW)
// and asserts NET_RAW is gone from every set (P0-2).
func TestSecuritySpecDropsNetRaw(t *testing.T) {
	base := []string{"CAP_CHOWN", "CAP_NET_RAW", "CAP_KILL"}
	spec := &oci.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{
		Bounding:    slices.Clone(base),
		Effective:   slices.Clone(base),
		Permitted:   slices.Clone(base),
		Inheritable: slices.Clone(base),
	}}}
	for _, opt := range []oci.SpecOpts{
		oci.WithAddedCapabilities(defaultCapabilities()),
		oci.WithDroppedCapabilities(droppedCapabilities()),
	} {
		if err := opt(context.Background(), nil, nil, spec); err != nil {
			t.Fatalf("spec opt: %v", err)
		}
	}
	caps := spec.Process.Capabilities
	for name, set := range map[string][]string{
		"bounding": caps.Bounding, "effective": caps.Effective,
		"permitted": caps.Permitted,
	} {
		if slices.Contains(set, "CAP_NET_RAW") {
			t.Fatalf("%s set still contains CAP_NET_RAW: %v", name, set)
		}
		if !slices.Contains(set, "CAP_CHOWN") {
			t.Fatalf("%s set lost CAP_CHOWN: %v", name, set)
		}
	}
	if slices.Contains(defaultCapabilities(), "CAP_NET_RAW") {
		t.Fatal("defaultCapabilities must not add CAP_NET_RAW back")
	}
}

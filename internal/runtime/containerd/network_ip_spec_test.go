package containerd

import (
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// The IP lookup reads the netns the spec pins before anything else; under
// runsc the pid-based fallback lands in the host namespace and reports the
// node's own address (T18, UC-44 gvisor 502s).
func TestSpecNetworkNamespacePath(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *specs.Spec
		want string
	}{
		{"nil spec", nil, ""},
		{"no linux section", &specs.Spec{}, ""},
		{"pinned netns from the pool", &specs.Spec{Linux: &specs.Linux{Namespaces: []specs.LinuxNamespace{
			{Type: specs.PIDNamespace},
			{Type: specs.NetworkNamespace, Path: " /var/run/netns/sb-1 "},
		}}}, "/var/run/netns/sb-1"},
		{"network namespace left to the runtime", &specs.Spec{Linux: &specs.Linux{Namespaces: []specs.LinuxNamespace{
			{Type: specs.NetworkNamespace},
		}}}, ""},
		{"no network namespace at all", &specs.Spec{Linux: &specs.Linux{Namespaces: []specs.LinuxNamespace{
			{Type: specs.MountNamespace, Path: "/proc/1/ns/mnt"},
		}}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := specNetworkNamespacePath(tc.spec); got != tc.want {
				t.Fatalf("specNetworkNamespacePath = %q, want %q", got, tc.want)
			}
		})
	}
}

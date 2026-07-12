package containerd

import (
	"context"
	"slices"
	"testing"

	"github.com/containerd/containerd/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/pkg/models"
)

// applyOpts runs each SpecOpt against a base spec with no client/container,
// mirroring how cntr.WithNewSpec applies them, so we can assert the resulting
// OCI spec content offline. This is the regression net for the "spec opts
// appended after WithNewSpec captured the slice" bug — if the security/limit
// opts are not part of the assembled slice, the generated spec is weak.
func applyOpts(t *testing.T, opts []oci.SpecOpts) *specs.Spec {
	t.Helper()
	spec := &specs.Spec{
		Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{}},
		Linux:   &specs.Linux{},
	}
	for _, opt := range opts {
		if err := opt(context.Background(), nil, nil, spec); err != nil {
			t.Fatalf("apply spec opt: %v", err)
		}
	}
	return spec
}

func TestSecuritySpecOptsEnvelope(t *testing.T) {
	spec := applyOpts(t, securitySpecOpts())

	if spec.Linux.Seccomp == nil {
		t.Fatal("seccomp profile missing — sandbox would run with full syscall surface")
	}
	if spec.Process.NoNewPrivileges != true {
		t.Fatal("NoNewPrivileges not set — setuid escalation possible")
	}
	// Capability set must match dockerd's default non-privileged bounding set
	// and must NOT include dangerous caps.
	if !slices.Contains(spec.Process.Capabilities.Bounding, "CAP_CHOWN") {
		t.Fatalf("expected CAP_CHOWN in bounding set, got %v", spec.Process.Capabilities.Bounding)
	}
	if slices.Contains(spec.Process.Capabilities.Bounding, "CAP_SYS_ADMIN") {
		t.Fatal("CAP_SYS_ADMIN must not be in the default capability set")
	}
	if !slices.Contains(spec.Linux.MaskedPaths, "/proc/kcore") {
		t.Fatalf("/proc/kcore not masked, masked=%v", spec.Linux.MaskedPaths)
	}
	if len(spec.Linux.ReadonlyPaths) == 0 {
		t.Fatal("expected readonly paths (e.g. /proc/sys)")
	}
}

func TestResourceSpecOptsUsesCFSQuotaNotCpuset(t *testing.T) {
	spec := applyOpts(t, resourceSpecOpts(models.CreateSandboxRequest{MemoryMB: 256, CPU: 0.5}))

	if spec.Linux.Resources == nil || spec.Linux.Resources.Memory == nil || spec.Linux.Resources.Memory.Limit == nil {
		t.Fatal("memory limit not set")
	}
	if *spec.Linux.Resources.Memory.Limit != 256*1024*1024 {
		t.Fatalf("memory limit = %d, want %d", *spec.Linux.Resources.Memory.Limit, 256*1024*1024)
	}
	// Fractional CPU must become a CFS quota/period, NOT a cpuset string
	// ("0.500" would be an invalid cpuset that runc rejects).
	if spec.Linux.Resources.CPU == nil || spec.Linux.Resources.CPU.Quota == nil || spec.Linux.Resources.CPU.Period == nil {
		t.Fatal("CPU CFS quota/period not set")
	}
	if spec.Linux.Resources.CPU.Cpus != "" {
		t.Fatalf("CPU.Cpus (cpuset) must be empty for fractional CPU, got %q", spec.Linux.Resources.CPU.Cpus)
	}
	if got := *spec.Linux.Resources.CPU.Quota; got != 50000 {
		t.Fatalf("CPU quota = %d, want 50000 (0.5 * 100ms period)", got)
	}
}

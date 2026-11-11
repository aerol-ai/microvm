package daemon

import (
	"fmt"
	"log/slog"

	"github.com/aerol-ai/microvm/internal/config"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

// capacityFromCgroupParent sizes admission from the cgroup that holds the
// sandboxes when one is configured (C7, SB_CONTAINERD_CGROUP_PARENT), not
// from the machine. On a Kubernetes worker the machine has more CPUs and
// memory than the pod may use, and admission sized from them accepted more
// than the pod could hold (Kubernetes Phase 0, finding F3). The free-memory
// probe also reads the room left under that cgroup's limit, so the floor
// sees the pod filling up, not only the machine.
//
// Without a cgroup parent nothing changes: on a VM, sandboxes do not run
// under sandboxd's group. The operator's explicit SB_HOST_* overrides are
// applied after this and still win. A limit that cannot be read stops the
// boot, as C7's own check does: admission sized from the machine is the
// bug this fixes.
func capacityFromCgroupParent(cfg config.Config, logger *slog.Logger, host capacity.HostInfo, probe capacity.MemProbe) (capacity.HostInfo, capacity.MemProbe, error) {
	if cfg.ContainerdCgroupParent == "" {
		return host, probe, nil
	}
	l, err := capacity.ReadCgroupLimit(cntr.CgroupRoot, cfg.ContainerdCgroupParent)
	if err != nil {
		return host, probe, fmt.Errorf("read the limits of the sandboxes' cgroup %s: %w", cfg.ContainerdCgroupParent, err)
	}
	clamped := host.ClampedTo(l)
	logger.Info("capacity sized from the sandboxes' cgroup, not the machine",
		"cgroup_parent", cfg.ContainerdCgroupParent,
		"cgroup_cpus", l.CPUs,
		"cgroup_memory_mb", l.MemoryBytes>>20,
		"machine_cpu_cores", host.CPUCores,
		"machine_memory_mb", host.MemoryTotalMB,
		"cpu_cores", clamped.CPUCores,
		"memory_mb", clamped.MemoryTotalMB,
	)
	return clamped, capacity.NewCgroupMemProbe(cntr.CgroupRoot, l, probe), nil
}

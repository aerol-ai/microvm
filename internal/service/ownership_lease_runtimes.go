package service

import (
	"fmt"

	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Which sandboxes the runtime supervisor can freeze on its own (review N2).
//
// On a node that writes the ownership lease file (SB_OWNERSHIP_LEASE_FILE, a
// Kubernetes worker), the runtime supervisor freezes every failover.policy=
// recreate sandbox the file fences once the lease runs out, even with
// sandboxd down (internal/supervisor/lease.go). It freezes a cgroup, so a
// sandbox can be fenced only if it runs in a group of its own under the
// sandboxes' parent:
//
//   - a container: its container's group, named by its container ref;
//   - a Firecracker VM: its own group, aerolvm-vmm/<sandbox> (the driver's
//     FenceGroup), when the VMs' cgroup sits under that same parent (the
//     default: SB_HOST_PROCESS_CGROUP_PARENT unset, or the containerd one);
//   - a WASM or V8-isolate sandbox: never. Their host processes (a WASM
//     resident host, a workerd group host) run many sandboxes, so no group
//     holds one sandbox alone, and freezing a shared one would stop the
//     others.
//
// Before, a Firecracker VM's file entry named a group that did not exist
// and WASM and isolate sandboxes were fenced in name only: each could run
// on after the cluster recreated it elsewhere. Now a recreate-policy create
// of a runtime the supervisor cannot freeze is refused on such a node, and
// a Firecracker VM is fenced in its own group.

// fenceRef is the group the lease file names for sb, under the sandboxes'
// cgroup parent: the runtime's own (FenceGrouper), or the container ref.
func (s *Service) fenceRef(sb *models.Sandbox) string {
	if rt, err := s.runtimeForSandbox(sb); err == nil {
		if g, ok := rt.(runtime.FenceGrouper); ok {
			return g.FenceGroup(sb.ID)
		}
	}
	return s.runtimeRef(sb)
}

// leaseFreezable reports whether the runtime supervisor can freeze a
// sandbox of runtime alone, on this node.
func (s *Service) leaseFreezable(chosenRuntime string) bool {
	switch chosenRuntime {
	case models.RuntimeWasm, models.RuntimeIsolate:
		return false
	case models.RuntimeFirecracker:
		return s.cfg.HostProcessCgroupParent == "" || s.cfg.HostProcessCgroupParent == s.cfg.ContainerdCgroupParent
	}
	return true
}

// refuseUnfencedRecreate refuses a failover.policy=recreate create, on a
// node that writes the lease file, of a runtime whose sandboxes the runtime
// supervisor cannot freeze alone: such a sandbox could run on here after
// the cluster recreated it elsewhere. A field check, nothing more; it runs
// on the failover recreate path too, so a sandbox is never recreated onto
// a node that could not fence it. 400, as every create validation.
func (s *Service) refuseUnfencedRecreate(failover *models.Failover, chosenRuntime string) error {
	if !s.ownershipLeaseFileOn() || failover == nil || !failover.ShouldRecreate() || s.leaseFreezable(chosenRuntime) {
		return nil
	}
	why := "its host process runs other sandboxes too"
	if chosenRuntime == models.RuntimeFirecracker {
		why = "its VMs' cgroup (SB_HOST_PROCESS_CGROUP_PARENT) is not under the sandboxes' cgroup parent"
	}
	return fmt.Errorf("failover.policy=recreate is not available for runtime %q on this node: if the node lost touch with the cluster, its runtime supervisor could not stop such a sandbox alone (%s), so it could run on here after being recreated elsewhere; use failover.policy=none, or a container or Firecracker runtime", chosenRuntime, why)
}

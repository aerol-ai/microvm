package daemon

import (
	"fmt"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// ownsPIDNamespace is hostproc.OwnsPIDNamespace; a var so tests set it.
var ownsPIDNamespace = hostproc.OwnsPIDNamespace

// checkHostProcessesOutliveAgent refuses to boot a worker that would start
// WASM, V8-isolate or Firecracker sandboxes it cannot keep (C14,
// plans/kubernetes-v2-architecture.md §8.9). These sandboxes are processes
// sandboxd starts, put in a cgroup outside its own so they outlive it. In a
// Kubernetes worker pod that is not enough: when the agent container owns
// its PID namespace, the container's end ends the namespace and the kernel
// kills every process in it, so each agent restart or upgrade would kill
// every such sandbox. The pod must share one process namespace
// (shareProcessNamespace: true, which the chart sets when these runtimes
// are on). Checked only where a cgroup parent says sandboxd runs in such a
// pod (SB_HOST_PROCESS_CGROUP_PARENT, by default SB_CONTAINERD_CGROUP_PARENT):
// on a VM PID 1 is systemd, and in a plain container a restart restarts
// everything anyway.
func checkHostProcessesOutliveAgent(cfg config.Config) error {
	if cfg.HostProcessCgroupParent == "" || !cfg.RunsHostProcessSandboxes() {
		return nil
	}
	owns, err := ownsPIDNamespace()
	if err != nil {
		return fmt.Errorf("WASM, V8-isolate and Firecracker sandboxes: cannot tell whether they would outlive this container: %w", err)
	}
	if owns {
		return fmt.Errorf("WASM, V8-isolate and Firecracker sandboxes need the worker pod to share one process namespace " +
			"(shareProcessNamespace: true): this container owns its own, so its restart would kill every one of them. " +
			"Turn those runtimes off (SB_ENABLE_WASM, SB_ENABLE_ISOLATE, SB_ENABLE_FIRECRACKER) or share the namespace")
	}
	return nil
}

// mountsOffReason says why this node must refuse external storage, or ""
// when it may serve it (F13). Only in a Kubernetes worker pod (a cgroup
// parent set, as above): there sandboxd's mount helpers serve sandboxes the
// runtime container builds, and a mount is safe to hand out only when
//
//   - the chart turned external storage on (worker.externalStorage.enabled),
//     which gives the two containers a mounts folder with two-way
//     propagation and gives sandboxd the runtime's pid to check each mount
//     through (SB_MOUNTS_RUNTIME_PID_FILE); and
//   - the pod shares one process namespace. Without it that pid names a
//     process in sandboxd's own container, so the check sees only itself,
//     and each helper ends with this container's namespace at the next
//     agent restart.
//
// The chart keeps external storage off by default: sharing the namespace
// lets every container in the pod, the internet-facing edge among them,
// read the command line of every process in it. A refusal is the safe
// answer: the sandbox would otherwise get the empty folder under its mount
// and write to local disk instead of the store.
func mountsOffReason(cfg config.Config) string {
	if cfg.HostProcessCgroupParent == "" {
		return ""
	}
	if cfg.MountsRuntimePIDFile == "" {
		return "external storage is off on this Kubernetes worker (chart value worker.externalStorage.enabled)"
	}
	owns, err := ownsPIDNamespace()
	if err != nil {
		return fmt.Sprintf("cannot tell whether this Kubernetes worker pod shares one process namespace: %v", err)
	}
	if owns {
		return "this Kubernetes worker pod does not share one process namespace (shareProcessNamespace: true), " +
			"so a mount helper would end with the agent container and a mount could not be checked from the runtime container"
	}
	return ""
}

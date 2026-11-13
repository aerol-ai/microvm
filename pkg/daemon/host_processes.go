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

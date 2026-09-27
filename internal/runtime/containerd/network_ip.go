package containerd

import (
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// containerIPv4FromTaskFn resolves the task's primary IPv4. Tests stub this on
// non-linux hosts where netlink/netns probing is unavailable.
var containerIPv4FromTaskFn = containerIPv4FromTask

// specNetworkNamespacePath returns the network namespace the OCI spec pins the
// container to, or "" when the spec leaves it to the runtime.
//
// This is the authoritative answer, and the one gVisor needs. The pid-based
// lookup enters the netns of the task's first process, which under runsc is a
// sandbox process in the HOST network namespace: it found the host's eth0 and
// recorded the node's own IP as the sandbox's, so every toolbox call dialled
// <node-ip>:2280 and got "connection refused" (T18, UC-44 gvisor 502s).
func specNetworkNamespacePath(spec *specs.Spec) string {
	if spec == nil || spec.Linux == nil {
		return ""
	}
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.NetworkNamespace {
			return strings.TrimSpace(ns.Path)
		}
	}
	return ""
}

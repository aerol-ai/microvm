package containerd

import "expvar"

// Engine observability tag (plans/containerd-engine.md §2 / Phase 5).
// Set to "containerd" when the driver is wired; remains "docker" otherwise
// so dashboards can split metrics without SSH.
var containerEngineExpvar = expvar.NewString("aerolvm_container_engine")

// inspectIPUnavailableTotal counts Inspects of a running task whose address
// could not be read (the netns probe failed). Each one is reported as a
// started sandbox without an address instead of an error. A steady rate means
// a sandbox whose network namespace is broken or gone while its task runs.
var inspectIPUnavailableTotal = expvar.NewInt("aerolvm_containerd_inspect_ip_unavailable_total")

func init() {
	containerEngineExpvar.Set("docker")
}

// PublishEngineTag stamps the host engine into expvar for operator dashboards.
func PublishEngineTag(engine string) {
	if engine == "" {
		engine = "docker"
	}
	containerEngineExpvar.Set(engine)
}

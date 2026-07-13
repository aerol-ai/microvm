package containerd

import "expvar"

// Engine observability tag (plans/containerd-engine.md §2 / Phase 5).
// Set to "containerd" when the driver is wired; remains "docker" otherwise
// so dashboards can split metrics without SSH.
var containerEngineExpvar = expvar.NewString("aerolvm_container_engine")

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

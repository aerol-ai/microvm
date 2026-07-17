package daemon

import (
	"log/slog"

	"github.com/aerol-ai/microvm/internal/config"
	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/internal/service"
)

// wireIsolateRuntime constructs the V8-isolate driver and registers it on the
// service (plans/isolate-runtime.md). Phase 1 wires the dispatch skeleton
// only; the bundle resolver (pkg/jsbundle) and the blank-host warm pool
// (internal/pool/isolate) attach here in Phases 2–3, mirroring how
// wireWasmRuntime grew.
func wireIsolateRuntime(cfg config.Config, logger *slog.Logger, svc *service.Service) *isolateruntime.Driver {
	driver := isolateruntime.New(isolateruntime.FromDaemonConfig(cfg), logger)
	svc.SetIsolateRuntime(driver)
	logger.Info("isolate runtime enabled",
		"workerd_path", cfg.IsolateWorkerdPath,
		"run_dir", cfg.IsolateRunDir,
		"group_granularity", cfg.IsolateGroupGranularity,
		"jail", cfg.IsolateUseJail,
		"jitless", cfg.IsolateJitless,
	)
	return driver
}

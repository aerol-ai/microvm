package daemon

import (
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/aerol-ai/microvm/internal/config"
	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
)

// wireIsolateRuntime constructs the V8-isolate driver, its bundle resolver
// (pkg/jsbundle content-addressed store) and its workerd group supervisor
// (pkg/isolate), and registers the driver on the service
// (plans/isolate-runtime.md Phase 2). The warm pool (internal/pool/isolate)
// attaches here in Phase 3, mirroring how wireWasmRuntime grew.
func wireIsolateRuntime(cfg config.Config, logger *slog.Logger, svc *service.Service) (*isolateruntime.Driver, error) {
	isoCfg := isolateruntime.FromDaemonConfig(cfg)
	driver := isolateruntime.New(isoCfg, logger)

	// Content-addressed bundle store under the run dir (POST /v1/js-bundles
	// writes here; file:// refs resolve without touching it). Size/quota caps
	// stay unlimited for the self-host default; the managed control plane sets
	// them when it lands.
	store, err := jsbundle.NewStore(jsbundle.StoreConfig{
		Dir: filepath.Join(cfg.IsolateRunDir, "bundles"),
	})
	if err != nil {
		return nil, fmt.Errorf("isolate bundle store: %w", err)
	}
	driver.SetBundleResolver(isolateruntime.NewBundleResolver(jsbundle.NewResolver(store)))
	driver.SetHostSupervisor(isolateruntime.NewHostSupervisor(isoCfg))

	// The service owns the same store instance: it serves POST /v1/js-bundles
	// and does the owner-scoped name→digest resolution on create, and the
	// driver's resolver reads the digests back out.
	svc.SetIsolateBundleStore(store)
	svc.SetIsolateRuntime(driver)
	logger.Info("isolate runtime enabled",
		"workerd_path", cfg.IsolateWorkerdPath,
		"run_dir", cfg.IsolateRunDir,
		"group_granularity", cfg.IsolateGroupGranularity,
		"jail", cfg.IsolateUseJail,
		"jitless", cfg.IsolateJitless,
	)
	return driver, nil
}

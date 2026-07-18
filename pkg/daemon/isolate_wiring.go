package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync/atomic"

	"github.com/aerol-ai/microvm/internal/config"
	isolatepool "github.com/aerol-ai/microvm/internal/pool/isolate"
	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
)

// wireIsolateRuntime constructs the V8-isolate driver, its bundle resolver
// (pkg/jsbundle content-addressed store), its workerd group supervisor
// (pkg/isolate), the blank-host warm pool, idle-TTL reaper, and bundle GC
// (plans/isolate-runtime.md Phase 2 leftovers + Phase 3).
func wireIsolateRuntime(cfg config.Config, logger *slog.Logger, svc *service.Service) (*isolateruntime.Driver, error) {
	isoCfg := isolateruntime.FromDaemonConfig(cfg)
	driver := isolateruntime.New(isoCfg, logger)

	store, err := jsbundle.NewStore(jsbundle.StoreConfig{
		Dir: filepath.Join(cfg.IsolateRunDir, "bundles"),
	})
	if err != nil {
		return nil, fmt.Errorf("isolate bundle store: %w", err)
	}
	driver.SetBundleResolver(isolateruntime.NewBundleResolver(jsbundle.NewResolver(store)))
	supervisor := isolateruntime.NewHostSupervisor(isoCfg)
	driver.SetHostSupervisor(supervisor)

	if cfg.IsolatePoolEnabled {
		pool := isolatepool.New(logger)
		pool.SetDepth(cfg.IsolatePoolDepthDefault)
		pool.SetSpawner(&poolSpawner{supervisor: supervisor})
		driver.SetWarmPool(pool)
		// Boot prewarm + refill: fill blank hosts before the first create
		// (the wasm prewarm lesson — ticker-only leaves the first creates cold).
		go func() {
			ctx := context.Background()
			for i := 0; i < cfg.IsolatePoolDepthDefault; i++ {
				if err := pool.WarmOne(ctx); err != nil {
					logger.Warn("isolate warm pool boot fill failed", "error", err)
					break
				}
			}
			pool.RunRefill(ctx, cfg.IsolatePoolRefillInterval)
		}()
	}

	svc.SetIsolateBundleStore(store)
	svc.SetIsolateRuntime(driver)
	logger.Info("isolate runtime enabled",
		"workerd_path", cfg.IsolateWorkerdPath,
		"run_dir", cfg.IsolateRunDir,
		"group_granularity", cfg.IsolateGroupGranularity,
		"jail", cfg.IsolateUseJail,
		"jitless", cfg.IsolateJitless,
		"idle_ttl", cfg.IsolateGroupIdleTTL,
		"pool", cfg.IsolatePoolEnabled,
	)
	return driver, nil
}

// startIsolateBackground starts the idle-TTL reaper and bundle GC loops.
func startIsolateBackground(ctx context.Context, cfg config.Config, driver *isolateruntime.Driver, svc *service.Service) {
	if driver != nil {
		go driver.RunIdleReaper(ctx)
	}
	if svc != nil {
		go svc.RunJSBundleGCLoop(ctx, cfg.IsolateBundleGCInterval)
	}
}

// poolSpawner adapts HostSupervisor into the warm-pool Spawner seam: each
// warm slot is a real blank group host under a synthetic pool key.
type poolSpawner struct {
	supervisor isolateruntime.HostSupervisor
	n          atomic.Int64
}

func (s *poolSpawner) Spawn(ctx context.Context) (isolateruntime.GroupHost, error) {
	n := s.n.Add(1)
	key := fmt.Sprintf("warm-%d", n)
	// Warm slots are blank group hosts — jail realization is best-effort for
	// the pool (the supervisor only needs GroupKey for the run-dir path).
	return s.supervisor.SpawnGroup(ctx, isolateruntime.JailSpec{GroupKey: key})
}

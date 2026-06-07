package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// wireWasmRuntime constructs the WASM driver and optional warm pool. The returned
// pool is non-nil only when SB_WASM_POOL_ENABLED=true; the caller should Close
// it on daemon shutdown.
func wireWasmRuntime(ctx context.Context, cfg config.Config, logger *slog.Logger, svc *service.Service) *wasmpool.Pool {
	driver := wasmruntime.New(wasmruntime.FromDaemonConfig(cfg), logger)
	resolver := wasmmod.NewResolver(cfg.WasmModulesDir)
	supervisor := worker.NewSupervisor(worker.DefaultSpawner)
	driver.SetModuleResolver(resolver)
	driver.SetWorkerSupervisor(supervisor)
	svc.SetWasmRuntime(driver)
	svc.SetWasmModuleResolver(resolver)

	var pool *wasmpool.Pool
	if cfg.WasmPoolEnabled {
		pool = wasmpool.New(cfg.WasmRunDir, logger)
		pool.SetDefaultDepth(cfg.WasmPoolDepthDefault)
		spawner := wasmpool.NewSupervisorSpawner(supervisor)
		driver.SetWarmPool(pool)
		refillCfg := wasmpool.RefillConfig{
			RefillInterval: cfg.WasmPoolRefillInterval,
			SpawnTimeout:   30 * time.Second,
		}
		go wasmpool.RunRefill(ctx, pool, refillCfg, spawner, logger)
		logger.Info("wasm warm pool enabled",
			"depth_default", cfg.WasmPoolDepthDefault,
			"refill_interval", cfg.WasmPoolRefillInterval)
	}

	logger.Info("wasm runtime enabled",
		"run_dir", cfg.WasmRunDir,
		"modules_dir", cfg.WasmModulesDir,
		"pool_enabled", cfg.WasmPoolEnabled,
	)
	return pool
}

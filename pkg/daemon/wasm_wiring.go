package daemon

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/runtime/wasm/statekv"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// wireWasmRuntime constructs the WASM driver and optional warm pool. The returned
// pool is non-nil only when SB_WASM_POOL_ENABLED=true; the caller should Close
// it on daemon shutdown.
func wireWasmRuntime(ctx context.Context, cfg config.Config, logger *slog.Logger, svc *service.Service, st *store.Store) *wasmpool.Pool {
	driver := wasmruntime.New(wasmruntime.FromDaemonConfig(cfg), logger)
	// One ModuleResolver chokepoint shared by the runtime driver (create-time
	// resolution) and the service (CreateWasmModule registration), so allowlist
	// + validation + content-addressed pull happen in exactly one place.
	resolver := wasmmod.NewModuleResolver(cfg.WasmModulesDir, cfg.WasmCacheDir)
	resolver.Reserved = cfg.WasmStandardModules
	resolver.Allowlist = make(map[string]struct{}, len(cfg.WasmRegistryAllowlist))
	for _, h := range cfg.WasmRegistryAllowlist {
		resolver.Allowlist[h] = struct{}{}
	}
	resolver.PullTimeout = cfg.WasmPullTimeout
	resolver.Auth = wasmmod.ModuleAuth{
		Username: cfg.WasmRegistryUsername,
		PATPath:  cfg.WasmRegistryPATPath,
	}
	supervisor := worker.NewSupervisor(worker.DefaultSpawner)
	driver.SetModuleResolver(resolver)
	driver.SetWorkerSupervisor(supervisor)
	if st != nil {
		// Wrap the durable host-KV store in a per-sandbox write limiter so a
		// chatty guest cannot starve the single-writer boot path (§4.6).
		// NewRateLimitedStore returns the inner store unchanged when the rate is
		// 0, keeping the feature off when the operator disables it.
		kv := statekv.NewRateLimitedStore(statekv.NewSQLiteStore(st), cfg.WasmStateKVWritesPerSec, cfg.WasmStateKVBurst)
		driver.SetStateKV(kv)
	}
	svc.SetWasmRuntime(driver)
	svc.SetWasmModuleResolver(resolver)

	if eng := strings.TrimSpace(cfg.WasmEngine); eng != "" && eng != "wazero" {
		_ = os.Setenv("AEROL_WASM_ENGINE", eng)
	}

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
		"engine", cfg.WasmEngine,
		"pool_enabled", cfg.WasmPoolEnabled,
	)
	return pool
}

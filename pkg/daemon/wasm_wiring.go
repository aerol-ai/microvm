package daemon

import (
	"context"
	"expvar"
	"log/slog"
	"os"
	"path/filepath"
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
	resolver.SetDigestMode(cfg.WasmModuleDigestMode)
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
	if st != nil {
		// Wire step-3 of the resolution precedence: a BYO catalogue id
		// (returned by CreateWasmModule) maps to its already-local, already
		// validated path + pinned digest. Only "ready" rows with a real path
		// resolve — a pending/failed row must fall through to a 404 rather than
		// boot a half-staged artifact. Lookup is read-only and goes through the
		// single-writer store like every other query.
		resolver.CatalogueLookup = func(ctx context.Context, id string) (path, digest string, ok bool) {
			rec, err := st.GetWasmModule(ctx, id)
			if err != nil {
				return "", "", false
			}
			if !strings.EqualFold(rec.Status, "ready") || strings.TrimSpace(rec.ModulePath) == "" {
				return "", "", false
			}
			return rec.ModulePath, rec.Digest, true
		}
	}
	supervisor := worker.NewSupervisor(worker.DefaultSpawner)
	driver.SetModuleResolver(resolver)
	driver.SetWorkerSupervisor(supervisor)
	// Resident-module host (compile-once/instantiate-many): opt-in, default off.
	// A second supervisor owns the shared host processes so their lifecycle is
	// independent of per-sandbox workers. Wired only when enabled — otherwise the
	// driver's residentHostEnabled() stays false and every create takes the
	// per-sandbox path. See plans/wasm-resident-module-host.md.
	if cfg.WasmResidentHostEnabled {
		driver.SetResidentHostSupervisor(worker.NewSupervisor(worker.DefaultResidentSpawner))
	}
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
	if dir := effectiveWasmCompileCacheDir(cfg); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			logger.Warn("wasm compile cache dir not created", "dir", dir, "error", err)
		} else {
			_ = os.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", dir)
		}
	}

	var pool *wasmpool.Pool
	if warmPoolEffectivelyEnabled(cfg) {
		pool = wasmpool.New(cfg.WasmRunDir, logger)
		pool.SetDefaultDepth(cfg.WasmPoolDepthDefault)
		pool.SetDefaultMemoryMB(cfg.WasmDefaultMemoryMB)
		spawner := wasmpool.NewSupervisorSpawner(supervisor)
		spawner.MemoryMB = cfg.WasmDefaultMemoryMB
		driver.SetWarmPool(pool)
		// Registration-time NoteModule (the API twin of seedStandardModules
		// below): POST /v1/wasm-modules marks the resolved digest as a refill
		// target on this node, so the pool pre-compiles before the module's
		// first create instead of learning it lazily inside Acquire.
		svc.SetWasmWarmPool(pool)
		refillCfg := wasmpool.RefillConfig{
			RefillInterval: cfg.WasmPoolRefillInterval,
			SpawnTimeout:   30 * time.Second,
		}
		go wasmpool.RunRefill(ctx, pool, refillCfg, spawner, logger)
		// Pre-seed the warm pool with the standard modules so the first tenant
		// create against "python" et al. hits a warm slot instead of paying cold
		// worker boot. Without this, a reserved keyword is only NoteModule'd
		// lazily on its first create — exactly the latency we staged the module
		// fleet-wide to avoid. Done in the background (resolution hashes up to a
		// 256MiB file) so it never blocks daemon startup (hard rule 2).
		go seedStandardModules(ctx, resolver, pool, cfg.WasmStandardModules, logger)
		logger.Info("wasm warm pool enabled",
			"depth_default", cfg.WasmPoolDepthDefault,
			"refill_interval", cfg.WasmPoolRefillInterval)
	} else if cfg.WasmPoolEnabled {
		// Resident host on: it serves every non-listen create, so the warm pool
		// would only pre-spawn redundant per-sandbox workers for the same modules
		// (double the resident memory — starved a t3.medium in the 2026-07-17
		// bench). Skip it. Public-expose creates take the cold path either way
		// (migrate-on-expose already pays that compile). See
		// plans/wasm-resident-module-host.md Validation.
		logger.Info("wasm warm pool skipped: resident host enabled (would only pre-spawn redundant workers for resident-served modules)")
	}

	// Boot-time resident-host pre-warm: bring up + compile the standard-module
	// resident hosts ahead of demand so the first create is an Instantiate, not a
	// cold compile. Backgrounded (compiling ~25MB modules is slow) so it never
	// blocks daemon boot (hard rule 2 / pr-review.md §2). No-op unless the flag
	// is set and a resident supervisor was wired above.
	if cfg.WasmResidentHostEnabled {
		refs := make([]string, 0, len(cfg.WasmStandardModules))
		for alias := range cfg.WasmStandardModules {
			refs = append(refs, alias)
		}
		go driver.PrewarmResidentHosts(ctx, refs)
		logger.Info("wasm resident host prewarm scheduled", "modules", len(refs))
		// Idle-TTL reaper: reclaim a resident host's RAM once it has held zero
		// instances for the TTL (pre-warmed standard-module hosts are pinned and
		// never reaped). Stops when ctx is cancelled on shutdown. No-op if the TTL
		// is 0. See plans/wasm-resident-module-host.md PR-C.
		go driver.RunResidentReaper(ctx, cfg.WasmResidentHostIdleTTL)
		logger.Info("wasm resident host reaper scheduled", "idle_ttl", cfg.WasmResidentHostIdleTTL)
		// Observability for the conservative capacity stance (PR-C): the admitter
		// cannot see a resident host process's own RAM (shared compiled module +
		// runtime), so expose the host footprint here and let operators reserve
		// headroom via MemoryFloorRatio/MemoryReservationRatio. Guard the publish
		// so a second wiring in-process (tests) doesn't panic on a duplicate name.
		if expvar.Get("aerolvm_wasm_resident_hosts") == nil {
			expvar.Publish("aerolvm_wasm_resident_hosts", expvar.Func(func() any {
				return driver.ResidentHostStats()
			}))
		}
	}

	logger.Info("wasm runtime enabled",
		"run_dir", cfg.WasmRunDir,
		"modules_dir", cfg.WasmModulesDir,
		"engine", cfg.WasmEngine,
		"pool_enabled", cfg.WasmPoolEnabled,
	)
	if wasmWiringTestHook != nil {
		wasmWiringTestHook(resolver)
	}
	return pool
}

// warmPoolEffectivelyEnabled reports whether the per-sandbox WASM warm pool
// should actually be wired. It is enabled only when the operator asked for it
// AND the resident host is off: with the resident host on, every non-listen
// create instantiates into a shared resident host and never consults the warm
// pool, so pre-spawning warm workers just doubles the resident memory footprint
// (2026-07-17 bench finding). The two are redundant; resident wins.
func warmPoolEffectivelyEnabled(cfg config.Config) bool {
	return cfg.WasmPoolEnabled && !cfg.WasmResidentHostEnabled
}

// effectiveWasmCompileCacheDir returns the wazero compile cache path. When
// SB_WASM_COMPILE_CACHE_DIR is unset, default to <cache>/wazero-compile; when
// explicitly set to empty, disable the cache.
func effectiveWasmCompileCacheDir(cfg config.Config) string {
	if _, set := os.LookupEnv("SB_WASM_COMPILE_CACHE_DIR"); set {
		return strings.TrimSpace(cfg.WasmCompileCacheDir)
	}
	cacheDir := cfg.WasmCacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(cfg.WasmModulesDir, "cache")
	}
	return filepath.Join(cacheDir, "wazero-compile")
}

// wasmWiringTestHook is invoked at the end of wireWasmRuntime so tests can
// exercise the wired resolver without exporting it from service.
var wasmWiringTestHook func(*wasmmod.ModuleResolver)

// seedStandardModules resolves each reserved keyword to its content digest +
// path and registers it as a warm-pool refill target, so the standard runtimes
// are pre-warmed before any tenant references them. Best-effort: a missing or
// invalid staged module is logged and skipped (the keyword still resolves on
// create, it just won't be pre-warmed) rather than failing daemon boot.
func seedStandardModules(ctx context.Context, resolver *wasmmod.ModuleResolver, pool *wasmpool.Pool, reserved map[string]string, logger *slog.Logger) {
	if resolver == nil || pool == nil {
		return
	}
	for alias := range reserved {
		if ctx.Err() != nil {
			return
		}
		resolved, err := resolver.Resolve(ctx, alias)
		if err != nil {
			logger.Warn("wasm warm pool seed skipped: standard module did not resolve",
				"alias", alias, "error", err)
			continue
		}
		pool.NoteModule(resolved.Digest, resolved.Path)
		logger.Info("wasm warm pool seeded standard module", "alias", alias, "digest", resolved.Digest)
	}
}

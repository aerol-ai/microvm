package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/aerol-ai/microvm/internal/config"
	isolatepool "github.com/aerol-ai/microvm/internal/pool/isolate"
	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/internal/service"
	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
)

// wireIsolateRuntime constructs the V8-isolate driver, its bundle resolver
// (pkg/jsbundle content-addressed store), its workerd group supervisor
// (pkg/isolate), the blank-host warm pool, idle-TTL reaper, and bundle GC
// (plans/isolate-runtime.md Phase 2 leftovers + Phase 3).
func wireIsolateRuntime(ctx context.Context, cfg config.Config, logger *slog.Logger, svc *service.Service) (*isolateruntime.Driver, error) {
	isoCfg := isolateruntime.FromDaemonConfig(cfg)
	if cfg.IsolateUseJail {
		// Bootstrap belongs at daemon start: a jail that cannot be realized
		// here must fail boot, not the first tenant's create. The base tree
		// (workerd + its shared libraries + /dev nodes) is built once and
		// every group chroot is hard-linked from it.
		shim, err := isolateShimPath()
		if err != nil {
			return nil, fmt.Errorf("isolate jail: locate daemon binary for the jail shim: %w", err)
		}
		isoCfg.ShimPath = shim
		if !pkgisolate.JailRealizable() {
			return nil, fmt.Errorf("isolate jail: SB_ISOLATE_USE_JAIL=true but this host cannot realize a jail (Linux root required); set SB_ISOLATE_USE_JAIL=false to run unconfined, accepting the risk")
		}
		if err := pkgisolate.PrepareJailBase(cfg.IsolateJailChrootBase, cfg.IsolateWorkerdPath); err != nil {
			return nil, fmt.Errorf("isolate jail: prepare chroot base: %w", err)
		}
	}
	driver := isolateruntime.New(isoCfg, logger)

	store, err := jsbundle.NewStore(jsbundle.StoreConfig{
		Dir: filepath.Join(cfg.IsolateRunDir, "bundles"),
	})
	if err != nil {
		return nil, fmt.Errorf("isolate bundle store: %w", err)
	}
	driver.SetBundleResolver(isolateruntime.NewBundleResolver(jsbundle.NewResolver(store)))
	supervisor := isolateruntime.NewHostSupervisor(isoCfg)
	// E3a: host-mediated egress destinations → audit JSONL (async, dial path).
	if cfg.EgressAttributionEnabled {
		if setter, ok := supervisor.(interface {
			SetEgressObserver(pkgisolate.EgressObserver)
		}); ok {
			setter.SetEgressObserver(svc.EgressAuditObserver())
		}
	}
	driver.SetHostSupervisor(supervisor)

	if cfg.IsolatePoolEnabled {
		pool := isolatepool.New(logger)
		pool.SetDepth(cfg.IsolatePoolDepthDefault)
		pool.SetSpawner(&poolSpawner{supervisor: supervisor, cfg: isoCfg})
		driver.SetWarmPool(pool)
		// Boot prewarm + refill: fill blank hosts before the first create
		// (the wasm prewarm lesson — ticker-only leaves the first creates cold).
		// Runs on the daemon ctx so the refill loop stops on shutdown (matching
		// the idle-reaper / bundle-GC loops), rather than leaking on
		// context.Background() until process exit.
		go func() {
			for i := 0; i < cfg.IsolatePoolDepthDefault; i++ {
				if ctx.Err() != nil {
					return
				}
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
	// Honest jail reporting: distinguish "jail requested" (config) from "jail
	// realizable here" (platform). When jail is requested but not realizable,
	// isolate creates FAIL CLOSED — say so loudly rather than logging a bare
	// jail=true that implies confinement the host can't provide.
	jailRealizable := pkgisolate.JailRealizable()
	if cfg.IsolateUseJail && !jailRealizable {
		logger.Warn("isolate jail requested but not realizable on this host; isolate creates will FAIL CLOSED — set SB_ISOLATE_USE_JAIL=false to run unconfined (accepting the risk) or deploy on Linux",
			"platform_can_jail", jailRealizable,
		)
	}
	logger.Info("isolate runtime enabled",
		"workerd_path", cfg.IsolateWorkerdPath,
		"run_dir", cfg.IsolateRunDir,
		"group_granularity", cfg.IsolateGroupGranularity,
		"jail_requested", cfg.IsolateUseJail,
		"jail_realizable", jailRealizable,
		"jail_chroot_base", cfg.IsolateJailChrootBase,
		"jail_cgroup_root", cfg.IsolateJailCgroupRoot,
		"seccomp_mode", cfg.IsolateSeccompMode,
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
	cfg        isolateruntime.Config
	n          atomic.Int64
}

func (s *poolSpawner) Spawn(ctx context.Context) (isolateruntime.GroupHost, error) {
	n := s.n.Add(1)
	key := fmt.Sprintf("warm-%d", n)
	// A warm blank is jailed exactly like a tenant group — same chroot shape,
	// same uid, same filter — with unlimited caps until a tenant claims it
	// (the router then applies theirs). Anything less would hand a tenant an
	// unconfined process whenever the pool had one ready.
	spec, err := isolateruntime.BuildJailSpec(s.cfg, key, 0, 0)
	if err != nil {
		if !s.cfg.UseJail {
			// Unjailed pools never needed a valid jail identity; keep the
			// run-dir-only spec they always had.
			return s.supervisor.SpawnGroup(ctx, isolateruntime.JailSpec{GroupKey: key})
		}
		return nil, fmt.Errorf("isolate warm pool: jail spec for %s: %w", key, err)
	}
	return s.supervisor.SpawnGroup(ctx, spec)
}

// isolateShimPath is the daemon binary re-exec'd as the jail shim; tests
// replace it.
var isolateShimPath = func() (string, error) {
	return os.Executable()
}

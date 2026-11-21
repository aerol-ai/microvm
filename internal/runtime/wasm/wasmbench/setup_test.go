//go:build wasmbench

package wasmbench_test

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/aerol-ai/microvm/internal/network/workerfence"
	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
	"github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// This tree: workers drop to uid/gid 65534 when the bench runs as root,
// each owner has its own compile cache, and operator modules are compiled
// once into the shared one.

func dispatchExtra(args []string) (bool, error) {
	if args[1] == worker.PrecompileFlag {
		return true, worker.RunPrecompileCLI(args[2:])
	}
	return false, nil
}

func newBenchDriver(t *testing.T, cfg wasm.Config, e *env, resolver *wasmmod.ModuleResolver) (*wasm.Driver, *worker.Supervisor) {
	t.Helper()
	// BENCH_NO_CONFINE=1 keeps workers root, to split the drop's cost from
	// the rest of this tree's create path.
	confine := worker.ConfinementFor(os.Getenv("BENCH_NO_CONFINE") != "1", 65534, 65534)
	worker.SetGrantPolicy(worker.GrantPolicy{Roots: []string{e.runDir, e.modules, resolver.CacheDir, e.cacheRoot}, Worker: confine})
	if err := os.MkdirAll(e.cacheRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.Worker = confine
	cfg.CompileCacheDir = e.cacheRoot
	// The worker fence and its gate, as pkg/daemon wires them when workers
	// drop (BENCH_NO_FENCE=1 leaves them out, to measure what they cost).
	if confine.Enabled() && os.Getenv("BENCH_NO_FENCE") != "1" {
		// No exception for the guest listeners: only root connects to them.
		fence := workerfence.New(workerfence.NewBackend(), func() (workerfence.Spec, error) {
			var local []netip.Prefix
			addrs, _ := net.InterfaceAddrs()
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok {
					if ip, ok := netip.AddrFromSlice(n.IP); ok {
						ones, _ := n.Mask.Size()
						if ip = ip.Unmap(); ip.Is4() && ones > 32 {
							ones -= 96
						}
						local = append(local, netip.PrefixFrom(ip, ones))
					}
				}
			}
			return workerfence.Spec{UID: confine.UID, Local: local}, nil
		}, nil)
		if err := fence.Ensure(); err != nil {
			t.Fatal(err)
		}
		worker.SetConfineGate(fence.Ensure)
		t.Cleanup(func() { worker.SetConfineGate(nil); _ = workerfence.NewBackend().Remove() })
		cfg.GuestListenHost = workerfence.GuestListenHost
	}
	d := wasm.New(cfg, nil)
	workers := worker.NewSupervisor(worker.Confine(worker.DefaultSpawner, confine))
	d.SetWorkerSupervisor(workers)
	d.SetResidentHostSupervisor(worker.NewSupervisor(worker.Confine(worker.DefaultResidentSpawner, confine)))
	return d, workers
}

// newPoolSpawner gives each warm slot a compile cache of its own, as
// pkg/daemon does.
func newPoolSpawner(e *env) wasmpool.Spawner {
	sp := wasmpool.NewSupervisorSpawner(e.workers)
	sp.CompileCache = e.driver.SlotCompileCache
	return sp
}

// bootNode does what pkg/daemon does at boot: compile the standard modules
// into the shared cache.
func bootNode(e *env) {
	e.driver.PrecompileModules(context.Background(), []string{"stdio"})
}

package worker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// ListenFallbackEnv carries SB_WASM_WASMTIME_LISTEN_FALLBACK to the worker:
// "false" keeps a sandbox on the wasmtime engine from moving to wazero when
// it needs a guest listener (ensureListenEngineLocked). Unset means on.
const ListenFallbackEnv = "AEROL_WASM_WASMTIME_LISTEN_FALLBACK"

// loadedEngine is the module a per-sandbox worker runs and the engine it
// runs it on.
type loadedEngine struct {
	modulePath string
	memoryMB   int
	// name is the engine eng is; "" before the first load.
	name string
	// fallbackFrom is the configured engine the worker left for wazero to
	// serve HTTP; "" while it runs the configured one.
	fallbackFrom string
}

// noteLoadedLocked records a load_module. The caller holds mu and has just
// loaded p on a fresh engine of the configured kind, so a fallback ends.
func (s *Server) noteLoadedLocked(p loadModulePayload, err error) {
	if err != nil {
		s.loaded = loadedEngine{}
		return
	}
	s.loaded = loadedEngine{modulePath: p.Path, memoryMB: p.MemoryMB, name: configuredEngineName()}
}

// configuredEngineName is the engine the worker was started with
// (SB_WASM_ENGINE, projected as AEROL_WASM_ENGINE); empty means wazero.
func configuredEngineName() string {
	if name := workerEngineName(); name != "" {
		return name
	}
	return wasmengine.EngineNameWazero()
}

// engineNameLocked is the engine the instance runs on. The caller holds mu.
func (s *Server) engineNameLocked() string {
	if s.loaded.name != "" {
		return s.loaded.name
	}
	return configuredEngineName()
}

// listenFallbackEnabled reads ListenFallbackEnv. sandboxd validates the
// setting, so a value that does not parse keeps the default.
func listenFallbackEnabled() bool {
	on, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(ListenFallbackEnv)))
	return err != nil || on
}

// newListenEngine builds the engine a sandbox moves to when its own cannot
// pre-open a listener. A var so tests can fail it.
var newListenEngine = func(ctx context.Context) (wasmengine.Engine, error) {
	return wasmengine.NewEngineFor(ctx, wasmengine.EngineNameWazero())
}

// ensureListenEngineLocked makes sure eng can pre-open a guest listener
// before one is asked for. The caller holds mu, has checked eng is set, and
// instantiates right after.
//
// No wasmtime release can give a WASI guest a pre-opened TCP listener
// (#175: the C API had one in v14-v19 only, wasmtime-go never wrapped it,
// and preview-1 sock_accept is a stub there). So a sandbox on wasmtime that
// exposes a port moves to wazero: this worker rebuilds the engine from the
// module it loaded, and the caller instantiates the guest on it with the
// same caps. Only this sandbox moves; wasmtime's instruction count is gone
// for it from then on (wazero meters wall time only). The guest restarts,
// as it does for any new listener. SB_WASM_WASMTIME_LISTEN_FALLBACK=false
// keeps the old error instead.
func (s *Server) ensureListenEngineLocked(ctx context.Context, sandboxID string) error {
	if s.eng.SupportsListen() {
		return nil
	}
	from := s.engineNameLocked()
	if !listenFallbackEnabled() {
		return fmt.Errorf("HTTP ingress (expose_port) is not supported on the %q WASM engine; use SB_WASM_ENGINE=wazero", from)
	}
	if s.loaded.modulePath == "" {
		return fmt.Errorf("HTTP ingress (expose_port) on the %q WASM engine: no module loaded to serve on wazero", from)
	}
	eng, err := newListenEngine(ctx)
	if err != nil {
		return fmt.Errorf("serve HTTP on wazero instead of %q: %w", from, err)
	}
	if err := eng.LoadModule(ctx, s.loaded.modulePath, wasmengine.LoadOptions{MemoryMB: s.loaded.memoryMB}); err != nil {
		_ = eng.Close(ctx)
		return fmt.Errorf("serve HTTP on wazero instead of %q: %w", from, err)
	}
	s.clearNetworkHook()
	_ = s.eng.Close(ctx)
	s.eng = eng
	s.loaded.name = wasmengine.EngineNameWazero()
	s.loaded.fallbackFrom = from
	slog.Info("wasm worker: sandbox serves HTTP on wazero; its engine cannot pre-open a guest listener",
		"sandbox_id", sandboxID, "configured_engine", from)
	return nil
}

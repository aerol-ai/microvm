package worker

import (
	"context"
	"fmt"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// loadedEngine is the module a per-sandbox worker runs and the engine it
// runs it on.
type loadedEngine struct {
	modulePath string
	memoryMB   int
	// name is the engine eng is; "" before the first load.
	name string
}

// noteLoadedLocked records a load_module that succeeded. The caller holds
// mu and has just loaded p on a fresh engine of the configured kind.
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

// ensureListenEngineLocked makes sure eng can pre-open a guest listener
// before one is asked for. The caller holds mu and has checked eng is set.
func (s *Server) ensureListenEngineLocked(_ context.Context, _ string) error {
	if s.eng.SupportsListen() {
		return nil
	}
	return fmt.Errorf("HTTP ingress (expose_port) is not supported on the %q WASM engine; use SB_WASM_ENGINE=wazero", workerEngineName())
}

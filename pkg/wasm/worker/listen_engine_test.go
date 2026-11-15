package worker

import (
	"errors"
	"testing"
)

func TestLoadedEngineName(t *testing.T) {
	t.Setenv("AEROL_WASM_ENGINE", "")
	s := &Server{}
	if got := s.engineNameLocked(); got != "wazero" {
		t.Fatalf("engine before a load = %q, want wazero", got)
	}
	t.Setenv("AEROL_WASM_ENGINE", "wasmtime")
	s.noteLoadedLocked(loadModulePayload{Path: "/m.wasm", MemoryMB: 64}, nil)
	if s.loaded.modulePath != "/m.wasm" || s.loaded.memoryMB != 64 || s.engineNameLocked() != "wasmtime" {
		t.Fatalf("after a load: %+v name %q", s.loaded, s.engineNameLocked())
	}
	// A failed load forgets the module: the engine holds none.
	s.noteLoadedLocked(loadModulePayload{Path: "/other.wasm"}, errors.New("compile"))
	if s.loaded.modulePath != "" {
		t.Fatalf("after a failed load: %+v", s.loaded)
	}
}

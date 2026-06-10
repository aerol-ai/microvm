package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

func TestWasmPathUnderDir(t *testing.T) {
	tests := []struct {
		root string
		path string
		want bool
	}{
		{"/var/modules", "/var/modules/abc.wasm", true},
		{"/var/modules/", "/var/modules/abc.wasm", true},
		{"/var/modules", "/var/modules/nested/abc.wasm", true},
		{"/var/modules", "/var/other/abc.wasm", false},
		{"/var/modules", "/var/modules/../abc.wasm", false},
		{"", "/abc.wasm", false},
		{"/var/modules", "", false},
	}
	for _, tt := range tests {
		if got := wasmPathUnderDir(tt.root, tt.path); got != tt.want {
			t.Errorf("wasmPathUnderDir(%q, %q) = %v; want %v", tt.root, tt.path, got, tt.want)
		}
	}
}

func TestStartWasmModuleGC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.WasmModuleGCEnabled = true
	svc.cfg.WasmModuleGCInterval = time.Millisecond * 10
	svc.cfg.WasmModuleGCTTL = time.Hour

	svc.StartWasmModuleGC(ctx)
	time.Sleep(time.Millisecond * 30)
}

func TestRunWasmModuleGC(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.WasmModuleGCTTL = 5 * time.Millisecond

	st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID:         "mod-1",
		ModuleRef:  "sha256:abc",
		ModulePath: "/tmp/abc.wasm",
	})

	time.Sleep(10 * time.Millisecond)

	svc.runWasmModuleGC(ctx, time.Now())

	_, err := st.GetWasmModule(ctx, "mod-1")
	if err == nil {
		t.Fatal("expected module to be deleted")
	}
}

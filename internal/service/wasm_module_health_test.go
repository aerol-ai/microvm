package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
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

func TestRunWasmModuleGCWithRuntimeRemovesImages(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.WasmModuleGCTTL = 5 * time.Millisecond

	rt := &recordingRuntime{}
	svc.SetWasmRuntime(rt)

	dir := t.TempDir()
	modPath := filepath.Join(dir, "module.wasm")
	if err := os.WriteFile(modPath, []byte("wasm"), 0o600); err != nil {
		t.Fatalf("write module: %v", err)
	}
	now := time.Now().UTC().Add(-2 * time.Hour)
	if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID:         "mod-rt",
		ModuleRef:  "sha256:rt",
		Status:     "ready",
		ModulePath: modPath,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	svc.runWasmModuleGC(ctx, time.Now().UTC())
	if len(rt.removeImages) != 1 || rt.removeImages[0] != "sha256:rt" {
		t.Fatalf("removeImages = %v, want [sha256:rt]", rt.removeImages)
	}
	if _, err := st.GetWasmModule(ctx, "mod-rt"); err == nil {
		t.Fatal("module should have been deleted")
	}

	svc.cfg.WasmModuleGCTTL = 0
	svc.runWasmModuleGC(ctx, time.Now().UTC())
}

func TestRunWasmModuleGCEdgeBranches(t *testing.T) {
	ctx := context.Background()
	svc := &Service{cfg: config.Config{WasmModuleGCTTL: 0}}

	// TTL <= 0 is a fast no-op.
	svc.runWasmModuleGC(ctx, time.Now().UTC())

	root := t.TempDir()
	nested := filepath.Join(root, "nested", "module.wasm")
	if err := os.MkdirAll(filepath.Dir(nested), 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.WriteFile(nested, []byte("wasm"), 0o600); err != nil {
		t.Fatalf("write nested module: %v", err)
	}
	if !wasmPathUnderDir(root, nested) {
		t.Fatalf("wasmPathUnderDir(%q, %q) = false, want true", root, nested)
	}
	if wasmPathUnderDir(root, filepath.Join(root, "..", "outside.wasm")) {
		t.Fatalf("wasmPathUnderDir should reject path outside root")
	}
}

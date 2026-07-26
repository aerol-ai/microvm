package wasm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestFenceCloneGeneration(t *testing.T) {
	if err := FenceCloneGeneration("", ""); err != nil {
		t.Fatalf("expected no error for empty generations, got %v", err)
	}
	if err := FenceCloneGeneration("gen-1", "gen-1"); err != nil {
		t.Fatalf("expected no error for matching generations, got %v", err)
	}
	err := FenceCloneGeneration("gen-1", "gen-2")
	if err == nil {
		t.Fatal("expected fenced error")
	}
	if !errors.Is(err, models.ErrSnapshotFenced) {
		t.Fatalf("expected ErrSnapshotFenced, got %v", err)
	}
}

func TestSnapshotMediaTypesAndDirExists(t *testing.T) {
	got := SnapshotMediaTypes()
	if got[configFileName] != mediaConfig || got[memoryFileName] != mediaMemory || got[globalsFileName] != mediaGlobals || got[wasiStateFileName] != mediaWASIState {
		t.Fatalf("unexpected media types map: %+v", got)
	}

	dir := t.TempDir()
	if DirExists(dir) {
		t.Fatal("expected DirExists false for fresh temp dir")
	}
	if err := os.WriteFile(filepath.Join(dir, configFileName), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	if !DirExists(dir) {
		t.Fatal("expected DirExists true after writing config.json")
	}
}

func TestZstdCompressEmpty(t *testing.T) {
	out, err := zstdCompress(nil)
	if err != nil {
		t.Fatalf("zstdCompress(nil) failed: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty output for nil input, got %d bytes", len(out))
	}
	out, err = zstdDecompress(nil)
	if err != nil {
		t.Fatalf("zstdDecompress(nil) failed: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty output for nil input, got %d bytes", len(out))
	}
}

func TestWriteSnapshotDirAppliesPortableDefaults(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "mem.snap")
	if err := WriteSnapshotDir(dir, SnapshotCapture{Memory: []byte("memory")}); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}
	got, err := ReadSnapshotDir(dir, "")
	if err != nil {
		t.Fatalf("ReadSnapshotDir: %v", err)
	}
	if got.Config.SchemaVersion != snapshotSchemaVersion || got.Config.Engine != engineWazero {
		t.Fatalf("defaults = %+v", got.Config)
	}
	if got.Config.WASIVersion != wasiPreview1 || got.Config.CapturedAt == "" {
		t.Fatalf("portable metadata defaults = %+v", got.Config)
	}
	if string(got.Globals) != "[]" || string(got.WASIState) != "{}" {
		t.Fatalf("default state = globals:%q wasi:%q", got.Globals, got.WASIState)
	}
}

func TestReadSnapshotDir_ErrorPaths(t *testing.T) {
	base := SnapshotCapture{
		Config: SnapshotConfig{
			SchemaVersion: snapshotSchemaVersion,
			Engine:        engineWazero,
			WASIVersion:   wasiPreview1,
			BaseModule:    SnapshotBaseModule{Digest: "sha256:abc", Size: 1},
			Entrypoint:    "_start",
			Durability:    models.DurabilityPassivatable,
		},
		Memory:    []byte("memory"),
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}

	dir := t.TempDir()
	if err := WriteSnapshotDir(dir, base); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}

	testError := func(name string, mutate func(cfg *SnapshotConfig)) {
		t.Run(name, func(t *testing.T) {
			cfgPath := filepath.Join(dir, configFileName)
			cfgBytes, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatalf("read config: %v", err)
			}
			var cfg SnapshotConfig
			if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
				t.Fatalf("unmarshal config: %v", err)
			}
			mutate(&cfg)
			out, err := json.MarshalIndent(cfg, "", "  ")
			if err != nil {
				t.Fatalf("marshal config: %v", err)
			}
			if err := os.WriteFile(cfgPath, out, 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err = ReadSnapshotDir(dir, engineWazero)
			if err == nil || !errors.Is(err, models.ErrSnapshotCorrupt) {
				t.Fatalf("expected ErrSnapshotCorrupt, got %v", err)
			}
		})
	}

	testError("UnsupportedSchema", func(cfg *SnapshotConfig) { cfg.SchemaVersion = 999 })
	testError("EngineMismatch", func(cfg *SnapshotConfig) { cfg.Engine = "does-not-match" })
	testError("MemoryChecksumMismatch", func(cfg *SnapshotConfig) { cfg.MemoryChecksum = "sha256:deadbeef" })
	testError("WASIStateChecksumMismatch", func(cfg *SnapshotConfig) { cfg.WASIStateChecksum = "sha256:deadbeef" })
	testError("GlobalsCountMismatch", func(cfg *SnapshotConfig) { cfg.GlobalsCount = 999 })
}

func TestCountGlobals_InvalidJSON(t *testing.T) {
	if got := countGlobals([]byte("not-json")); got != 0 {
		t.Fatalf("expected 0 globals for invalid JSON, got %d", got)
	}
}

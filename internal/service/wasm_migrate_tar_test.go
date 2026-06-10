package service

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestWasmCheckpointTarRoundTrip(t *testing.T) {
	src := filepath.Join(t.TempDir(), "mem.snap")
	cap := wasmengine.SnapshotCapture{
		Config: wasmengine.SnapshotConfig{
			SchemaVersion:   1,
			Engine:          wasmengine.EngineNameWazero(),
			EngineVersion:   "test",
			WASIVersion:     "preview1",
			BaseModule:      wasmengine.SnapshotBaseModule{Digest: "sha256:abc", Size: 42},
			Entrypoint:      "_start",
			Durability:      models.DurabilityPassivatable,
			CloneGeneration: "gen-migrate-1",
		},
		Memory:    []byte("linear-memory"),
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}
	if err := wasmengine.WriteSnapshotDir(src, cap); err != nil {
		t.Fatalf("WriteSnapshotDir: %v", err)
	}

	var tarBuf bytes.Buffer
	if err := writeWasmCheckpointTar(&tarBuf, src); err != nil {
		t.Fatalf("writeWasmCheckpointTar: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "mem.snap")
	if err := extractWasmCheckpointTar(bytes.NewReader(tarBuf.Bytes()), dst); err != nil {
		t.Fatalf("extractWasmCheckpointTar: %v", err)
	}
	got, err := wasmengine.ReadSnapshotDir(dst, wasmengine.EngineNameWazero())
	if err != nil {
		t.Fatalf("ReadSnapshotDir: %v", err)
	}
	if got.Config.CloneGeneration != cap.Config.CloneGeneration {
		t.Fatalf("clone_generation = %q, want %q", got.Config.CloneGeneration, cap.Config.CloneGeneration)
	}
	if string(got.Memory) != string(cap.Memory) {
		t.Fatalf("memory = %q, want %q", got.Memory, cap.Memory)
	}
}

func TestWasmCheckpointTarHelperBranches(t *testing.T) {
	t.Run("member helper", func(t *testing.T) {
		if !wasmSnapshotTarMember("config.json") || wasmSnapshotTarMember("bad.json") {
			t.Fatal("wasmSnapshotTarMember helper failed")
		}
	})

	t.Run("missing source dir", func(t *testing.T) {
		if err := writeWasmCheckpointTar(io.Discard, filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("expected error for missing mem.snap dir")
		}
	})

	t.Run("unexpected tar entry", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(&tar.Header{Name: "unexpected.bin", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		_, _ = tw.Write([]byte("oops"))
		_ = tw.Close()
		if err := extractWasmCheckpointTar(bytes.NewReader(buf.Bytes()), filepath.Join(t.TempDir(), "dst")); err == nil {
			t.Fatal("expected unexpected tar entry error")
		}
	})

	t.Run("invalid snapshot contents", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, name := range []string{"config.json", "memory.zstd", "globals.cbor", "wasi-state.cbor"} {
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len("bad")), Typeflag: tar.TypeReg}); err != nil {
				t.Fatalf("write header %s: %v", name, err)
			}
			_, _ = tw.Write([]byte("bad"))
		}
		_ = tw.Close()
		if err := extractWasmCheckpointTar(bytes.NewReader(buf.Bytes()), filepath.Join(t.TempDir(), "dst")); err == nil {
			t.Fatal("expected invalid snapshot error")
		}
	})

	t.Run("missing tar file", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(&tar.Header{Name: "config.json", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		_, _ = tw.Write([]byte("{}{}"))
		_ = tw.Close()
		if err := extractWasmCheckpointTar(bytes.NewReader(buf.Bytes()), filepath.Join(t.TempDir(), "dst")); err == nil {
			t.Fatal("expected missing tar member error")
		}
	})

	t.Run("read tar error", func(t *testing.T) {
		if err := extractWasmCheckpointTar(bytes.NewReader([]byte("not a tar")), filepath.Join(t.TempDir(), "dst")); err == nil {
			t.Fatal("expected tar read error")
		}
	})

	t.Run("write entry errors", func(t *testing.T) {
		dir := t.TempDir()
		filePath := filepath.Join(dir, "regular.txt")
		if err := os.WriteFile(filePath, []byte("x"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		tw := tar.NewWriter(io.Discard)
		if err := writeTarFileEntry(tw, "missing", filepath.Join(dir, "missing")); err == nil {
			t.Fatal("expected stat error")
		}
		if err := writeTarFileEntry(tw, "dir", dir); err == nil {
			t.Fatal("expected non-regular file error")
		}
		if err := writeTarFileEntry(tw, "file", filePath); err != nil {
			t.Fatalf("writeTarFileEntry regular file: %v", err)
		}
	})
}

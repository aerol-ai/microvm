package service

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// mem.snap artifact basenames (§4.8.1).
var wasmSnapshotTarFiles = []string{
	"config.json",
	"memory.zstd",
	"globals.cbor",
	"wasi-state.cbor",
}

func writeWasmCheckpointTar(w io.Writer, memSnapDir string) error {
	if !wasmengine.DirExists(memSnapDir) {
		return fmt.Errorf("mem.snap missing at %s", memSnapDir)
	}
	tw := tar.NewWriter(w)
	defer tw.Close()
	for _, name := range wasmSnapshotTarFiles {
		path := filepath.Join(memSnapDir, name)
		if err := writeTarFileEntry(tw, name, path); err != nil {
			return err
		}
	}
	return nil
}

func extractWasmCheckpointTar(r io.Reader, dstDir string) error {
	parent := filepath.Dir(dstDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".mem.snap-import-*")
	if err != nil {
		return err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }

	tr := tar.NewReader(r)
	seen := map[string]struct{}{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanup()
			return fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(hdr.Name)
		if !wasmSnapshotTarMember(base) {
			cleanup()
			return fmt.Errorf("unexpected tar entry %q", hdr.Name)
		}
		seen[base] = struct{}{}
		outPath := filepath.Join(tmp, base)
		f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			cleanup()
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			_ = f.Close()
			cleanup()
			return err
		}
		if err := f.Close(); err != nil {
			cleanup()
			return err
		}
	}
	for _, name := range wasmSnapshotTarFiles {
		if _, ok := seen[name]; !ok {
			cleanup()
			return fmt.Errorf("mem.snap tar missing %q", name)
		}
	}
	if _, err := wasmengine.ReadSnapshotDir(tmp, wasmengine.EngineNameWazero()); err != nil {
		cleanup()
		return err
	}
	_ = os.RemoveAll(dstDir)
	if err := os.Rename(tmp, dstDir); err != nil {
		cleanup()
		return err
	}
	return nil
}

func wasmSnapshotTarMember(name string) bool {
	name = strings.TrimSpace(name)
	for _, want := range wasmSnapshotTarFiles {
		if name == want {
			return true
		}
	}
	return false
}

func writeTarFileEntry(tw *tar.Writer, name, path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    fi.Size(),
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

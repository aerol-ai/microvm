package firecracker

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A stopped VM moves with its memory: worker A exports its snapshot folder,
// worker B imports it, takes a network slot for it and restores it with
// Start, keeping the snapshot's vsock CID.
func TestSandboxSnapshotMovesToAnotherWorker(t *testing.T) {
	ctx := context.Background()
	a, b := newDriverFixture(t), newDriverFixture(t)
	if _, err := a.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1, OverlaySizeGB: 1},
		"sb-move", "tok", nil); err != nil {
		t.Fatalf("Create on A: %v", err)
	}
	var bundle bytes.Buffer
	if err := a.driver.ExportSandboxSnapshot(ctx, "sb-move", &bundle); !errors.Is(err, errSandboxRunning) {
		t.Fatalf("export of a running VM = %v, want errSandboxRunning", err)
	}
	if err := a.driver.Stop(ctx, "sb-move"); err != nil {
		t.Fatalf("Stop on A: %v", err)
	}
	if err := a.driver.ExportSandboxSnapshot(ctx, "sb-move", &bundle); err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := b.driver.ImportSandboxSnapshot(ctx, "sb-move", bytes.NewReader(bundle.Bytes())); err != nil {
		t.Fatalf("import on B: %v", err)
	}
	if b.pool.alloc == 0 {
		t.Fatal("B gave the sandbox no network slot")
	}
	manifest, err := b.driver.readSandboxSnapshotManifest("sb-move")
	if err != nil || manifest.VsockCID != 3 || !manifest.HasOverlay {
		t.Fatalf("B's manifest = %+v, %v", manifest, err)
	}
	if _, err := b.driver.StartWithIdentity(ctx, "sb-move", "sb-move", "tok"); err != nil {
		t.Fatalf("Start on B from the moved snapshot: %v", err)
	}
	// A second import of a sandbox running on B is refused.
	if err := b.driver.ImportSandboxSnapshot(ctx, "sb-move", bytes.NewReader(bundle.Bytes())); !errors.Is(err, errSandboxRunning) {
		t.Fatalf("import over a running VM = %v", err)
	}
}

// What an import refuses, leaving nothing in place: a stream that is not a
// snapshot, the manifest not first, another sandbox's manifest, a missing
// file, a file a snapshot does not have, a memory file changed in transit.
func TestSandboxSnapshotImportRefuses(t *testing.T) {
	ctx := context.Background()
	a := newDriverFixture(t)
	if _, err := a.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1},
		"sb-src", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := a.driver.Stop(ctx, "sb-src"); err != nil {
		t.Fatal(err)
	}
	dir := a.driver.sandboxSnapshotDir("sb-src")
	file := func(name string) []byte {
		raw, err := os.ReadFile(dir + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	build := func(entries ...[2]any) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range entries {
			name, body := e[0].(string), e[1].([]byte)
			_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg})
			_, _ = tw.Write(body)
		}
		_ = tw.Close()
		return buf.Bytes()
	}
	m, st, mem, root := file(sandboxSnapshotManifestName), file(sandboxSnapshotStateFileName), file(sandboxSnapshotMemoryFileName), file(sandboxSnapshotRootfsFileName)
	changed := append([]byte(nil), mem...)
	changed[0] ^= 1
	for _, tc := range []struct {
		name, id string
		bundle   []byte
		want     string
	}{
		{"not a tar", "sb-src", []byte("not a snapshot"), ""},
		{"manifest not first", "sb-src", build([2]any{sandboxSnapshotStateFileName, st}, [2]any{sandboxSnapshotManifestName, m}), "manifest must come first"},
		{"another sandbox's manifest", "sb-other", build([2]any{sandboxSnapshotManifestName, m}), "belongs to"},
		{"memory missing", "sb-src", build([2]any{sandboxSnapshotManifestName, m}, [2]any{sandboxSnapshotStateFileName, st}, [2]any{sandboxSnapshotRootfsFileName, root}), "missing"},
		{"a stranger's file", "sb-src", build([2]any{sandboxSnapshotManifestName, m}, [2]any{"../../etc/passwd", []byte("x")}), "not part of a sandbox snapshot"},
		{"memory changed", "sb-src", build([2]any{sandboxSnapshotManifestName, m}, [2]any{sandboxSnapshotStateFileName, st}, [2]any{sandboxSnapshotMemoryFileName, changed}, [2]any{sandboxSnapshotRootfsFileName, root}), "integrity"},
	} {
		b := newDriverFixture(t)
		err := b.driver.ImportSandboxSnapshot(ctx, tc.id, bytes.NewReader(tc.bundle))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want it to mention %q", tc.name, err, tc.want)
		}
		if _, err := os.Stat(b.driver.sandboxSnapshotDir(tc.id)); !os.IsNotExist(err) {
			t.Fatalf("%s: a refused import left a snapshot folder", tc.name)
		}
		if b.pool.alloc != 0 {
			t.Fatalf("%s: a refused import took a network slot", tc.name)
		}
	}
}

// A move that does not happen drops what the import put in place.
func TestDropImportedSnapshot(t *testing.T) {
	ctx := context.Background()
	a, b := newDriverFixture(t), newDriverFixture(t)
	if _, err := a.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1}, "sb-drop", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := a.driver.Stop(ctx, "sb-drop"); err != nil {
		t.Fatal(err)
	}
	var bundle bytes.Buffer
	if err := a.driver.ExportSandboxSnapshot(ctx, "sb-drop", &bundle); err != nil {
		t.Fatal(err)
	}
	if err := b.driver.ImportSandboxSnapshot(ctx, "sb-drop", &bundle); err != nil {
		t.Fatal(err)
	}
	if err := b.driver.DropImportedSnapshot(ctx, "sb-drop"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(b.driver.sandboxSnapshotDir("sb-drop")); !os.IsNotExist(err) {
		t.Fatal("the dropped import's folder is still there")
	}
	if b.pool.release == 0 {
		t.Fatal("the dropped import kept its network slot")
	}
	if err := b.driver.DropImportedSnapshot(ctx, "bad id/"); err == nil {
		t.Fatal("a bad id was accepted")
	}
}

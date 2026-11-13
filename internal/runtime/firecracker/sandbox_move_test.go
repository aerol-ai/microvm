package firecracker

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

// writeHoley makes a size-byte file whose only data is at each offset.
func writeHoley(t *testing.T, path string, size int64, data map[int64]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	for off, s := range data {
		if _, err := f.WriteAt([]byte(s), off); err != nil {
			t.Fatal(err)
		}
	}
}

// A file of holes moves as its data only and lands with its holes (F36:
// a VM's 10 GiB disk went whole, and the target's copy was dense).
func TestMoveEntryKeepsHoles(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "disk")
	const size = 64 << 20
	data := map[int64]string{0: "boot", 32 << 20: strings.Repeat("d", 10_000), size - 5: "tail!"}
	writeHoley(t, src, size, data)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tarFile(tw, src, "disk"); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > 1<<20 {
		t.Fatalf("a %d-byte file with %d data bytes sent %d bytes", size, 10_009, buf.Len())
	}
	tr := tar.NewReader(&buf)
	h, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "copy")
	if err := writeMoveEntry(dst, h, tr); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(src)
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, want) {
		t.Fatal("the copy's bytes differ")
	}
	var st syscall.Stat_t
	if err := syscall.Stat(dst, &st); err != nil {
		t.Fatal(err)
	}
	if st.Blocks*512 > 4<<20 {
		t.Fatalf("the copy takes %d bytes on disk for %d bytes of data", st.Blocks*512, 10_009)
	}

	// A dense file moves whole, and its zero blocks become holes.
	dense := filepath.Join(dir, "dense")
	if err := os.WriteFile(dense, append(bytes.Repeat([]byte{0}, 1<<20), "end"...), 0o600); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	tw = tar.NewWriter(&buf)
	if err := tarFile(tw, dense, "dense"); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	tr = tar.NewReader(&buf)
	if h, err = tr.Next(); err != nil {
		t.Fatal(err)
	}
	if err := writeMoveEntry(filepath.Join(dir, "dense-copy"), h, tr); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(filepath.Join(dir, "dense-copy"))
	if len(got) != 1<<20+3 || string(got[len(got)-3:]) != "end" {
		t.Fatalf("dense copy: %d bytes", len(got))
	}
}

func TestMoveEntryRefusesBadRanges(t *testing.T) {
	entry := func(size string, table []byte, data int) (*tar.Header, io.Reader) {
		body := append(append([]byte{}, table...), bytes.Repeat([]byte("x"), data)...)
		return &tar.Header{Name: "disk", Size: int64(len(body)), PAXRecords: map[string]string{sparseSizeKey: size}}, bytes.NewReader(body)
	}
	two := func(a, b, c, d int64) []byte { return sparseTable([]byteRange{{a, b}, {c, d}}) }
	for _, tc := range []struct {
		name  string
		size  string
		table []byte
		data  int
	}{
		{"a size that is not a number", "ten", sparseTable(nil), 0},
		{"a negative size", "-1", sparseTable(nil), 0},
		{"a size past the bound", "1099511627777", sparseTable(nil), 0},
		{"ranges out of order", "100", two(50, 60, 10, 20), 20},
		{"overlapping ranges", "100", two(10, 30, 20, 40), 40},
		{"a range past the end", "100", sparseTable([]byteRange{{90, 110}}), 20},
		{"an empty range", "100", sparseTable([]byteRange{{10, 10}}), 0},
		{"fewer bytes than the ranges", "100", sparseTable([]byteRange{{0, 50}}), 10},
		{"more bytes than the ranges", "100", sparseTable([]byteRange{{0, 5}}), 10},
		{"a table cut short", "100", sparseTable([]byteRange{{0, 5}})[:10], 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, r := entry(tc.size, tc.table, tc.data)
			if err := writeMoveEntry(filepath.Join(t.TempDir(), "disk"), h, r); err == nil {
				t.Fatal("written")
			}
		})
	}
	// An all-hole file: no ranges, its full size.
	h, r := entry("4096", sparseTable(nil), 0)
	p := filepath.Join(t.TempDir(), "holes")
	if err := writeMoveEntry(p, h, r); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Size() != 4096 {
		t.Fatalf("size %d", st.Size())
	}
}

// A name that would leave its folder is refused before any file is made.
func TestInside(t *testing.T) {
	dir := t.TempDir()
	if p, err := inside(dir, "snapshot.memory"); err != nil || p != filepath.Join(dir, "snapshot.memory") {
		t.Fatalf("inside = %q, %v", p, err)
	}
	for _, name := range []string{"../x", "..", ".", "", "a/../../x"} {
		if _, err := inside(dir, name); err == nil {
			t.Errorf("%q was taken as a name inside %s", name, dir)
		}
	}
}

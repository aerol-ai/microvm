package movebundle

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A checkpoint directory goes to another worker whole: the same files, the
// same bytes.
func TestWriteDirReadDir(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	files := map[string]string{"checkpoint.img": "state", "pages.img": strings.Repeat("p", 70_000), "pages_meta.img": "meta"}
	writeFiles(t, src, files)
	var buf bytes.Buffer
	if err := WriteDir(ctx, &buf, src, "sb-1"); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	m, err := ReadDir(ctx, bytes.NewReader(buf.Bytes()), dst, "sb-1", NoBound)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 3 || m.Files[0] != "checkpoint.img" {
		t.Fatalf("manifest %+v", m)
	}
	for name, body := range files {
		got, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil || string(got) != body {
			t.Fatalf("%s: %d bytes, %v", name, len(got), err)
		}
	}
	// Another sandbox's stream does not open as this one.
	if _, err := ReadDir(ctx, bytes.NewReader(buf.Bytes()), t.TempDir(), "sb-2", NoBound); err == nil {
		t.Fatal("a stream for sb-1 was read as sb-2's")
	}
}

func TestWriteDirRefusals(t *testing.T) {
	ctx := context.Background()
	empty := t.TempDir()
	if err := WriteDir(ctx, &bytes.Buffer{}, empty, "sb-1"); err == nil {
		t.Fatal("an empty directory was written")
	}
	sub := t.TempDir()
	if err := os.Mkdir(filepath.Join(sub, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteDir(ctx, &bytes.Buffer{}, sub, "sb-1"); err == nil {
		t.Fatal("a directory inside was written")
	}
	named := t.TempDir()
	writeFiles(t, named, map[string]string{ManifestName: "x"})
	if err := WriteDir(ctx, &bytes.Buffer{}, named, "sb-1"); err == nil {
		t.Fatal("a file named like the manifest was written")
	}
	if err := WriteDir(ctx, &bytes.Buffer{}, filepath.Join(empty, "none"), "sb-1"); err == nil {
		t.Fatal("a missing directory was written")
	}
	full := t.TempDir()
	writeFiles(t, full, map[string]string{"a": "1"})
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := WriteDir(cancelled, &bytes.Buffer{}, full, "sb-1"); err == nil {
		t.Fatal("a cancelled write went on")
	}
}

// stream builds a tar by hand: a manifest (raw) and entries.
func stream(t *testing.T, manifest any, entries ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if manifest != nil {
		raw, _ := json.Marshal(manifest)
		_ = tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: int64(len(raw)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(raw)
	}
	for _, h := range entries {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			_, _ = tw.Write(bytes.Repeat([]byte("x"), int(h.Size)))
		}
	}
	_ = tw.Close()
	return buf.Bytes()
}

func TestReadDirRefusals(t *testing.T) {
	good := Manifest{Version: 1, SandboxID: "sb-1", Files: []string{"a", "b"}}
	reg := func(name string) *tar.Header {
		return &tar.Header{Name: name, Mode: 0o600, Size: 1, Typeflag: tar.TypeReg}
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"nothing", nil},
		{"a file before the manifest", stream(t, nil, reg("a"))},
		{"a manifest that is not JSON", func() []byte {
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			_ = tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
			_, _ = tw.Write([]byte("{"))
			_ = tw.Close()
			return buf.Bytes()
		}()},
		{"another version", stream(t, Manifest{Version: 2, SandboxID: "sb-1", Files: []string{"a"}})},
		{"no files", stream(t, Manifest{Version: 1, SandboxID: "sb-1"})},
		{"a path in a name", stream(t, Manifest{Version: 1, SandboxID: "sb-1", Files: []string{"../a"}})},
		{"a name twice", stream(t, Manifest{Version: 1, SandboxID: "sb-1", Files: []string{"a", "a"}})},
		{"the manifest named", stream(t, Manifest{Version: 1, SandboxID: "sb-1", Files: []string{ManifestName}})},
		{"a file not named", stream(t, good, reg("a"), reg("c"))},
		{"a file twice", stream(t, good, reg("a"), reg("a"))},
		{"a link", stream(t, good, &tar.Header{Name: "a", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})},
		{"a file missing", stream(t, good, reg("a"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadDir(context.Background(), bytes.NewReader(tc.raw), t.TempDir(), "sb-1", NoBound); err == nil {
				t.Fatal("read")
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadDir(cancelled, bytes.NewReader(stream(t, good, reg("a"), reg("b"))), t.TempDir(), "sb-1", NoBound); err == nil {
		t.Fatal("a cancelled read went on")
	}
}

func TestAddFileAndCreateFile(t *testing.T) {
	dir := t.TempDir()
	if err := AddFile(tar.NewWriter(&bytes.Buffer{}), dir, "d"); err == nil {
		t.Fatal("a directory was added")
	}
	if err := AddFile(tar.NewWriter(&bytes.Buffer{}), filepath.Join(dir, "none"), "n"); err == nil {
		t.Fatal("a missing file was added")
	}
	p := filepath.Join(dir, "f")
	if err := CreateFile(p, strings.NewReader("x"), 1); err != nil {
		t.Fatal(err)
	}
	if err := CreateFile(p, strings.NewReader("y"), 1); err == nil {
		t.Fatal("an existing file was overwritten")
	}
	// Exactly size bytes: no more are read, and fewer is an error.
	long := filepath.Join(dir, "long")
	if err := CreateFile(long, strings.NewReader("xyz"), 2); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(long); string(got) != "xy" {
		t.Fatalf("CreateFile wrote %q, want 2 bytes", got)
	}
	if err := CreateFile(filepath.Join(dir, "short"), strings.NewReader("x"), 2); err == nil || !strings.Contains(err.Error(), "ends after 1 of its 2 bytes") {
		t.Fatalf("a short file: %v", err)
	}
}

// The bound counts the bytes ReadDir writes, all files together: a bundle
// at the bound is read whole; one byte past it is refused before the file
// that would pass it is made.
func TestReadDirBound(t *testing.T) {
	good := Manifest{Version: 1, SandboxID: "sb-1", Files: []string{"a", "b"}}
	raw := stream(t, good, &tar.Header{Name: "a", Mode: 0o600, Size: 3, Typeflag: tar.TypeReg},
		&tar.Header{Name: "b", Mode: 0o600, Size: 4, Typeflag: tar.TypeReg})
	if _, err := ReadDir(context.Background(), bytes.NewReader(raw), t.TempDir(), "sb-1", 7); err != nil {
		t.Fatalf("a bundle at the bound: %v", err)
	}
	dir := t.TempDir()
	_, err := ReadDir(context.Background(), bytes.NewReader(raw), dir, "sb-1", 6)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a bundle one byte past the bound: %v, want ErrTooLarge", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "b")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the file past the bound was made")
	}
	for _, bound := range []int64{0, -1} {
		if _, err := ReadDir(context.Background(), bytes.NewReader(raw), t.TempDir(), "sb-1", bound); err == nil {
			t.Fatalf("a bound of %d was taken", bound)
		}
	}
}

// A sparse entry is refused before anything of it is written, whatever
// the bound, and in both of the forms a tar reader expands.
func TestReadDirRefusesSparseEntries(t *testing.T) {
	const realsize = 64 << 20
	for _, tc := range []struct {
		name  string
		bound int64
	}{{"under a bound", 1 << 20}, {"with no bound", NoBound}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			raw := sparseBundle(t, "sb-1", "checkpoint.img", realsize)
			_, err := ReadDir(context.Background(), bytes.NewReader(raw), dir, "sb-1", tc.bound)
			if err == nil || !strings.Contains(err.Error(), "sparse entry") {
				t.Fatalf("a %d-byte stream holding a %d-byte sparse file: %v, want it refused", len(raw), realsize, err)
			}
			if _, err := os.Stat(filepath.Join(dir, "checkpoint.img")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("the sparse entry's file was made")
			}
		})
	}
	for _, h := range []*tar.Header{
		{Typeflag: tar.TypeGNUSparse},
		{Typeflag: tar.TypeReg, PAXRecords: map[string]string{"GNU.sparse.major": "1"}},
		{Typeflag: tar.TypeReg, PAXRecords: map[string]string{"GNU.sparse.size": "1"}},
	} {
		if !sparse(h) {
			t.Errorf("%+v is not seen as sparse", h)
		}
	}
	if sparse(&tar.Header{Typeflag: tar.TypeReg, PAXRecords: map[string]string{"path": "a"}}) {
		t.Error("a plain PAX record is seen as sparse")
	}
}

// sparseBundle is a bundle whose one file is a PAX sparse entry of size
// bytes, all of it a hole: its stream holds a few headers only. Go's tar
// writer does not write sparse entries, so its blocks are built here.
func sparseBundle(t *testing.T, id, name string, size int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	raw, _ := json.Marshal(Manifest{Version: 1, SandboxID: id, Files: []string{name}})
	if err := tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: int64(len(raw)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(raw)
	if err := tw.Flush(); err != nil {
		t.Fatal(err)
	}
	pax := paxRecord("GNU.sparse.major", "1") + paxRecord("GNU.sparse.minor", "0") +
		paxRecord("GNU.sparse.name", name) + paxRecord("GNU.sparse.realsize", fmt.Sprint(size))
	out := append(buf.Bytes(), ustarBlock("PaxHeaders/"+name, tar.TypeXHeader, int64(len(pax)))...)
	out = append(out, padBlock([]byte(pax))...)
	// The data: the sparse map (no data regions), one block.
	out = append(out, ustarBlock("GNUSparseFile.0/"+name, tar.TypeReg, 512)...)
	out = append(out, padBlock([]byte("0\n"))...)
	return append(out, make([]byte, 1024)...)
}

func ustarBlock(name string, typeflag byte, size int64) []byte {
	b := make([]byte, 512)
	copy(b[0:100], name)
	copy(b[100:108], "0000600\x00")
	copy(b[108:116], "0000000\x00")
	copy(b[116:124], "0000000\x00")
	copy(b[124:136], fmt.Sprintf("%011o\x00", size))
	copy(b[136:148], fmt.Sprintf("%011o\x00", 0))
	copy(b[148:156], "        ")
	b[156] = typeflag
	copy(b[257:263], "ustar\x00")
	copy(b[263:265], "00")
	var sum int64
	for _, c := range b {
		sum += int64(c)
	}
	copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

func paxRecord(k, v string) string {
	body := " " + k + "=" + v + "\n"
	n := len(body) + 1
	for len(fmt.Sprint(n))+len(body) != n {
		n = len(fmt.Sprint(n)) + len(body)
	}
	return fmt.Sprint(n) + body
}

func padBlock(b []byte) []byte {
	if r := len(b) % 512; r != 0 {
		b = append(b, make([]byte, 512-r)...)
	}
	return b
}

func TestInside(t *testing.T) {
	dir := t.TempDir()
	if p, err := Inside(dir, "pages.img"); err != nil || p != filepath.Join(dir, "pages.img") {
		t.Fatalf("Inside = %q, %v", p, err)
	}
	for _, name := range []string{"../x", "..", ".", "", "a/../../x"} {
		if _, err := Inside(dir, name); err == nil {
			t.Errorf("%q was taken as a name inside %s", name, dir)
		}
	}
}

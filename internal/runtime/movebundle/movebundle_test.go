package movebundle

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
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
	m, err := ReadDir(ctx, bytes.NewReader(buf.Bytes()), dst, "sb-1")
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
	if _, err := ReadDir(ctx, bytes.NewReader(buf.Bytes()), t.TempDir(), "sb-2"); err == nil {
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
			if _, err := ReadDir(context.Background(), bytes.NewReader(tc.raw), t.TempDir(), "sb-1"); err == nil {
				t.Fatal("read")
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadDir(cancelled, bytes.NewReader(stream(t, good, reg("a"), reg("b"))), t.TempDir(), "sb-1"); err == nil {
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
	if err := CreateFile(p, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if err := CreateFile(p, strings.NewReader("y")); err == nil {
		t.Fatal("an existing file was overwritten")
	}
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

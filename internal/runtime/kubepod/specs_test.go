package kubepod

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestSpecStore(t *testing.T) {
	s, err := newSpecStore(filepath.Join(t.TempDir(), "specs"))
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(s.dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("folder = %v, %v; want 0700", fi, err)
	}
	if _, err := s.get("sb-1"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("get of a missing spec = %v", err)
	}
	if ok, err := s.has("sb-1"); ok || err != nil {
		t.Fatalf("has = %v, %v", ok, err)
	}
	for _, name := range []string{"sb-1", "sb-2"} {
		if err := s.put(&Pod{Metadata: ObjectMeta{Name: name, Annotations: map[string]string{AnnotationSandboxID: name}}}); err != nil {
			t.Fatal(err)
		}
	}
	// Overwrite: the latest spec wins.
	if err := s.put(&Pod{Metadata: ObjectMeta{Name: "sb-1", Annotations: map[string]string{AnnotationSandboxID: "sb-1", "v": "2"}}}); err != nil {
		t.Fatal(err)
	}
	p, err := s.get("sb-1")
	if err != nil || p.Metadata.Annotations["v"] != "2" {
		t.Fatalf("get = %+v, %v", p, err)
	}
	// What list must skip: a leftover temporary file, a folder, other files.
	for _, junk := range []string{".spec-123", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(s.dir, junk), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(s.dir, "dir.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A damaged spec is named, and does not hide the others.
	if err := os.WriteFile(filepath.Join(s.dir, "sb-bad.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	all, bad, err := s.list()
	if err != nil || len(all) != 2 || len(bad) != 1 || bad[0] != "sb-bad" {
		t.Fatalf("list = %d, bad %v, %v; want 2 and sb-bad", len(all), bad, err)
	}
	if err := s.remove("sb-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.remove("sb-1"); err != nil {
		t.Fatalf("second remove = %v, want nil", err)
	}
	if ok, _ := s.has("sb-1"); ok {
		t.Fatal("removed spec still there")
	}
}

func TestSpecStoreErrors(t *testing.T) {
	dir := t.TempDir()
	s, err := newSpecStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A folder in place of a spec file: remove and has cannot treat it as
	// a missing file.
	if err := os.MkdirAll(filepath.Join(dir, "busy.json", "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.remove("busy"); err == nil {
		t.Error("remove of a folder that is not empty: want an error")
	}
	if _, err := s.get("busy"); err == nil {
		t.Error("get of a folder: want an error")
	}
	if err := s.put(&Pod{Metadata: ObjectMeta{Name: "busy"}}); err == nil {
		t.Error("put over a folder: want an error")
	}
	gone := &specStore{dir: filepath.Join(dir, "missing")}
	if _, _, err := gone.list(); err == nil {
		t.Error("list of a missing folder: want an error")
	}
	if err := gone.put(&Pod{Metadata: ObjectMeta{Name: "x"}}); err == nil {
		t.Error("put into a missing folder: want an error")
	}
	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "locked")
		if err := os.Mkdir(locked, 0o700); err != nil {
			t.Fatal(err)
		}
		ls := &specStore{dir: locked}
		if err := ls.put(&Pod{Metadata: ObjectMeta{Name: "x"}}); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
		if _, err := ls.has("x"); err == nil {
			t.Error("has in an unreadable folder: want an error")
		}
	}
}

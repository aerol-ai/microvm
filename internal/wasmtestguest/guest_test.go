package wasmtestguest

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPathBuildsAndCachesTheStdioGuest(t *testing.T) {
	out := Path(t, Stdio)
	if filepath.Base(out) != "wasip1-stdio.wasm" {
		t.Fatalf("output = %s", out)
	}
	first, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	// A second call reuses the binary instead of rebuilding it.
	if again := Path(t, Stdio); again != out {
		t.Fatalf("second path = %s", again)
	}
	second, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if !second.ModTime().Equal(first.ModTime()) {
		t.Fatal("cached guest was rebuilt")
	}
}

func TestOutputName(t *testing.T) {
	for guest, want := range map[string]string{
		HTTP:    "wasip1-http.wasm",
		Stdio:   "wasip1-stdio.wasm",
		"other": "wasip1-other.wasm",
	} {
		if got := OutputName(guest); got != want {
			t.Fatalf("OutputName(%q) = %q, want %q", guest, got, want)
		}
	}
}

// fakeRepo lays out pkg/wasm/testdata/<guest> under a temp root.
func fakeRepo(t *testing.T, guest, source string) string {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, "pkg", "wasm", "testdata", guest)
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if source != "" {
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/guest\n\ngo 1.21\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestBuildRebuildsAStaleBinary(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	root := fakeRepo(t, "aerolmini", "package main\n\nfunc main() {}\n")
	out := filepath.Join(root, "pkg", "wasm", "testdata", OutputName("aerolmini"))
	// A binary older than the source must be replaced.
	if err := os.WriteFile(out, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(out, old, old); err != nil {
		t.Fatal(err)
	}
	got, err := build(root, "aerolmini")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "stale" || len(data) < 8 || string(data[:4]) != "\x00asm" {
		t.Fatalf("stale binary was not rebuilt (%d bytes)", len(data))
	}
}

func TestBuildReportsUnavailableAndCompileErrors(t *testing.T) {
	t.Run("missing source", func(t *testing.T) {
		_, err := build(t.TempDir(), "aerolnone")
		if !errors.Is(err, errUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no go files", func(t *testing.T) {
		root := fakeRepo(t, "aerolempty", "")
		if err := os.Mkdir(filepath.Join(root, "pkg", "wasm", "testdata", "aerolempty", "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := build(root, "aerolempty")
		if !errors.Is(err, errUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("windows", func(t *testing.T) {
		root := fakeRepo(t, "aerolwin", "package main\n")
		old := goos
		goos = "windows"
		t.Cleanup(func() { goos = old })
		if _, err := build(root, "aerolwin"); !errors.Is(err, errUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no toolchain", func(t *testing.T) {
		root := fakeRepo(t, "aerolnogo", "package main\n")
		old := lookPath
		lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
		t.Cleanup(func() { lookPath = old })
		if _, err := build(root, "aerolnogo"); !errors.Is(err, errUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("compile error", func(t *testing.T) {
		if _, err := exec.LookPath("go"); err != nil {
			t.Skip("go toolchain unavailable")
		}
		root := fakeRepo(t, "aerolbroken", "package main\n\nfunc main() { undefined() }\n")
		_, err := build(root, "aerolbroken")
		if err == nil || errors.Is(err, errUnavailable) {
			t.Fatalf("err = %v, want a compile failure", err)
		}
	})
}

func TestRepoRootFindsTheModule(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "pkg", "wasm", "testdata", Stdio)); err != nil {
		t.Fatalf("root %s has no stdio guest: %v", root, err)
	}
	// Outside any module the walk ends with errUnavailable.
	dir := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if _, err := repoRoot(); !errors.Is(err, errUnavailable) && err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestPathSkipsWhenUnavailable(t *testing.T) {
	old := lookPath
	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	t.Cleanup(func() { lookPath = old })
	ran := false
	t.Run("skip", func(t *testing.T) {
		defer func() { ran = true }()
		Path(t, "aerolnone")
		t.Fatal("Path did not skip")
	})
	if !ran {
		t.Fatal("subtest did not run")
	}
}

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallSelf(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src-toolboxd")
	want := []byte("#!toolboxd-binary\x00bytes")
	if err := os.WriteFile(src, want, 0o600); err != nil {
		t.Fatal(err)
	}
	old := selfExecutable
	t.Cleanup(func() { selfExecutable = old })
	selfExecutable = func() (string, error) { return src, nil }

	dest := filepath.Join(dir, "vol", "toolboxd")
	if err := os.Mkdir(filepath.Dir(dest), 0o777); err != nil {
		t.Fatal(err)
	}
	// Twice: an init container that runs again finds its own earlier copy.
	for i := 0; i < 2; i++ {
		if err := installSelf([]string{dest}); err != nil {
			t.Fatalf("installSelf: %v", err)
		}
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("copy = %q, %v; want %q", got, err, want)
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v, want 0755", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(dest))
	if len(entries) != 1 {
		t.Fatalf("folder holds %d files, want only the copy (no temporary file left)", len(entries))
	}
}

func TestInstallSelfRefuses(t *testing.T) {
	dir := t.TempDir()
	old := selfExecutable
	t.Cleanup(func() { selfExecutable = old })

	cases := []struct {
		name string
		args []string
		self func() (string, error)
		want string
	}{
		{"no path", nil, os.Executable, "usage"},
		{"relative path", []string{"toolboxd"}, os.Executable, "usage"},
		{"two paths", []string{"/a", "/b"}, os.Executable, "usage"},
		{"own binary unknown", []string{filepath.Join(dir, "x")}, func() (string, error) { return "", errors.New("no /proc") }, "find own binary"},
		{"own binary unreadable", []string{filepath.Join(dir, "x")}, func() (string, error) { return filepath.Join(dir, "missing"), nil }, "open own binary"},
		{"target folder missing", []string{filepath.Join(dir, "nope", "x")}, os.Executable, "install to"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			selfExecutable = tc.self
			err := installSelf(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("installSelf(%q) = %v, want an error with %q", tc.args, err, tc.want)
			}
		})
	}
}

func TestInstallSelfRenameFails(t *testing.T) {
	dir := t.TempDir()
	// The target is a folder that is not empty: the rename cannot replace it.
	dest := filepath.Join(dir, "taken")
	if err := os.MkdirAll(filepath.Join(dest, "inside"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := installSelf([]string{dest})
	if err == nil || !strings.Contains(err.Error(), "install to") {
		t.Fatalf("installSelf onto a folder = %v, want an error", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("folder holds %d entries, want the temporary file removed", len(entries))
	}
}

// TestMainInstallToSubprocess runs main with --install-to the way a
// pod-mode init container does: the copy is the test binary itself.
func TestMainInstallToSubprocess(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "toolboxd")
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessMainInstallTo")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_INSTALL_TO="+dest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install helper failed: %v: %s", err, out)
	}
	self, err := os.Stat(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	copied, err := os.Stat(dest)
	if err != nil || copied.Size() != self.Size() {
		t.Fatalf("copy = %v, %v; want %d bytes", copied, err, self.Size())
	}

	bad := exec.Command(os.Args[0], "-test.run=TestHelperProcessMainInstallTo")
	bad.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_INSTALL_TO=relative/path")
	out, err := bad.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(out), "usage") {
		t.Fatalf("install to a relative path: %v: %s; want exit 1 with usage", err, out)
	}
}

func TestHelperProcessMainInstallTo(t *testing.T) {
	dest := os.Getenv("GO_WANT_HELPER_PROCESS_INSTALL_TO")
	if dest == "" {
		return
	}
	os.Args = []string{"toolboxd", "--install-to", dest}
	main()
	os.Exit(0)
}

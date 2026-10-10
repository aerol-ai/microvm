package containerd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareSandboxHostFilesRunDirIsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareSandboxHostFiles(path, "sb-1"); err == nil {
		t.Fatal("want error when run dir is a file")
	}
}

func TestPrepareSandboxHostFiles(t *testing.T) {
	dir := t.TempDir()
	hf, err := prepareSandboxHostFiles(dir, "sb-abc")
	if err != nil {
		t.Fatalf("prepareSandboxHostFiles() error = %v", err)
	}
	for _, p := range []string{hf.ResolvConf, hf.Hosts, hf.Hostname} {
		if _, statErr := os.Stat(p); statErr != nil {
			t.Fatalf("expected host file %q: %v", p, statErr)
		}
	}
	name, err := os.ReadFile(hf.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(name)) != "sb-abc" {
		t.Fatalf("hostname = %q, want sb-abc", strings.TrimSpace(string(name)))
	}
}

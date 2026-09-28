//go:build linux

package hostport

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPlatformEnableIPForward(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip_forward")
	prev := ipForwardPath
	ipForwardPath = path
	defer func() { ipForwardPath = prev }()

	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := platformEnableIPForward(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "1\n" {
		t.Fatalf("ip_forward = %q, want 1", b)
	}
	// Already on: no write (a read-only file must not fail it).
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := platformEnableIPForward(); err != nil {
		t.Fatalf("already-on must not write: %v", err)
	}
	ipForwardPath = filepath.Join(t.TempDir(), "missing", "ip_forward")
	if err := platformEnableIPForward(); err == nil {
		t.Fatal("unwritable sysctl: want error")
	}
}

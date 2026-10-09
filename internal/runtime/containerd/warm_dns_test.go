package containerd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
)

// TestParkHostFilesFollowAdoption covers D14: the park slot's resolv.conf is
// renamed to the adopting sandbox (so Destroy removes it), and a slot torn
// down unadopted removes its own.
func TestParkHostFilesFollowAdoption(t *testing.T) {
	run := t.TempDir()
	d := &Driver{cfg: Config{RunDir: run}}
	files, err := prepareSandboxHostFiles(run, "park-1")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(files.ResolvConf); err != nil || len(b) == 0 {
		t.Fatalf("park resolv.conf not generated: %v", err)
	}
	d.adoptParkHostFiles("park-1", "sb-1")
	if _, err := os.Stat(filepath.Join(run, "hosts", "park-1")); !os.IsNotExist(err) {
		t.Fatal("slot files must move on adopt")
	}
	if _, err := os.Stat(filepath.Join(run, "hosts", "sb-1", "resolv.conf")); err != nil {
		t.Fatalf("adopted resolv.conf missing: %v", err)
	}
	if err := d.removeHostFiles("sb-1"); err != nil {
		t.Fatal(err)
	}
	d.adoptParkHostFiles("", "x")
	d.adoptParkHostFiles("same", "same")
	d.adoptParkHostFiles("missing", "sb-2")

	if _, err := prepareSandboxHostFiles(run, "park-2"); err != nil {
		t.Fatal(err)
	}
	_ = d.destroyParked(context.Background(), &containerdpool.ParkedSlot{ID: "park-2"})
	if _, err := os.Stat(filepath.Join(run, "hosts", "park-2")); !os.IsNotExist(err) {
		t.Fatal("an unadopted slot's files must be removed with it")
	}
}

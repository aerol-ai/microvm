package containerd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
)

// TestParkHostFilesAreTheContainers covers D14 and its lifetime: the park
// slot's generated resolv.conf is keyed by the container id, which a parked
// container keeps when a sandbox adopts it, so it stays at the path the
// container's spec mounts. A slot torn down unadopted removes its own, by
// slot id or, from the boot purge, by container id alone.
func TestParkHostFilesAreTheContainers(t *testing.T) {
	run := t.TempDir()
	d := &Driver{cfg: Config{RunDir: run}}
	files, err := prepareSandboxHostFiles(run, "park-1")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(files.ResolvConf); err != nil || len(b) == 0 {
		t.Fatalf("park resolv.conf not generated: %v", err)
	}
	if files.Dir != hostFilesDir(run, "park-1") {
		t.Fatalf("park host files at %s, want the container id's path", files.Dir)
	}

	for _, slot := range []*containerdpool.ParkedSlot{{ID: "park-2"}, {ContainerID: "park-3"}} {
		key := slot.ID + slot.ContainerID
		if _, err := prepareSandboxHostFiles(run, key); err != nil {
			t.Fatal(err)
		}
		_ = d.destroyParked(context.Background(), slot)
		if _, err := os.Stat(filepath.Join(run, "hosts", key)); !os.IsNotExist(err) {
			t.Fatalf("an unadopted slot's files must be removed with it (%+v)", slot)
		}
	}
}

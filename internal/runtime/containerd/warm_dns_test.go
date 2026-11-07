package containerd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
)

// TestParkHostFilesAreTheContainers covers D14 and its lifetime: the park
// slot's generated resolv.conf is keyed by the container id, which a parked
// container keeps when a sandbox adopts it, so it stays at the path the
// container's spec mounts. A slot torn down unadopted removes its own, by
// slot id or, from the boot purge, by container id alone, once the
// container is confirmed gone; a delete that fails keeps them with the
// container that still mounts them.
func TestParkHostFilesAreTheContainers(t *testing.T) {
	run := t.TempDir()
	d := &Driver{cfg: Config{RunDir: run}}
	d.SetClient(NewTestClient("aerolvm", newFakeTransport())) // no such container: gone
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
		if err := d.destroyParked(context.Background(), slot); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(run, "hosts", key)); !os.IsNotExist(err) {
			t.Fatalf("an unadopted slot's files must be removed with it (%+v)", slot)
		}
	}

	stuck := newFakeTransport()
	stuck.loadContainerFn = func(context.Context, string) (cntr.Container, error) { return nil, errors.New("engine busy") }
	d.SetClient(NewTestClient("aerolvm", stuck))
	if _, err := prepareSandboxHostFiles(run, "park-4"); err != nil {
		t.Fatal(err)
	}
	if err := d.destroyParked(context.Background(), &containerdpool.ParkedSlot{ID: "park-4", ContainerID: "park-4"}); err == nil {
		t.Fatal("a failed delete must be reported")
	}
	if _, err := os.Stat(filepath.Join(run, "hosts", "park-4")); err != nil {
		t.Fatalf("a container still there must keep its files: %v", err)
	}
}

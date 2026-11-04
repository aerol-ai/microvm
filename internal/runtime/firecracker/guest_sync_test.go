package firecracker

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Stop asks the guest to flush its filesystems before the pause, so the
// saved rootfs.ext4 holds every write made before Stop. CreateSnapshot
// exports that disk alone, so it needs the flush; Start restores memory and
// does not.

func stoppedFixtureSandbox(t *testing.T, id string) *driverFixture {
	t.Helper()
	f := newDriverFixture(t)
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, id, "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return f
}

// vsockOps lists the ops the driver sent, in order.
func vsockOps(t *testing.T, d *fakeVsockDialer) []string {
	t.Helper()
	var ops []string
	for _, w := range d.snapshotWrites() {
		var msg struct {
			Op string `json:"op"`
		}
		if err := json.Unmarshal(w, &msg); err == nil && msg.Op != "" {
			ops = append(ops, msg.Op)
		}
	}
	return ops
}

func indexOf(ops []string, op string) int {
	for i, o := range ops {
		if o == op {
			return i
		}
	}
	return -1
}

func TestStopFlushesTheGuestBeforeThePause(t *testing.T) {
	f := stoppedFixtureSandbox(t, "sb-sync-ok")
	before := len(vsockOps(t, f.vsock))
	if err := f.driver.Stop(context.Background(), "sb-sync-ok"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	ops := vsockOps(t, f.vsock)[before:]
	syncAt, preAt := indexOf(ops, "sync_fs"), indexOf(ops, "pre_snapshot")
	if syncAt < 0 || preAt < 0 || syncAt > preAt {
		t.Fatalf("ops sent by Stop = %v, want sync_fs before pre_snapshot", ops)
	}
	manifest, err := f.driver.readSandboxSnapshotManifest("sb-sync-ok")
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.GuestSynced {
		t.Fatal("manifest.GuestSynced = false after the guest acked sync_fs")
	}
}

// An agent from before sync_fs answers "unknown op". Stop still saves the
// VM (Start does not need the flush), and records the disk as unflushed.
func TestStopRecordsAnUnflushedDiskWhenTheGuestCannotSync(t *testing.T) {
	f := stoppedFixtureSandbox(t, "sb-sync-old")
	f.vsock.mu.Lock()
	f.vsock.guestRespOk, f.vsock.guestError = false, `unknown op \"sync_fs\"`
	f.vsock.mu.Unlock()
	if err := f.driver.Stop(context.Background(), "sb-sync-old"); err != nil {
		t.Fatalf("Stop with an agent that cannot sync: %v", err)
	}
	manifest, err := f.driver.readSandboxSnapshotManifest("sb-sync-old")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.GuestSynced {
		t.Fatal("manifest.GuestSynced = true although the guest refused sync_fs")
	}
}

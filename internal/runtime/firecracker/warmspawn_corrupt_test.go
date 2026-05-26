package firecracker

// warmspawn_corrupt_test.go is the Phase 6 PR-A warm-spawn-path
// regression: when the snapshot integrity check fails with an
// ErrSnapshotCorrupt-wrapping error, WarmSpawn must call the
// TemplateHealthNotifier with the templateID + reason BEFORE returning
// the error to the caller, and it must still honour the existing
// cleanup contract (process + rundir torn down). Without the notifier
// call the refill loop would re-pick the same corrupt template on every
// tick and spin forever (the lister filters status=ready, and only the
// notifier-driven service-side UPDATE moves the row out of ready).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestWarmSpawn_CorruptSnapshotNotifiesAndCleans is the end-to-end
// runtime-side assertion. It writes real bytes, computes the real
// checksum, then mutates one of the files in place so verify fails
// with a deterministic ErrSnapshotCorrupt wrap. Asserts:
//
//   - notifier received exactly one call with the WarmSpawnRequest's
//     TemplateID + a non-empty reason
//   - WarmSpawn returned an error that wraps ErrSnapshotCorrupt
//   - VMM was shut down + rundir cleaned (the existing cleanup
//     contract still applies on the corruption arm)
//   - LoadSnapshot was NOT called — host-side verification must run
//     before any byte hits firecracker.
func TestWarmSpawn_CorruptSnapshotNotifiesAndCleans(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.SnapshotVerifyOnLoad = true

	notifier := &recordingHealthNotifier{}
	f.driver.SetTemplateHealthNotifier(notifier)

	tplDir := t.TempDir()
	snapMem := filepath.Join(tplDir, "snapshot.memory")
	snapState := filepath.Join(tplDir, "snapshot.state")
	memBytes := []byte("MEM-ORIGINAL")
	stateBytes := []byte("STATE-ORIGINAL")
	if err := os.WriteFile(snapMem, memBytes, 0o600); err != nil {
		t.Fatalf("write snap mem: %v", err)
	}
	if err := os.WriteFile(snapState, stateBytes, 0o600); err != nil {
		t.Fatalf("write snap state: %v", err)
	}
	memSum := sha256.Sum256(memBytes)
	stateSum := sha256.Sum256(stateBytes)
	combined := "sha256:" + hex.EncodeToString(memSum[:]) + "|sha256:" + hex.EncodeToString(stateSum[:])

	// Corrupt the memory file after computing the checksum so
	// verifySnapshotChecksum will produce a real, sentinel-wrapped
	// mismatch error.
	if err := os.WriteFile(snapMem, []byte("MEM-CORRUPTED-DIFFERENT-LENGTH"), 0o600); err != nil {
		t.Fatalf("rewrite mem: %v", err)
	}

	_, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID:             "vmms-warm-corrupt",
		TemplateID:         "tpl-corrupt-warm",
		SnapshotMemoryPath: snapMem,
		SnapshotStatePath:  snapState,
		SnapshotChecksum:   combined,
		VsockCID:           200,
	})
	if err == nil {
		t.Fatal("WarmSpawn returned nil error despite corrupted snapshot")
	}
	if !errors.Is(err, models.ErrSnapshotCorrupt) {
		t.Errorf("WarmSpawn err = %v, want errors.Is(ErrSnapshotCorrupt)", err)
	}

	calls := notifier.snapshot()
	if len(calls) != 1 {
		t.Fatalf("notifier got %d calls, want 1; the refill loop would spin forever without this", len(calls))
	}
	if calls[0].templateID != "tpl-corrupt-warm" {
		t.Errorf("notifier templateID = %q, want %q", calls[0].templateID, "tpl-corrupt-warm")
	}
	if calls[0].reason == "" {
		t.Errorf("notifier reason is empty; service-side snapshot_error column needs the wrapped error message")
	}

	// LoadSnapshot must not have been called — host-side verification
	// runs before any byte hits firecracker. Same contract the cold-load
	// path's TestCreate_SnapshotLoadPath_VerifyMismatchRefusesLoad asserts.
	if f.client.snapshotLoad != nil {
		t.Errorf("LoadSnapshot was called despite corrupted snapshot: %+v", f.client.snapshotLoad)
	}

	// Cleanup contract holds even when corruption short-circuits the
	// spawn sequence. The spawner.go promise to the pool is "no leaked
	// process, no leaked rundir on any error path"; corruption is just
	// another error path.
	if !f.vmm.shutdown {
		t.Error("VMM not shut down after corruption error; pool would leak the process")
	}
	if !f.vmm.cleaned {
		t.Error("rundir not cleaned after corruption error")
	}
}

// TestWarmSpawn_CorruptionNoNotifierStillReturnsError covers the
// production fallback where the notifier was never wired (e.g.
// firecracker enabled but SetTemplateHealthNotifier not called — unit
// tests that exercise warmspawn without the service). The corruption
// signal must still surface to the caller; only the side-effect (mark
// unhealthy + rebuild kick) is silently dropped.
func TestWarmSpawn_CorruptionNoNotifierStillReturnsError(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.SnapshotVerifyOnLoad = true
	// Intentionally no notifier wiring.

	tplDir := t.TempDir()
	snapMem := filepath.Join(tplDir, "snapshot.memory")
	snapState := filepath.Join(tplDir, "snapshot.state")
	if err := os.WriteFile(snapMem, []byte("a"), 0o600); err != nil {
		t.Fatalf("write snap mem: %v", err)
	}
	if err := os.WriteFile(snapState, []byte("b"), 0o600); err != nil {
		t.Fatalf("write snap state: %v", err)
	}

	_, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID:             "vmms-warm-nonotify",
		TemplateID:         "tpl-no-notifier",
		SnapshotMemoryPath: snapMem,
		SnapshotStatePath:  snapState,
		// Deliberately wrong checksum.
		SnapshotChecksum: "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000" +
			"|sha256:" + "0000000000000000000000000000000000000000000000000000000000000000",
		VsockCID: 200,
	})
	if err == nil {
		t.Fatal("WarmSpawn returned nil error despite checksum mismatch with no notifier wired")
	}
	if !errors.Is(err, models.ErrSnapshotCorrupt) {
		t.Errorf("WarmSpawn err = %v, want errors.Is(ErrSnapshotCorrupt)", err)
	}
}

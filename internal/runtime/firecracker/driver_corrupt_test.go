package firecracker

// driver_corrupt_test.go is the Phase 6 PR-A driver-side regression:
// the cold-load path (Driver.Create → configureVMMForLoad →
// verifySnapshotChecksum) must surface checksum mismatches as errors
// that wrap models.ErrSnapshotCorrupt, so the service-side intercept
// in createFirecrackerSandbox can errors.Is against the sentinel.
//
// The existing TestCreate_SnapshotLoadPath_VerifyMismatchRefusesLoad in
// create_test.go covers the behavioural contract (no LoadSnapshot,
// clean teardown); this file pins the typed-error contract that the
// service layer's intercept depends on.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCreate_SnapshotLoadPath_CorruptionWrapsSentinel locks the
// runtime → service contract: a checksum mismatch at cold-load time
// must return an error that satisfies errors.Is(err, ErrSnapshotCorrupt).
// Without the sentinel wrap the service-side intercept silently
// degrades to "raw firecracker error" and the template never moves
// out of ready — the corruption stays latent until the next Create
// re-hits the same mismatch and re-fails the same way.
func TestCreate_SnapshotLoadPath_CorruptionWrapsSentinel(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.SnapshotVerifyOnLoad = true

	tplDir := t.TempDir()
	templateRootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(templateRootfs, []byte("TEMPLATE-ROOTFS"), 0o644); err != nil {
		t.Fatalf("write template rootfs: %v", err)
	}
	snapMem := filepath.Join(tplDir, "snapshot.memory")
	snapState := filepath.Join(tplDir, "snapshot.state")
	if err := os.WriteFile(snapMem, []byte("MEM-BYTES"), 0o600); err != nil {
		t.Fatalf("write snap mem: %v", err)
	}
	if err := os.WriteFile(snapState, []byte("STATE-BYTES"), 0o600); err != nil {
		t.Fatalf("write snap state: %v", err)
	}

	resolver := &fakeTemplateResolver{
		rootfsPath:         templateRootfs,
		hasSnapshot:        true,
		snapshotMemoryPath: snapMem,
		snapshotStatePath:  snapState,
		// Deliberately wrong checksum.
		snapshotChecksum: "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000" +
			"|sha256:" + "0000000000000000000000000000000000000000000000000000000000000000",
		snapshotVsockCID: 200,
	}
	f.driver.SetTemplateResolver(resolver)

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1, TemplateID: "tpl-corrupt-sum",
	}, "sb-corrupt-sum", "tok", nil)
	if err == nil {
		t.Fatal("Create returned nil error despite checksum mismatch")
	}
	if !errors.Is(err, models.ErrSnapshotCorrupt) {
		t.Fatalf("Create err = %v, want errors.Is(ErrSnapshotCorrupt) — service intercept depends on this", err)
	}
	// LoadSnapshot must not have been issued — same belt-and-suspenders
	// the existing VerifyMismatchRefusesLoad test asserts. Repeated
	// here so a regression in only the wrap (not the refusal) lights
	// up *this* test, keeping the failure signal local to the sentinel
	// contract.
	if f.client.snapshotLoad != nil {
		t.Errorf("LoadSnapshot was called despite checksum mismatch: %+v", f.client.snapshotLoad)
	}
}

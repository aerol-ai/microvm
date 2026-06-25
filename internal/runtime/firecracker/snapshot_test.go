package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestSnapshotTemplate_HappyPath is the Phase 3 capture-path regression
// test: SnapshotTemplate must drive the transient VMM through the exact
// REST sequence firecracker requires
// (machine-config -> boot-source -> drive -> nic -> vsock -> InstanceStart ->
// Paused -> CreateSnapshot), then write artifacts whose checksum it
// returns to the service layer. A change to the wire ordering would
// hand firecracker a 400 on real hardware; the fakeClient is permissive
// enough that only the recorded order catches it.
func TestSnapshotTemplate_HappyPath(t *testing.T) {
	f := newDriverFixture(t)

	tplDir := t.TempDir()
	rootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(rootfs, []byte("ROOTFS"), 0o644); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	memOut := filepath.Join(tplDir, "snapshot.memory")
	stateOut := filepath.Join(tplDir, "snapshot.state")

	const guestCID uint32 = 200
	result, err := f.driver.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID:    "tpl-happy",
		RootfsPath:    rootfs,
		OutMemoryPath: memOut,
		OutStatePath:  stateOut,
		GuestCID:      guestCID,
		MemoryMB:      512,
		VCPU:          1,
	})
	if err != nil {
		t.Fatalf("SnapshotTemplate: %v", err)
	}

	// REST wire ordering — firecracker rejects out-of-order requests on
	// real hardware. The fakeClient permits anything, so this is the
	// only place the bug would surface in tests. Pre_snapshot send goes
	// through sendVsockOp, which is best-effort and not on this client.
	want := []string{
		"PutMachineConfig",
		"PutBootSource",
		"PutDrive:" + rootDriveID,
		"PutDrive:" + overlayDriveID,
		"PutNetworkInterface:" + primaryIfaceID,
		"PutVsock",
		"Action:" + firecracker.ActionInstanceStart,
		"PatchVM:" + firecracker.VMStatePaused,
		"CreateSnapshot",
	}
	if len(f.client.restOrder) != len(want) {
		t.Fatalf("REST order length = %d (%v), want %d (%v)",
			len(f.client.restOrder), f.client.restOrder, len(want), want)
	}
	for i, got := range f.client.restOrder {
		if got != want[i] {
			t.Errorf("REST order[%d] = %q, want %q (full: %v)", i, got, want[i], f.client.restOrder)
		}
	}

	// PR-B: rootfs MUST be captured read-only (the snapshot is the
	// immutable base under per-sandbox overlays); overlay placeholder
	// MUST exist (PATCHed away by each clone before Resume).
	if root, ok := f.client.drives[rootDriveID]; !ok || !root.IsReadOnly {
		t.Errorf("rootfs drive read-only = %v, want true (drive=%+v)", root.IsReadOnly, root)
	}
	if ov, ok := f.client.drives[overlayDriveID]; !ok || ov.PathOnHost == "" {
		t.Errorf("overlay drive missing or empty path: %+v", ov)
	} else if _, err := os.Stat(ov.PathOnHost); err != nil {
		t.Errorf("overlay placeholder file %q not on disk: %v", ov.PathOnHost, err)
	}

	// Machine config came from the request, not the per-sandbox shape.
	// TrackDirtyPages MUST be true — without it, future diff snapshots
	// (Phase 4+ optimization) cannot be built on top of this base.
	if f.client.mc == nil || f.client.mc.VcpuCount != 1 || f.client.mc.MemSizeMib != 512 {
		t.Errorf("MachineConfig wrong: %+v", f.client.mc)
	}
	if f.client.mc != nil && !f.client.mc.TrackDirtyPages {
		t.Error("MachineConfig.TrackDirtyPages = false; must be true for future diff snapshots")
	}

	// PutVsock must carry the *template's* CID, not the slot's CID.
	// That value is baked into the snapshot state file, so every clone
	// resumes listening on the same CID — the load path expects this.
	if f.client.vsock == nil || uint32(f.client.vsock.GuestCID) != guestCID {
		t.Errorf("PutVsock.GuestCID = %v, want %d", f.client.vsock, guestCID)
	}

	// CreateSnapshot request shape.
	if f.client.snapshotCreate == nil {
		t.Fatal("CreateSnapshot was not called")
	}
	if f.client.snapshotCreate.SnapshotType != "Full" {
		t.Errorf("SnapshotCreate.SnapshotType = %q, want Full", f.client.snapshotCreate.SnapshotType)
	}
	if f.client.snapshotCreate.SnapshotPath != stateOut {
		t.Errorf("SnapshotCreate.SnapshotPath = %q, want %q", f.client.snapshotCreate.SnapshotPath, stateOut)
	}
	if f.client.snapshotCreate.MemFilePath != memOut {
		t.Errorf("SnapshotCreate.MemFilePath = %q, want %q", f.client.snapshotCreate.MemFilePath, memOut)
	}

	// Artifacts exist on disk and the returned checksum re-hashes them
	// to the same digest. This is the integrity contract the load path
	// relies on — verifySnapshotChecksum re-hashes the same bytes.
	memBytes, err := os.ReadFile(memOut)
	if err != nil {
		t.Fatalf("read memOut: %v", err)
	}
	stateBytes, err := os.ReadFile(stateOut)
	if err != nil {
		t.Fatalf("read stateOut: %v", err)
	}
	memSum := sha256.Sum256(memBytes)
	stateSum := sha256.Sum256(stateBytes)
	want = nil // reuse var
	wantChecksum := "sha256:" + hex.EncodeToString(memSum[:]) + "|sha256:" + hex.EncodeToString(stateSum[:])
	if result.Checksum != wantChecksum {
		t.Errorf("Checksum = %q, want %q", result.Checksum, wantChecksum)
	}
	if result.MemorySizeBytes != int64(len(memBytes)) {
		t.Errorf("MemorySizeBytes = %d, want %d", result.MemorySizeBytes, len(memBytes))
	}
	if result.StateSizeBytes != int64(len(stateBytes)) {
		t.Errorf("StateSizeBytes = %d, want %d", result.StateSizeBytes, len(stateBytes))
	}

	// Cleanup contract: pool released, TAP removed, VMM shut down. The
	// transient VMM does not leak into the driver's per-sandbox maps.
	if f.pool.alloc != 1 || f.pool.release != 1 {
		t.Errorf("pool alloc=%d release=%d, want 1/1", f.pool.alloc, f.pool.release)
	}
	if f.tapHost.ensureCalls != 1 || f.tapHost.removeCalls != 1 {
		t.Errorf("tap ensure=%d remove=%d, want 1/1", f.tapHost.ensureCalls, f.tapHost.removeCalls)
	}
	if !f.vmm.shutdown {
		t.Error("transient VMM should be shut down after snapshot capture")
	}
	if _, ok := f.driver.vmms["tpl-snap-tpl-happy"]; ok {
		t.Error("transient VMM should NOT be registered in driver.vmms")
	}
}

// TestSnapshotTemplate_RejectsReservedCID confirms the driver refuses a
// CID in the reserved range (0-2). Firecracker would reject the
// PutVsock body with a confusing error; the explicit check surfaces a
// clearer message and prevents the allocator from handing back garbage.
func TestSnapshotTemplate_RejectsReservedCID(t *testing.T) {
	f := newDriverFixture(t)
	tplDir := t.TempDir()
	rootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(rootfs, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := f.driver.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID:    "tpl-bad-cid",
		RootfsPath:    rootfs,
		OutMemoryPath: filepath.Join(tplDir, "m"),
		OutStatePath:  filepath.Join(tplDir, "s"),
		GuestCID:      2, // reserved
		MemoryMB:      256,
		VCPU:          1,
	})
	if err == nil {
		t.Fatal("expected reserved-CID rejection")
	}
	if !contains(err.Error(), "reserved") {
		t.Errorf("error should mention reserved CID, got: %v", err)
	}
	if f.pool.alloc != 0 {
		t.Errorf("pool should not have been touched on validation error; alloc=%d", f.pool.alloc)
	}
}

// TestSnapshotTemplate_RequiresPool confirms the seam-precondition
// guard: SnapshotTemplate without SetPool returns
// ErrRuntimeNotImplemented so the operator can pinpoint the missing
// daemon wiring.
func TestSnapshotTemplate_RequiresPool(t *testing.T) {
	d := New(Config{KernelImage: "/anything"}, nil)
	_, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID: "tpl-no-pool", RootfsPath: "/x",
		OutMemoryPath: "/y", OutStatePath: "/z",
		GuestCID: 100, MemoryMB: 256, VCPU: 1,
	})
	if err == nil {
		t.Fatal("expected error without pool")
	}
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Errorf("err should wrap ErrRuntimeNotImplemented, got %v", err)
	}
}

// TestSnapshotTemplate_CreateSnapshotFailureRemovesArtifacts is the
// cleanup contract for the most expensive step: if firecracker rejects
// CreateSnapshot, any partial snapshot.memory / snapshot.state files
// must be removed. Leaving a half-written file is worse than no file —
// the integrity check at load time would reject it correctly, but the
// has_snapshot=true row would (briefly, until the goroutine's failure
// handler fires) advertise it.
func TestSnapshotTemplate_CreateSnapshotFailureRemovesArtifacts(t *testing.T) {
	f := newDriverFixture(t)
	tplDir := t.TempDir()
	rootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(rootfs, []byte("ROOTFS"), 0o644); err != nil {
		t.Fatal(err)
	}
	memOut := filepath.Join(tplDir, "snapshot.memory")
	stateOut := filepath.Join(tplDir, "snapshot.state")
	// Pre-create a partial file at memOut so we can verify it gets
	// removed on the failure path. Firecracker on a real host might
	// have written some bytes before erroring; the cleanup must not
	// depend on the file being absent.
	if err := os.WriteFile(memOut, []byte("PARTIAL-BYTES"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.client.snapshotCreateErr = errors.New("firecracker: snapshot: out of disk")

	_, err := f.driver.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID:    "tpl-snap-fail",
		RootfsPath:    rootfs,
		OutMemoryPath: memOut,
		OutStatePath:  stateOut,
		GuestCID:      150,
		MemoryMB:      256,
		VCPU:          1,
	})
	if err == nil {
		t.Fatal("expected snapshot error")
	}
	if _, statErr := os.Stat(memOut); !os.IsNotExist(statErr) {
		t.Errorf("memOut should have been removed, stat err=%v", statErr)
	}
	if _, statErr := os.Stat(stateOut); !os.IsNotExist(statErr) {
		t.Errorf("stateOut should have been removed, stat err=%v", statErr)
	}
	// Cleanup contract: pool released, TAP removed, VMM shut down.
	if f.pool.release != 1 {
		t.Errorf("pool release = %d, want 1", f.pool.release)
	}
	if f.tapHost.removeCalls != 1 {
		t.Errorf("tap remove = %d, want 1", f.tapHost.removeCalls)
	}
	if !f.vmm.shutdown {
		t.Error("vmm should have been shut down on snapshot failure")
	}
}

// TestSnapshotChecksum_RoundTrip is the unit-level guarantee for the
// integrity primitives the load path leans on. format → parse → verify
// must agree on the bytes; a regression in any of the three breaks
// snapshot-load on every host.
func TestSnapshotChecksum_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	memPath := filepath.Join(dir, "snap.memory")
	statePath := filepath.Join(dir, "snap.state")
	if err := os.WriteFile(memPath, []byte("memory-contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("state-contents"), 0o600); err != nil {
		t.Fatal(err)
	}

	memHex, _, err := hashFile(memPath)
	if err != nil {
		t.Fatalf("hashFile mem: %v", err)
	}
	stateHex, _, err := hashFile(statePath)
	if err != nil {
		t.Fatalf("hashFile state: %v", err)
	}

	combined := formatSnapshotChecksum(memHex, stateHex)
	gotMem, gotState, err := parseSnapshotChecksum(combined)
	if err != nil {
		t.Fatalf("parseSnapshotChecksum: %v", err)
	}
	if gotMem != memHex || gotState != stateHex {
		t.Errorf("parsed (%q, %q), want (%q, %q)", gotMem, gotState, memHex, stateHex)
	}

	// verifySnapshotChecksum on the same files MUST succeed.
	if err := verifySnapshotChecksum(memPath, statePath, combined); err != nil {
		t.Errorf("verify on unchanged files: %v", err)
	}

	// Mutate the memory file and verify MUST fail. A real corruption
	// at load time should surface here, not crash firecracker on an
	// mmap of half-bytes.
	if err := os.WriteFile(memPath, []byte("CORRUPTED"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySnapshotChecksum(memPath, statePath, combined); err == nil {
		t.Error("verify on mutated memory: expected error, got nil")
	} else if !errors.Is(err, models.ErrSnapshotCorrupt) {
		// Phase 6 PR-A: checksum-mismatch errors MUST wrap
		// models.ErrSnapshotCorrupt so the service-layer intercept (and
		// the warmspawn notifier) can errors.Is against it without
		// importing the runtime package. File-I/O errors stay unwrapped
		// — those aren't deterministic corruption signals.
		t.Errorf("verify on mutated memory: err=%v, want errors.Is(ErrSnapshotCorrupt)", err)
	}
}

// TestVerifySnapshotChecksum_StateMismatchIsCorrupt mirrors the memory-
// mismatch arm above for the state file half. Both halves of the
// combined checksum must surface the sentinel — the service-side
// intercept only checks errors.Is(err, ErrSnapshotCorrupt) and would
// silently miss state-file corruption otherwise.
func TestVerifySnapshotChecksum_StateMismatchIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	memPath := filepath.Join(dir, "snap.memory")
	statePath := filepath.Join(dir, "snap.state")
	if err := os.WriteFile(memPath, []byte("memory-contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("state-contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	memHex, _, err := hashFile(memPath)
	if err != nil {
		t.Fatalf("hashFile mem: %v", err)
	}
	stateHex, _, err := hashFile(statePath)
	if err != nil {
		t.Fatalf("hashFile state: %v", err)
	}
	combined := formatSnapshotChecksum(memHex, stateHex)

	if err := os.WriteFile(statePath, []byte("STATE-CORRUPTED"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = verifySnapshotChecksum(memPath, statePath, combined)
	if err == nil {
		t.Fatal("verify on mutated state: expected error, got nil")
	}
	if !errors.Is(err, models.ErrSnapshotCorrupt) {
		t.Errorf("verify on mutated state: err=%v, want errors.Is(ErrSnapshotCorrupt)", err)
	}
}

// TestVerifySnapshotChecksum_MissingFileIsNotCorrupt guards the
// "file-I/O failure stays unwrapped" half of the contract. A missing
// snapshot file is not deterministic corruption — it might mean the
// template was partially deleted, or the on-disk layout changed mid-
// boot. Mapping it to ErrSnapshotCorrupt would auto-rebuild templates
// the operator just `mv`d to a holding directory.
func TestVerifySnapshotChecksum_MissingFileIsNotCorrupt(t *testing.T) {
	dir := t.TempDir()
	memPath := filepath.Join(dir, "snap.memory")
	statePath := filepath.Join(dir, "snap.state")
	if err := os.WriteFile(memPath, []byte("memory-contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("state-contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	memHex, _, err := hashFile(memPath)
	if err != nil {
		t.Fatalf("hashFile mem: %v", err)
	}
	stateHex, _, err := hashFile(statePath)
	if err != nil {
		t.Fatalf("hashFile state: %v", err)
	}
	combined := formatSnapshotChecksum(memHex, stateHex)
	if err := os.Remove(statePath); err != nil {
		t.Fatalf("remove state: %v", err)
	}
	err = verifySnapshotChecksum(memPath, statePath, combined)
	if err == nil {
		t.Fatal("verify on missing state: expected error, got nil")
	}
	if errors.Is(err, models.ErrSnapshotCorrupt) {
		t.Errorf("verify on missing state: err=%v, must NOT wrap ErrSnapshotCorrupt", err)
	}
}

// TestSnapshotChecksum_ParseRejectsMalformed guards the
// self-describing checksum format: an empty string, a missing
// separator, or a missing "sha256:" prefix MUST return an error so
// the caller falls back to "checksum not verifiable" rather than
// silently treating bad input as a match.
func TestSnapshotChecksum_ParseRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"sha256:abc",              // no separator
		"|sha256:abc",             // empty left half
		"sha256:abc|",             // empty right half
		"md5:abc|sha256:def",      // wrong prefix on left
		"sha256:abc|md5:def",      // wrong prefix on right
		"justgarbage|moregarbage", // no prefix on either side
	}
	for _, in := range cases {
		if _, _, err := parseSnapshotChecksum(in); err == nil {
			t.Errorf("parseSnapshotChecksum(%q) = nil error; want rejection", in)
		}
	}
}

package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshot_ExtraCoverage(t *testing.T) {
	// SnapshotTemplate preconditions
	d := &Driver{}
	req := TemplateSnapshotRequest{
		TemplateID:    "test-tpl",
		RootfsPath:    "/tmp/rootfs",
		OutMemoryPath: "/tmp/mem",
		OutStatePath:  "/tmp/state",
		GuestCID:      4,
	}

	// pool nil
	if _, err := d.SnapshotTemplate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "TAP pool not registered") {
		t.Errorf("expected pool nil error, got %v", err)
	}

	d.pool = newFakePool()

	// tapHost nil
	if _, err := d.SnapshotTemplate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "TAP host manager not registered") {
		t.Errorf("expected tapHost nil error, got %v", err)
	}

	d.tapHost = &fakeTapHost{}

	// vsockDial nil
	if _, err := d.SnapshotTemplate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "vsock dialer not registered") {
		t.Errorf("expected vsockDial nil error, got %v", err)
	}

	d.vsockDial = newFakeVsockDialer()

	// KernelImage empty
	if _, err := d.SnapshotTemplate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "KernelImage not configured") {
		t.Errorf("expected KernelImage empty error, got %v", err)
	}

	d.cfg.KernelImage = "/kernel"

	// TemplateID empty
	reqEmptyTpl := req
	reqEmptyTpl.TemplateID = ""
	if _, err := d.SnapshotTemplate(context.Background(), reqEmptyTpl); err == nil || !strings.Contains(err.Error(), "template id is empty") {
		t.Errorf("expected empty template ID error, got %v", err)
	}

	// Paths empty
	reqEmptyPaths := req
	reqEmptyPaths.RootfsPath = ""
	if _, err := d.SnapshotTemplate(context.Background(), reqEmptyPaths); err == nil || !strings.Contains(err.Error(), "rootfs/out paths are required") {
		t.Errorf("expected paths required error, got %v", err)
	}

	// GuestCID < 3
	reqReservedCID := req
	reqReservedCID.GuestCID = 2
	if _, err := d.SnapshotTemplate(context.Background(), reqReservedCID); err == nil || !strings.Contains(err.Error(), "reserved (must be >= 3)") {
		t.Errorf("expected reserved CID error, got %v", err)
	}

	// validateSandboxID fails (e.g. invalid chars in TemplateID)
	reqInvalidTpl := req
	reqInvalidTpl.TemplateID = "test-tpl!"
	if _, err := d.SnapshotTemplate(context.Background(), reqInvalidTpl); err == nil || !strings.Contains(err.Error(), "invalid character") {
		t.Errorf("expected invalid sandbox ID error, got %v", err)
	}

	// allocateSparse errors
	if err := allocateSparse("/nonexistent/dir/file", 100); err == nil || !strings.Contains(err.Error(), "create ") {
		t.Errorf("expected create error, got %v", err)
	}

	// create file for truncate error test
	dir := t.TempDir()
	fpath := filepath.Join(dir, "sparse")
	if err := allocateSparse(fpath, -1); err == nil || !strings.Contains(err.Error(), "truncate ") {
		t.Errorf("expected truncate error, got %v", err)
	}

	// verifySnapshotChecksum errors
	// bad expected format
	if err := verifySnapshotChecksum("mem", "state", "bad"); err == nil || !strings.Contains(err.Error(), "snapshot checksum: ") {
		t.Errorf("expected parse error, got %v", err)
	}

	// mem missing
	expected := formatSnapshotChecksum("bad", "bad")
	if err := verifySnapshotChecksum("/nonexistent/mem", "state", expected); err == nil || !strings.Contains(err.Error(), "hash memory") {
		t.Errorf("expected hash memory error, got %v", err)
	}

	// mem digest mismatch
	memPath := filepath.Join(dir, "mem")
	os.WriteFile(memPath, []byte("mem content"), 0644)
	if err := verifySnapshotChecksum(memPath, "state", expected); err == nil || !strings.Contains(err.Error(), "memory file") {
		t.Errorf("expected memory digest mismatch, got %v", err)
	}

	memDigest, _, _ := hashFile(memPath)
	expected2 := formatSnapshotChecksum(memDigest, "bad")

	// state missing
	if err := verifySnapshotChecksum(memPath, "/nonexistent/state", expected2); err == nil || !strings.Contains(err.Error(), "hash state") {
		t.Errorf("expected hash state error, got %v", err)
	}

	// state digest mismatch
	statePath := filepath.Join(dir, "state")
	os.WriteFile(statePath, []byte("state content"), 0644)
	if err := verifySnapshotChecksum(memPath, statePath, expected2); err == nil || !strings.Contains(err.Error(), "state file") {
		t.Errorf("expected state digest mismatch, got %v", err)
	}
}

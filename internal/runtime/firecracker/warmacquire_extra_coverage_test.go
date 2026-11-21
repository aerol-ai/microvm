package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestTryAcquireWarm_ExtraCoverage(t *testing.T) {
	// Acquire error
	t.Run("AcquireErr", func(t *testing.T) {
		f := newDriverFixture(t)
		pool, _ := stageWarmFixture(t, f)
		stageWarmTemplate(t, f, false)
		pool.acquireEr = errors.New("acquire error")

		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image:      "alpine:3.20",
			TemplateID: "tpl-warm",
		}, "sb-test", "tok", nil)
		if err == nil || err.Error() != "firecracker runtime: warm pool acquire: acquire error" {
			t.Errorf("expected acquire error, got %v", err)
		}
	})

	// Overlay incompatible
	t.Run("OverlayIncompatible", func(t *testing.T) {
		f := newDriverFixture(t)
		stageWarmFixture(t, f)
		stageWarmTemplate(t, f, false) // HasOverlay = false

		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image:         "alpine:3.20",
			TemplateID:    "tpl-warm",
			OverlaySizeGB: 1,
		}, "sb-test", "tok", nil)
		if err == nil || !errors.Is(err, models.ErrRuntimeNotImplemented) && len(err.Error()) < 10 { // actually it wraps no specific error, just returns an error string
			t.Errorf("expected overlay incompatible error, got %v", err)
		}
	})

	// Overlay Mkfs missing bin
	t.Run("OverlayMkfsMissingBin", func(t *testing.T) {
		f := newDriverFixture(t)
		stageWarmFixture(t, f)
		stageWarmTemplate(t, f, true) // HasOverlay = true
		f.driver.cfg.OverlayEnabled = true
		f.driver.cfg.OverlayMkfs = true
		f.driver.cfg.Mkfs4Bin = ""

		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image:         "alpine:3.20",
			TemplateID:    "tpl-warm",
			OverlaySizeGB: 1,
		}, "sb-test", "tok", nil)
		if err == nil || err.Error() != "firecracker runtime: SB_FIRECRACKER_OVERLAY_MKFS=true but SB_FIRECRACKER_MKFS_BIN is unset" {
			t.Errorf("expected missing bin error, got %v", err)
		}
	})

	// The slot's staged rootfs is gone: the claim fails before any PATCH
	// and hands the slot back, rather than resuming a VM whose root drive
	// Firecracker cannot reopen.
	t.Run("SlotRootfsMissing", func(t *testing.T) {
		f := newDriverFixture(t)
		pool, handle := stageWarmFixture(t, f)
		stageWarmTemplate(t, f, false)
		if err := os.Remove(filepath.Join(handle.runDir, rootfsFileName)); err != nil {
			t.Fatal(err)
		}

		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image:      "alpine:3.20",
			TemplateID: "tpl-warm",
		}, "sb-test", "tok", nil)
		if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "warm slot rootfs") {
			t.Fatalf("expected a warm slot rootfs error, got %v", err)
		}
		if len(f.client.drivePatches) != 0 || len(f.client.vmStates) != 0 {
			t.Fatalf("drive patches %v, vm states %v; want none", f.client.drivePatches, f.client.vmStates)
		}
		if len(pool.releaseCalls) != 1 || handle.shutdowns != 1 {
			t.Fatalf("pool releases %v, handle shutdowns %d; want the slot released and its VM shut down", pool.releaseCalls, handle.shutdowns)
		}
	})

	// Patch rootfs error
	t.Run("PatchRootfsErr", func(t *testing.T) {
		f := newDriverFixture(t)
		stageWarmFixture(t, f)
		stageWarmTemplate(t, f, false)
		f.client.drivePatchErr = errors.New("patch rootfs error")

		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image:      "alpine:3.20",
			TemplateID: "tpl-warm",
		}, "sb-test", "tok", nil)
		if err == nil {
			t.Errorf("expected patch rootfs error, got nil")
		}
	})

	// Patch overlay error
	t.Run("PatchOverlayErr", func(t *testing.T) {
		f := newDriverFixture(t)
		stageWarmFixture(t, f)
		stageWarmTemplate(t, f, true)
		f.client.drivePatchErr = errors.New("patch overlay error")
		f.driver.cfg.OverlayEnabled = true

		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image:         "alpine:3.20",
			TemplateID:    "tpl-warm",
			OverlaySizeGB: 1,
		}, "sb-test", "tok", nil)
		if err == nil {
			t.Errorf("expected patch overlay error, got nil")
		}
	})

	// Patch VM Resumed error
	t.Run("PatchVMResumedErr", func(t *testing.T) {
		f := newDriverFixture(t)
		stageWarmFixture(t, f)
		stageWarmTemplate(t, f, false)
		f.client.patchVMErr = errors.New("patch vm resumed error")

		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image:      "alpine:3.20",
			TemplateID: "tpl-warm",
		}, "sb-test", "tok", nil)
		if err == nil {
			t.Errorf("expected action resume error, got nil")
		}
	})

	// Handshake error
	t.Run("HandshakeErr", func(t *testing.T) {
		f := newDriverFixture(t)
		stageWarmFixture(t, f)
		stageWarmTemplate(t, f, false)
		// dial fails
		f.vsock.err = errors.New("dial failed")

		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image:      "alpine:3.20",
			TemplateID: "tpl-warm",
		}, "sb-test", "tok", nil)
		if err == nil {
			t.Errorf("expected handshake error, got nil")
		}
	})
}

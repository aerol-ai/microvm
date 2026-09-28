package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestTryAcquireWarm_OverlayMismatchAndAcquireError(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.SetWarmPool(&fakeWarmPool{})
	req := models.CreateSandboxRequest{TemplateID: "tpl", OverlaySizeGB: 1}
	snap := &TemplateResolution{HasSnapshot: true, HasOverlay: false}
	if _, hit, err := f.driver.tryAcquireWarm(context.Background(), req, "sb", snap, &TapSlot{}, ""); err == nil || hit {
		t.Fatalf("overlay mismatch: hit=%v err=%v", hit, err)
	}

	pool := &fakeWarmPool{acquireEr: errors.New("acquire failed")}
	f.driver.SetWarmPool(pool)
	if _, hit, err := f.driver.tryAcquireWarm(context.Background(), models.CreateSandboxRequest{TemplateID: "tpl"}, "sb", &TemplateResolution{HasSnapshot: true}, &TapSlot{}, ""); err == nil || hit {
		t.Fatalf("acquire error: hit=%v err=%v", hit, err)
	}
}

type nilTransferPool struct {
	*fakePool
}

func (p *nilTransferPool) Transfer(context.Context, string, string, time.Time) (*TapSlot, error) {
	return nil, nil
}

func TestTryAcquireWarm_TransferNilSlotRollback(t *testing.T) {
	f := newDriverFixture(t)
	pool, handle := stageWarmFixture(t, f)
	stageWarmTemplate(t, f, false)
	f.driver.SetPool(&nilTransferPool{fakePool: f.pool})
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-warm",
	}, "sb-transfer-nil", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "warm tap transfer") {
		t.Fatalf("transfer nil: got %v", err)
	}
	if handle.shutdowns == 0 {
		t.Fatal("expected warm handle shutdown on rollback")
	}
	_ = pool
}

func TestTryAcquireWarm_OverlayMkfsSuccess(t *testing.T) {
	f := newDriverFixture(t)
	stageWarmFixture(t, f)
	stageWarmTemplate(t, f, true)
	mkfs := filepath.Join(t.TempDir(), "mkfs.ext4")
	if err := os.WriteFile(mkfs, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.driver.cfg.OverlayMkfs = true
	f.driver.cfg.Mkfs4Bin = mkfs
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-warm", OverlaySizeGB: 1,
	}, "sb-warm-mkfs", "tok", nil); err != nil {
		t.Fatalf("warm mkfs create: %v", err)
	}
}

package firecracker

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCreate_WaitSocketAndOverlayMkfsMissingBin(t *testing.T) {
	f := newDriverFixture(t)
	f.vmm.waitErr = os.ErrDeadlineExceeded
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-wait-sock", "tok", nil); err == nil || !strings.Contains(err.Error(), "wait api socket") {
		t.Fatalf("wait socket: got %v", err)
	}

	f.vmm.waitErr = nil
	f.driver.cfg.OverlayMkfs = true
	f.driver.cfg.Mkfs4Bin = ""
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, OverlaySizeGB: 1,
	}, "sb-mkfs-missing", "tok", nil); err == nil || !strings.Contains(err.Error(), "SB_FIRECRACKER_MKFS_BIN is unset") {
		t.Fatalf("mkfs missing bin: got %v", err)
	}
}

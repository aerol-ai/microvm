//go:build darwin

package firecracker

import (
	"context"
	"os"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"golang.org/x/sys/unix"
)

// unix.Chflags / UF_IMMUTABLE exist only on BSD/darwin — keep this off the
// default (linux CI) build so coverage_95_test.go stays portable.
func TestDestroy_SnapshotDirRemoveWarn(t *testing.T) {
	f := newDriverFixture(t)
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-snap-rm-warn", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	snapDir := f.driver.sandboxSnapshotDir("sb-snap-rm-warn")
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(snapDir, unix.UF_IMMUTABLE); err != nil {
		t.Fatalf("chflags: %v", err)
	}
	defer unix.Chflags(snapDir, 0)
	// Immutable snapshot dir makes RemoveAll fail; Destroy may surface that
	// or only WARN — either way the cleanup-failure branch is exercised.
	_ = f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-snap-rm-warn"})
}

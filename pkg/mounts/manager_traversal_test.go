package mounts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// A sandbox ID is a path component for every host dir and bind MountAll creates.
// A '..' id (reachable via the X-Cluster-Create-ID forward header) must be
// rejected before any filesystem side effect, so it can never escape rootDir
// via MkdirAll, the bind source, or the rollback RemoveAll.
func TestMountAllRejectsTraversalSandboxID(t *testing.T) {
	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeS3: envKernelAdapter{},
	})

	// A canary directory a sibling of rootDir, standing in for anything on the
	// host the traversal could reach. It must survive the rejected mount.
	canary := filepath.Join(filepath.Dir(m.rootDir), "canary")
	if err := os.MkdirAll(canary, 0o700); err != nil {
		t.Fatal(err)
	}

	mounts := []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://b", Target: "/data"}}
	for _, id := range []string{"../canary", "../../etc", "sb/../..", ".."} {
		t.Run(id, func(t *testing.T) {
			_, err := m.MountAll(context.Background(), id, mounts)
			if err == nil {
				t.Fatalf("MountAll(%q) = nil error, want rejection", id)
			}
			if !strings.Contains(err.Error(), "invalid sandbox ID") {
				t.Fatalf("error = %v, want invalid-sandbox-ID rejection", err)
			}
		})
	}

	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("canary dir disturbed by a rejected mount: %v", err)
	}
}

// A well-formed id still mounts, proving the guard doesn't break the happy path.
func TestMountAllAcceptsGeneratedID(t *testing.T) {
	oldProbe := waitForMountProbe
	waitForMountProbe = func(string, time.Duration) error { return nil }
	t.Cleanup(func() { waitForMountProbe = oldProbe })

	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeS3: envKernelAdapter{},
	})
	binds, err := m.MountAll(context.Background(), "sb-0123456789abcdef",
		[]models.MountSpec{{Type: models.MountTypeS3, Source: "s3://b", Target: "/data"}})
	if err != nil {
		t.Fatalf("MountAll(valid id) = %v", err)
	}
	if len(binds) != 1 {
		t.Fatalf("binds = %d, want 1", len(binds))
	}
}

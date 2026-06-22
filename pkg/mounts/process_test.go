package mounts

import (
	"context"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// shFailAdapter mimics a FUSE mount tool (mount-s3, rclone) that prints a
// diagnostic to stderr and exits non-zero — the real-world "bad creds / wrong
// region / unreachable endpoint" case. The mount never becomes ready, so the
// readiness probe times out.
type shFailAdapter struct{}

func (shFailAdapter) Build(_ string, _ int, _ models.MountSpec, _, _ string) (adapters.Plan, error) {
	return adapters.Plan{
		Argv:          []string{"sh", "-c", "echo 'mount-s3 fatal: bucket unreachable' >&2; exit 2"},
		IsKernelMount: false,
	}, nil
}

// TestMountWaitErrorSurfacesToolOutput is the regression guard for
// cluster-hetero UC-81..84: a failing S3 mount produced only a bare "timed out
// waiting for mount" because the FUSE process's stderr was discarded. The
// mount-tool output and process-liveness hint must now appear in the error so
// the failure is diagnosable.
func TestMountWaitErrorSurfacesToolOutput(t *testing.T) {
	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeS3: shFailAdapter{},
	})

	_, err := m.MountAll(context.Background(), "sb-s3-fail", []models.MountSpec{
		{Type: models.MountTypeS3, Source: "s3://bucket", Target: "/data"},
	})
	if err == nil {
		t.Fatal("expected MountAll to fail")
	}
	msg := err.Error()
	// Backward-compatible: the original timeout phrasing is still present so the
	// integration assertion ("timed out waiting for mount") keeps matching.
	if !strings.Contains(msg, "timed out waiting for mount") {
		t.Errorf("error missing timeout phrase: %q", msg)
	}
	// New diagnostic: the tool's captured stderr line is surfaced so the
	// failure reason (bad bucket/creds/region) is visible instead of discarded.
	if !strings.Contains(msg, "mount-s3 fatal: bucket unreachable") {
		t.Errorf("error missing captured tool output: %q", msg)
	}
}

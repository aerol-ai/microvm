package mounts

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// shFailAdapter mimics a FUSE mount tool (mount-s3, rclone) that prints a
// diagnostic to stderr and exits non-zero — the real-world "bad creds / wrong
// region / unreachable endpoint" case. The mount never becomes ready, and the
// readiness wait ends as soon as the tool exits rather than at the timeout.
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
// mount-tool output and its exit status must now appear in the error so the
// failure is diagnosable.
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
	// The tool exited, so the error says that and how, instead of waiting out
	// the timeout and calling it one.
	if !errors.Is(err, errMountToolExited) || !strings.Contains(msg, "exit status 2") {
		t.Errorf("error missing the tool's exit: %q", msg)
	}
	// New diagnostic: the tool's captured stderr line is surfaced so the
	// failure reason (bad bucket/creds/region) is visible instead of discarded.
	if !strings.Contains(msg, "mount-s3 fatal: bucket unreachable") {
		t.Errorf("error missing captured tool output: %q", msg)
	}
}

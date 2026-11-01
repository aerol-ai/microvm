package mounts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

type kernelArgvAdapter []string

func (a kernelArgvAdapter) Build(string, int, models.MountSpec, string, string) (adapters.Plan, error) {
	return adapters.Plan{Argv: a, IsKernelMount: true}, nil
}

// A mount tool that is not installed is the node's configuration, so it
// carries ErrMountToolUnavailable and names the tool. A tool that is there
// and fails (bad bucket, bad credentials, bad options) is not: that stays the
// caller's problem.
func TestMountAllToolUnavailable(t *testing.T) {
	cases := []struct {
		name        string
		adapter     adapters.Adapter
		unavailable bool
		wantInMsg   string
	}{
		{"FUSE tool not on PATH", argvAdapter{"aerolvm-no-such-mount-tool", "--foreground"}, true, `exec: "aerolvm-no-such-mount-tool": executable file not found in $PATH`},
		{"FUSE tool at a missing absolute path", argvAdapter{"/nonexistent/aerolvm/mount-s3"}, true, "/nonexistent/aerolvm/mount-s3"},
		{"kernel mount program not on PATH", kernelArgvAdapter{"aerolvm-no-such-mount"}, true, `exec: "aerolvm-no-such-mount": executable file not found in $PATH`},
		{"FUSE tool runs and fails", argvAdapter{"sh", "-c", "echo 'bucket does not exist' >&2; exit 2"}, false, "bucket does not exist"},
		{"kernel mount runs and fails", kernelArgvAdapter{"sh", "-c", "echo 'bad option' >&2; exit 32"}, false, "bad option"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeS3: tc.adapter})
			_, err := m.MountAll(context.Background(), "sb-tool", s3Spec)
			if err == nil {
				t.Fatal("MountAll succeeded")
			}
			if got := errors.Is(err, ErrMountToolUnavailable); got != tc.unavailable {
				t.Fatalf("errors.Is(ErrMountToolUnavailable) = %v, want %v; err = %v", got, tc.unavailable, err)
			}
			if !strings.Contains(err.Error(), tc.wantInMsg) {
				t.Fatalf("err = %q, want it to contain %q", err, tc.wantInMsg)
			}
			if _, statErr := os.Stat(filepath.Join(m.rootDir, "sb-tool")); !os.IsNotExist(statErr) {
				t.Fatalf("failed mount left its directory behind: %v", statErr)
			}
		})
	}
}

// The local-mode failure on main f34b607e, replayed: the real S3 adapter on a
// node without mount-s3. Before, this error fell to the API's catch-all 400.
func TestMountAllS3WithoutMountS3(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	m := newTestManager(t, adapters.Adapters())
	_, err := m.MountAll(context.Background(), "sb-local-mode", []models.MountSpec{
		{Type: models.MountTypeS3, Source: "s3://bucket", Target: "/data"},
	})
	if !errors.Is(err, ErrMountToolUnavailable) {
		t.Fatalf("err = %v, want ErrMountToolUnavailable", err)
	}
	want := `mount 0 (s3): spawn mount tool: mount tool is not installed on this node: mount-s3: exec: "mount-s3": executable file not found in $PATH`
	if err.Error() != want {
		t.Fatalf("err = %q\nwant  %q", err, want)
	}
}

func TestToolStartErrorLeavesOtherFailuresAlone(t *testing.T) {
	other := errors.New("fork/exec mount-s3: permission denied")
	if got := toolStartError("mount-s3", other); got != other {
		t.Fatalf("toolStartError rewrapped an unrelated start failure: %v", got)
	}
}

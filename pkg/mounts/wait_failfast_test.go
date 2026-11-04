package mounts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

func TestWaitForMount(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	cases := []struct {
		name    string
		path    func(t *testing.T) string
		exited  <-chan struct{}
		timeout time.Duration
		wantErr error  // matched with errors.Is
		wantMsg string // matched as a substring, for the timeout
		maxWait time.Duration
	}{
		{
			name:    "fails fast when the tool has exited",
			path:    func(t *testing.T) string { return t.TempDir() },
			exited:  closed,
			timeout: 30 * time.Second,
			wantErr: errMountToolExited,
			maxWait: 2 * time.Second,
		},
		{
			name: "fails fast when the path is removed mid-wait",
			path: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "0")
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
				time.AfterFunc(300*time.Millisecond, func() { _ = os.Remove(p) })
				return p
			},
			timeout: 30 * time.Second,
			wantErr: errMountPathRemoved,
			maxWait: 2 * time.Second,
		},
		{
			name:    "times out for a live but slow tool",
			path:    func(t *testing.T) string { return t.TempDir() },
			timeout: 300 * time.Millisecond,
			wantMsg: "timed out waiting for mount at",
			maxWait: 2 * time.Second,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path(t)
			start := time.Now()
			err := waitForMount(path, tc.timeout, tc.exited)
			elapsed := time.Since(start)
			if err == nil {
				t.Fatal("waitForMount = nil, want an error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("err = %v, want %q", err, tc.wantMsg)
			}
			if elapsed > tc.maxWait {
				t.Fatalf("waited %v, want under %v", elapsed, tc.maxWait)
			}
			if tc.wantMsg != "" && elapsed < tc.timeout {
				t.Fatalf("timed out after %v, before the %v timeout", elapsed, tc.timeout)
			}
		})
	}

	t.Run("returns once the path is a mount point", func(t *testing.T) {
		if devOf("/dev") == devOf("/") {
			t.Skip("/dev is not a separate mount here")
		}
		if err := waitForMount("/dev", time.Second, nil); err != nil {
			t.Fatalf("waitForMount(/dev) = %v", err)
		}
	})
}

type argvAdapter []string

func (a argvAdapter) Build(string, int, models.MountSpec, string, string) (adapters.Plan, error) {
	return adapters.Plan{Argv: a}, nil
}

// removedUnderToolAdapter starts a live tool and removes the sandbox directory
// 300ms later. Build runs after MountAll has created the directory, so the
// removal can never land before it.
type removedUnderToolAdapter struct{}

func (removedUnderToolAdapter) Build(_ string, _ int, _ models.MountSpec, hostTarget, _ string) (adapters.Plan, error) {
	time.AfterFunc(300*time.Millisecond, func() { _ = os.RemoveAll(filepath.Dir(hostTarget)) })
	return adapters.Plan{Argv: []string{"sleep", "30"}}, nil
}

// End to end through MountAll with the real readiness wait: a tool that dies,
// or a directory that disappears, fails the create in well under the 10s
// timeout, and the error says which.
func TestMountAllFailsFast(t *testing.T) {
	cases := []struct {
		name     string
		adapter  adapters.Adapter
		wantErr  error
		wantMsgs []string
	}{
		{
			name:     "tool exits non-zero",
			adapter:  argvAdapter{"sh", "-c", "echo 'mount-s3 fatal: bucket unreachable' >&2; exit 2"},
			wantErr:  errMountToolExited,
			wantMsgs: []string{"exit status 2", "mount tool output: mount-s3 fatal: bucket unreachable"},
		},
		{
			name:     "tool is killed",
			adapter:  argvAdapter{"sh", "-c", "kill -9 $$"},
			wantErr:  errMountToolExited,
			wantMsgs: []string{"signal: killed", "mount tool produced no output"},
		},
		{
			name:    "directory removed under a live tool",
			adapter: removedUnderToolAdapter{},
			wantErr: errMountPathRemoved,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeS3: tc.adapter})
			m.waitTimeout = 10 * time.Second
			start := time.Now()
			_, err := m.MountAll(context.Background(), "sb-fail-fast", s3Spec)
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Fatalf("MountAll took %v; it should not wait out the timeout", elapsed)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			for _, want := range tc.wantMsgs {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err = %q, missing %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "timed out") {
				t.Errorf("err = %q reads as a timeout", err)
			}
		})
	}
}

func TestMountWaitError(t *testing.T) {
	exitedWith := func(err error) *procExit {
		e := &procExit{done: make(chan struct{}), err: err}
		close(e.done)
		return e
	}
	running := &procExit{done: make(chan struct{})}
	withOutput := &capturedOutput{}
	_, _ = withOutput.Write([]byte("mount-s3 INFO starting\n"))
	timeout := errors.New("timed out waiting for mount at /m/sb/0")

	cases := []struct {
		name    string
		waitErr error
		exit    *procExit
		out     *capturedOutput
		want    string
	}{
		{"live tool, timeout, output", timeout, running, withOutput,
			"timed out waiting for mount at /m/sb/0 (mount tool output: mount-s3 INFO starting)"},
		{"live tool, timeout, silent", timeout, running, &capturedOutput{},
			"timed out waiting for mount at /m/sb/0 (mount tool produced no output)"},
		{"tool exited cleanly", errMountToolExited, exitedWith(nil), &capturedOutput{},
			"mount tool exited before the mount was ready: exit status 0 (mount tool produced no output)"},
		{"path removed, tool exited too", errMountPathRemoved, exitedWith(errors.New("signal: killed")), withOutput,
			"mount path was removed while waiting for the mount (mount tool exited: signal: killed) (mount tool output: mount-s3 INFO starting)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := mountWaitError(tc.waitErr, tc.exit, tc.out)
			if err.Error() != tc.want {
				t.Fatalf("got  %q\nwant %q", err, tc.want)
			}
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("%v does not wrap %v", err, tc.waitErr)
			}
		})
	}
}

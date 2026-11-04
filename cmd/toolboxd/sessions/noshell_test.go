package sessions

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeImage stands in an image whose PATH holds onPath and whose /bin/sh
// exists or not, for the rest of the test.
func fakeImage(t *testing.T, onPath map[string]string, binSh bool) {
	t.Helper()
	oldLook, oldStat := lookPath, statPath
	t.Cleanup(func() { lookPath, statPath = oldLook, oldStat })
	lookPath = func(name string) (string, error) {
		if p, ok := onPath[name]; ok {
			return p, nil
		}
		return "", exec.ErrNotFound
	}
	statPath = func(name string) (os.FileInfo, error) {
		if name == "/bin/sh" && binSh {
			return os.Stat(os.Args[0]) // any file will do
		}
		return nil, fs.ErrNotExist
	}
}

func TestDetectShellPrefersBashThenSh(t *testing.T) {
	for _, tc := range []struct {
		name   string
		onPath map[string]string
		binSh  bool
		want   string
	}{
		{"bash and sh", map[string]string{"bash": "/usr/bin/bash", "sh": "/usr/bin/sh"}, true, "/usr/bin/bash"},
		{"sh only (alpine)", map[string]string{"sh": "/bin/busybox-sh"}, true, "/bin/busybox-sh"},
		{"PATH misses it", nil, true, "/bin/sh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeImage(t, tc.onPath, tc.binSh)
			if got, err := detectShell(); err != nil || got != tc.want {
				t.Fatalf("detectShell = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// An image without a shell (distroless) is refused up front with a reason a
// person can act on, not "fork/exec /bin/sh: no such file or directory".
func TestNoShellImageIsRefusedPlainly(t *testing.T) {
	fakeImage(t, nil, false)
	for _, req := range []models.CreateSessionRequest{
		{},                     // a terminal: aerolvm shell, SSH
		{PTY: true, Name: "x"}, // the same, named
		{Command: "echo hi"},   // a command string needs sh -c
	} {
		if argv, err := buildArgv(req); !errors.Is(err, ErrNoShell) {
			t.Fatalf("buildArgv(%+v) = %v, %v; want ErrNoShell", req, argv, err)
		}
	}
	// An explicit argv names its own program, so no shell is needed.
	if argv, err := buildArgv(models.CreateSessionRequest{Argv: []string{"/app/server"}}); err != nil || argv[0] != "/app/server" {
		t.Fatalf("buildArgv(argv) = %v, %v", argv, err)
	}

	mgr := newTestManager(t)
	if _, err := mgr.Create(context.Background(), models.CreateSessionRequest{PTY: true}); !errors.Is(err, ErrNoShell) {
		t.Fatalf("Create in an image with no shell = %v, want ErrNoShell", err)
	}
	if n := len(mgr.List()); n != 0 {
		t.Fatalf("a refused session was kept: %d sessions", n)
	}
}

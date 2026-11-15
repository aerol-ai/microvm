package e2b

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

func TestManagerOptionsCwd(t *testing.T) {
	denied := func(string, os.FileMode) error { return os.ErrPermission }
	cases := []struct {
		name  string
		mkdir func(string, os.FileMode) error
		getwd func() (string, error)
		want  string
	}{
		{name: "made or already there", mkdir: func(string, os.FileMode) error { return nil }, want: "/home/user"},
		{name: "cannot be made: the agent's cwd", mkdir: denied, getwd: func() (string, error) { return "/srv/app", nil }, want: "/srv/app"},
		{name: "no cwd either: the root", mkdir: denied, getwd: func() (string, error) { return "", errors.New("gone") }, want: "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newFakeLauncher()
			lim := codeinterp.NewLimit(3)
			opts := managerOptions(l, lim, "/home/user", tc.mkdir, tc.getwd)
			if opts.DefaultCwd != tc.want {
				t.Fatalf("DefaultCwd = %q, want %q", opts.DefaultCwd, tc.want)
			}
			if opts.Launcher != l || opts.Limit != lim || !opts.ListDefaults || opts.ProtectDefaults || opts.DefaultID != nil {
				t.Fatalf("options = %+v, want E2B's: listed, deletable defaults with random ids", opts)
			}
		})
	}
}

func TestUsableCwdCreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "home", "user")
	if got := usableCwd(dir, os.MkdirAll, os.Getwd); got != dir {
		t.Fatalf("cwd = %q, want %q", got, dir)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("directory not made: %v", err)
	}
}

// ManagerOptions itself touches /home/user, so it only runs where that
// already exists and the call changes nothing.
func TestManagerOptionsUsesHomeUser(t *testing.T) {
	if fi, err := os.Stat(DefaultCwd); err != nil || !fi.IsDir() {
		t.Skipf("%s does not exist here", DefaultCwd)
	}
	if got := ManagerOptions(newFakeLauncher(), nil).DefaultCwd; got != DefaultCwd {
		t.Fatalf("DefaultCwd = %q", got)
	}
}

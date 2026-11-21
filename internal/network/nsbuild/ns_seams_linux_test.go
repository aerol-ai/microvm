//go:build linux

package nsbuild

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// The steps' own logic with the privileged calls stood in (seams), so it is
// checked without rights: which mounts a share and a bind make, what a
// failure leaves behind, and when a thread may go back to the pool.

type fakeCalls struct {
	mu     sync.Mutex
	mounts []string
	// mountErr answers each mount, by its flags.
	mountErr   func(flags uintptr) error
	unshareErr error
	getErr     error
	setErr     error
}

func stub(t *testing.T, f *fakeCalls) {
	t.Helper()
	m, u, g, s := mount, unshare, nsGet, nsSet
	t.Cleanup(func() { mount, unshare, nsGet, nsSet = m, u, g, s })
	mount = func(source, target, _ string, flags uintptr, _ string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		kind := "share"
		if flags&unix.MS_BIND != 0 {
			kind = "bind"
		}
		f.mounts = append(f.mounts, kind+" "+filepath.Base(source)+" "+filepath.Base(target))
		if f.mountErr != nil {
			return f.mountErr(flags)
		}
		return nil
	}
	unshare = func(int) error { return f.unshareErr }
	nsGet = func() (netns.NsHandle, error) {
		if f.getErr != nil {
			return netns.None(), f.getErr
		}
		return netns.NsHandle(-1), nil
	}
	nsSet = func(netns.NsHandle) error { return f.setErr }
}

func (f *fakeCalls) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.mounts...)
}

// TestShareNetnsRootMakesAMountFirst: a root that is not a mount point yet
// (EINVAL) is bound onto itself once, then shared; any other failure, or a
// second EINVAL, is an error.
func TestShareNetnsRootMakesAMountFirst(t *testing.T) {
	root := t.TempDir()
	t.Run("already a mount", func(t *testing.T) {
		f := &fakeCalls{}
		stub(t, f)
		if err := shareNetnsRoot(root); err != nil || len(f.seen()) != 1 {
			t.Fatalf("%v, mounts %v", err, f.seen())
		}
	})
	t.Run("not a mount yet", func(t *testing.T) {
		shares := 0
		f := &fakeCalls{mountErr: func(flags uintptr) error {
			if flags&unix.MS_SHARED != 0 {
				if shares++; shares == 1 {
					return unix.EINVAL
				}
			}
			return nil
		}}
		stub(t, f)
		if err := shareNetnsRoot(root); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(f.seen(), ","); !strings.Contains(got, "bind") || len(f.seen()) != 3 {
			t.Fatalf("mounts %v", f.seen())
		}
	})
	t.Run("the bind fails", func(t *testing.T) {
		f := &fakeCalls{mountErr: func(flags uintptr) error {
			if flags&unix.MS_BIND != 0 {
				return unix.EPERM
			}
			return unix.EINVAL
		}}
		stub(t, f)
		if err := shareNetnsRoot(root); err == nil || !strings.Contains(err.Error(), "mount --bind") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("still not a mount after the bind", func(t *testing.T) {
		f := &fakeCalls{mountErr: func(flags uintptr) error {
			if flags&unix.MS_BIND != 0 {
				return nil
			}
			return unix.EINVAL
		}}
		stub(t, f)
		if err := shareNetnsRoot(root); err == nil || !strings.Contains(err.Error(), "make-shared") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("no folder to lock", func(t *testing.T) {
		stub(t, &fakeCalls{})
		if err := shareNetnsRoot(filepath.Join(root, "none")); err == nil || !strings.Contains(err.Error(), "open netns dir") {
			t.Fatalf("%v", err)
		}
	})
}

// TestCreateNamedSteps: a create makes the file and binds a new namespace
// on it; an existing file is success; a bind that fails leaves no file.
func TestCreateNamedSteps(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sb-1")
	t.Run("made", func(t *testing.T) {
		f := &fakeCalls{}
		stub(t, f)
		if err := CreateNamed(root, "sb-1"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("no file: %v", err)
		}
		if got := f.seen(); len(got) != 2 || !strings.HasPrefix(got[1], "bind net sb-1") {
			t.Fatalf("mounts %v", got)
		}
		if err := CreateNamed(root, "sb-1"); err != nil {
			t.Fatalf("an existing namespace: %v", err)
		}
	})
	t.Run("the bind fails: no file is left", func(t *testing.T) {
		stub(t, &fakeCalls{mountErr: func(flags uintptr) error {
			if flags&unix.MS_BIND != 0 {
				return unix.EPERM
			}
			return nil
		}})
		if err := CreateNamed(root, "sb-2"); err == nil || !strings.Contains(err.Error(), "bind") {
			t.Fatalf("%v", err)
		}
		if _, err := os.Stat(filepath.Join(root, "sb-2")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a failed create left its file: %v", err)
		}
	})
	t.Run("the file cannot be made", func(t *testing.T) {
		stub(t, &fakeCalls{})
		if err := os.Mkdir(filepath.Join(root, "ro"), 0o555); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() == 0 {
			t.Skip("root writes a read-only folder")
		}
		if err := CreateNamed(filepath.Join(root, "ro"), "sb-3"); err == nil || !strings.Contains(err.Error(), "create netns file") {
			t.Fatalf("%v", err)
		}
	})
}

// TestBindNewNetnsWayBack: the thread may go back to the pool only once it
// is home; a way back that fails keeps it locked, and says so.
func TestBindNewNetnsWayBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sb-1")
	for _, tc := range []struct {
		name     string
		f        *fakeCalls
		wantHome bool
		want     string
	}{
		{"made and home", &fakeCalls{}, true, ""},
		{"no handle on this thread's namespace", &fakeCalls{getErr: errors.New("no ns")}, true, "open this thread's netns"},
		{"the unshare fails", &fakeCalls{unshareErr: unix.EPERM}, true, "unshare a new netns"},
		{"the bind fails, home again", &fakeCalls{mountErr: func(uintptr) error { return unix.EPERM }}, true, "bind"},
		{"the way back fails", &fakeCalls{setErr: errors.New("setns refused")}, false, "return to the original netns"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub(t, tc.f)
			home, err := bindNewNetnsOnThread(path)
			if home != tc.wantHome || (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("home %v, %v; want home %v, %q", home, err, tc.wantHome, tc.want)
			}
		})
	}
	// Through bindNewNetns, on a goroutine of its own: a thread that could
	// not go back ends with it.
	stub(t, &fakeCalls{setErr: errors.New("setns refused")})
	if err := bindNewNetns(path); err == nil || !strings.Contains(err.Error(), "return to the original netns") {
		t.Fatalf("%v", err)
	}
}

//go:build linux

package rootd

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openRoot opens dir as readInRoot's root.
func openRoot(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// within makes the files of an image root under dir: name to content, or
// to "->target" for a link, "|" for a FIFO, "/" for a folder.
func within(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, what := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		var err error
		switch {
		case strings.HasPrefix(what, "->"):
			err = os.Symlink(what[2:], p)
		case what == "|":
			err = syscall.Mkfifo(p, 0o644)
		case what == "/":
			err = os.Mkdir(p, 0o755)
		default:
			err = os.WriteFile(p, []byte(what), 0o644)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestReadInRoot (M1 PR 7, the broken-agent and broken-image cases): the
// helper reads an image's passwd inside the image's root. A link,
// absolute or climbing, resolves inside that root and never reaches the
// host's file; a FIFO is refused at once, never waited on; a file past the
// bound is refused, never read whole; a missing file or folder is absent.
func TestReadInRoot(t *testing.T) {
	// The host's secret, beside the image's root: what a hostile image
	// wants the helper to read as root.
	base := t.TempDir()
	secret := filepath.Join(base, "secret")
	if err := os.WriteFile(secret, []byte("host secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		files    map[string]string
		present  bool
		body     string
		badMatch string
	}{
		{"a plain file", map[string]string{"etc/passwd": "app:x:1:1::/:/bin/sh\n"}, true, "app:x:1:1::/:/bin/sh\n", ""},
		{"absent", map[string]string{"etc/group": "g:x:1:\n"}, false, "", ""},
		{"no etc", map[string]string{"bin/sh": "x"}, false, "", ""},
		{"etc is a file", map[string]string{"etc": "x"}, false, "", ""},
		{"a link inside the image", map[string]string{"etc/passwd": "->../usr/share/passwd", "usr/share/passwd": "u:x:2:2::/:/bin/sh\n"}, true, "u:x:2:2::/:/bin/sh\n", ""},
		{"etc a link to a folder inside", map[string]string{"etc": "->/private/etc", "private/etc/passwd": "p:x:3:3::/:/bin/sh\n"}, true, "p:x:3:3::/:/bin/sh\n", ""},
		{"an absolute link to the host's file", map[string]string{"etc/passwd": "->" + secret}, false, "", ""},
		{"a link climbing to the host's file", map[string]string{"etc/passwd": "->../../../../../../../../" + secret}, false, "", ""},
		{"an absolute link to a file of the image's own", map[string]string{"etc/passwd": "->/secret", "secret": "mine\n"}, true, "mine\n", ""},
		{"a FIFO", map[string]string{"etc/passwd": "|"}, true, "", "not a regular file"},
		{"a folder", map[string]string{"etc/passwd": "/"}, true, "", "not a regular file"},
		{"a link loop", map[string]string{"etc/passwd": "->/etc/loop", "etc/loop": "->/etc/passwd"}, true, "", "too many levels"},
		{"a magic link", map[string]string{"etc/passwd": "->/proc/self/root/etc/passwd", "proc/self/root/etc/passwd": "fake\n"}, true, "fake\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "rootfs")
			if err := os.Mkdir(root, 0o755); err != nil {
				t.Fatal(err)
			}
			within(t, root, tc.files)
			done := make(chan UserFile, 1)
			go func() { done <- readInRoot(openRoot(t, root), "etc/passwd") }()
			var f UserFile
			select {
			case f = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the read hung")
			}
			if f.Present != tc.present || string(f.Body) != tc.body || (tc.badMatch == "") != (f.Bad == "") || !strings.Contains(f.Bad, tc.badMatch) {
				t.Fatalf("read %+v (body %q), want present %v body %q bad %q", f, f.Body, tc.present, tc.body, tc.badMatch)
			}
			if strings.Contains(string(f.Body), "host secret") {
				t.Fatal("the host's file was read")
			}
		})
	}
	// Past the bound: refused from its size, never read (a sparse file).
	root := filepath.Join(t.TempDir(), "rootfs")
	within(t, root, map[string]string{"etc/x": "x"})
	big, err := os.Create(filepath.Join(root, "etc", "passwd"))
	if err != nil {
		t.Fatal(err)
	}
	if err := big.Truncate(maxUserFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = big.Close()
	if f := readInRoot(openRoot(t, root), "etc/passwd"); !f.Present || f.Bad == "" || f.Body != nil {
		t.Fatalf("a huge Passwd: %+v", f)
	}
	// At the bound: read.
	if err := os.Truncate(filepath.Join(root, "etc", "passwd"), maxUserFileBytes); err != nil {
		t.Fatal(err)
	}
	if f := readInRoot(openRoot(t, root), "etc/passwd"); f.Bad != "" || len(f.Body) != maxUserFileBytes {
		t.Fatalf("a passwd at the bound: bad %q, %d bytes", f.Bad, len(f.Body))
	}
	// A closed root fails the open, which is no file to read.
	if f := readInRoot(-1, "etc/passwd"); !f.Present || f.Bad == "" {
		t.Fatalf("a bad root: %+v", f)
	}
}

// TestReadImageFilesKernel: the real read, as root. The image's layers are
// mounted detached: the upper layer's files over the lower's, and one
// layer alone over the empty folder; read-only, nosuid, nodev and noexec
// by the mount's own flags. While the read holds the mount, no mount table
// has it: neither the process's nor the reading thread's lists its id,
// where both list a mount the test makes (so the check does see a mount),
// and the reading thread is in the process's mount namespace. A FIFO
// passwd does not hold the read. A layer outside the snapshots folder or
// reached through a link is refused, and so is a bottom folder that is
// not empty.
func TestReadImageFilesKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (mounts)")
	}
	snaps, l1, l2, empty := imageLayers(t)
	pin := filepath.Join(t.TempDir(), "pin")
	pinID := mountTmpfs(t, pin)
	processNS, err := os.Readlink(mainThread("ns/mnt"))
	if err != nil {
		t.Fatal(err)
	}
	type seen struct {
		idErr, fsErr       error
		mnt                uint64
		fs                 unix.Statfs_t
		inSelf, inThread   bool
		pinSelf, pinThread bool
		ns                 string
	}
	var got []seen
	imageMountedHook = func(mfd int) {
		var s seen
		s.mnt, s.idErr = mountIDOf(mfd)
		s.fsErr = unix.Fstatfs(mfd, &s.fs)
		s.inSelf, s.inThread = inTable("/proc/self/mountinfo", s.mnt), inTable("/proc/thread-self/mountinfo", s.mnt)
		s.pinSelf, s.pinThread = inTable("/proc/self/mountinfo", pinID), inTable("/proc/thread-self/mountinfo", pinID)
		s.ns, _ = os.Readlink("/proc/thread-self/ns/mnt")
		got = append(got, s)
	}
	t.Cleanup(func() { imageMountedHook = nil })
	for _, tc := range []struct {
		name          string
		layers        []string
		passwd, group string
	}{
		{"two layers", []string{l2, l1}, "app:x:1000:1000::/:/bin/sh\n", "base:x:1:\n"},
		{"one layer", []string{l1}, "base:x:1:1::/:/bin/sh\n", "base:x:1:\n"},
	} {
		got = nil
		f, err := readImageFiles(snaps, empty, tc.layers)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if string(f.Passwd.Body) != tc.passwd || string(f.Group.Body) != tc.group {
			t.Fatalf("%s: passwd %q group %q", tc.name, f.Passwd.Body, f.Group.Body)
		}
		if len(got) != 1 || got[0].idErr != nil || got[0].fsErr != nil {
			t.Fatalf("%s: mounted %d times: %+v", tc.name, len(got), got)
		}
		s := got[0]
		const want = unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
		if s.fs.Type != unix.OVERLAYFS_SUPER_MAGIC || s.fs.Flags&want != want {
			t.Fatalf("%s: the image's mount is type %#x with flags %#x, want overlay with %#x", tc.name, s.fs.Type, s.fs.Flags, want)
		}
		if !s.pinSelf || !s.pinThread {
			t.Fatalf("%s: the tables lack the test's own mount %d (process %v, thread %v)", tc.name, pinID, s.pinSelf, s.pinThread)
		}
		if s.inSelf || s.inThread {
			t.Fatalf("%s: the image's mount %d is in a mount table (process %v, thread %v)", tc.name, s.mnt, s.inSelf, s.inThread)
		}
		if s.ns != processNS {
			t.Fatalf("%s: the read ran in mount namespace %s, not the process's %s", tc.name, s.ns, processNS)
		}
	}
	// No layer: no files, nothing mounted.
	got = nil
	if f, err := readImageFiles(snaps, empty, nil); err != nil || f.Passwd.Present || len(got) != 0 {
		t.Fatalf("no layer: %+v, %v, %d mounts", f, err, len(got))
	}
	// A FIFO in the upper layer is refused, never waited on.
	if err := os.Remove(filepath.Join(l2, "etc", "passwd")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(l2, "etc", "passwd"), 0o644); err != nil {
		t.Fatal(err)
	}
	type read struct {
		f   UserFiles
		err error
	}
	done := make(chan read, 1)
	go func() {
		f, err := readImageFiles(snaps, empty, []string{l2, l1})
		done <- read{f, err}
	}()
	select {
	case r := <-done:
		if r.err != nil || r.f.Passwd.Bad == "" {
			t.Fatalf("a FIFO Passwd: %+v, %v", r.f.Passwd, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a FIFO Passwd held the read")
	}
	// Refused: a layer outside the snapshots folder; a layer reached
	// through a link, even one under the folder; a bottom folder that
	// holds a file, which would show through.
	outside := t.TempDir()
	within(t, outside, map[string]string{"fs/etc/passwd": "evil:x:0:0::/:/bin/sh\n"})
	if err := os.Symlink(outside, filepath.Join(snaps, "3")); err != nil {
		t.Fatal(err)
	}
	for name, layers := range map[string][]string{
		"outside":        {l1, "/etc"},
		"through a link": {filepath.Join(snaps, "3", "fs"), l1},
	} {
		if _, err := readImageFiles(snaps, empty, layers); err == nil {
			t.Fatalf("a layer %s was mounted", name)
		}
	}
	within(t, empty, map[string]string{"etc/passwd": "stray:x:0:0::/:/bin/sh\n"})
	if _, err := readImageFiles(snaps, empty, []string{l1}); err == nil || !strings.Contains(err.Error(), "holds etc") {
		t.Fatalf("a bottom folder that is not empty: %v", err)
	}
}

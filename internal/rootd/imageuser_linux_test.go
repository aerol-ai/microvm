//go:build linux

package rootd

import (
	"context"
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

// TestReadImageFilesKernel: the real read, as root: the image's layers are
// mounted read-only in a mount namespace of the reading thread's own, the
// upper layer's files over the lower's, and the mount is never in the
// host's mount table, during or after. A FIFO passwd in a layer does not
// hold the read. One layer is bound, not overlaid.
func TestReadImageFilesKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (mounts)")
	}
	snaps := filepath.Join(t.TempDir(), "snapshots")
	l1, l2 := filepath.Join(snaps, "1", "fs"), filepath.Join(snaps, "2", "fs")
	within(t, l1, map[string]string{"etc/passwd": "base:x:1:1::/:/bin/sh\n", "etc/group": "base:x:1:\n"})
	within(t, l2, map[string]string{"etc/passwd": "app:x:1000:1000::/:/bin/sh\n", "usr/bin/x": "x"})
	mp := filepath.Join(t.TempDir(), "imageroot")
	if err := os.Mkdir(mp, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := readImageFiles(context.Background(), snaps, mp, []string{l2, l1})
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Passwd.Body) != "app:x:1000:1000::/:/bin/sh\n" || string(f.Group.Body) != "base:x:1:\n" {
		t.Fatalf("passwd %q group %q", f.Passwd.Body, f.Group.Body)
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mounts), mp) {
		t.Fatal("the image's mount reached the host's mount table")
	}
	// One layer: bound read-only.
	if f, err := readImageFiles(context.Background(), snaps, mp, []string{l1}); err != nil || string(f.Passwd.Body) != "base:x:1:1::/:/bin/sh\n" {
		t.Fatalf("one layer: %+v, %v", f, err)
	}
	// No layer: no files, nothing mounted.
	if f, err := readImageFiles(context.Background(), snaps, mp, nil); err != nil || f.Passwd.Present {
		t.Fatalf("no layer: %+v, %v", f, err)
	}
	// A FIFO in the upper layer.
	if err := os.Remove(filepath.Join(l2, "etc", "passwd")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(l2, "etc", "passwd"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, err = readImageFiles(ctx, snaps, mp, []string{l2, l1})
	if err != nil || f.Passwd.Bad == "" {
		t.Fatalf("a FIFO Passwd: %+v, %v", f, err)
	}
	// The mount is read-only and noexec: proved by the flags, read inside
	// the thread's namespace while it is mounted.
	flags := make(chan string, 1)
	imageMountedHook = func() {
		raw, _ := os.ReadFile("/proc/thread-self/mountinfo")
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, " "+mp+" ") {
				flags <- line
				return
			}
		}
		flags <- ""
	}
	t.Cleanup(func() { imageMountedHook = nil })
	if _, err := readImageFiles(context.Background(), snaps, mp, []string{l2, l1}); err != nil {
		t.Fatal(err)
	}
	line := <-flags
	for _, want := range []string{"ro", "nosuid", "nodev", "noexec"} {
		if !strings.Contains(line, want) {
			t.Fatalf("the image's mount %q lacks %s", line, want)
		}
	}
	// A layer outside the snapshots folder is never mounted.
	if _, err := readImageFiles(context.Background(), snaps, mp, []string{l2, "/etc"}); err == nil {
		t.Fatal("mounted a folder outside the snapshots")
	}
}

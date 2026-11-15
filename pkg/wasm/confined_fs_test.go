package wasm

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	experimentalsys "github.com/tetratelabs/wazero/experimental/sys"
	"github.com/tetratelabs/wazero/experimental/sysfs"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// confinedTree builds base/work (the mount) next to base/outside/secret:
//
//	work/f        "hello"
//	work/d/g      "g"
//	work/link  -> f
//	work/esc   -> ..
//	work/escf  -> ../outside/secret
func confinedTree(t *testing.T) (work, outside string) {
	t.Helper()
	base := t.TempDir()
	work = filepath.Join(base, "work")
	outside = filepath.Join(base, "outside")
	mustDo(t, os.MkdirAll(filepath.Join(work, "d"), 0o755))
	mustDo(t, os.MkdirAll(outside, 0o755))
	mustDo(t, os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o644))
	mustDo(t, os.WriteFile(filepath.Join(work, "f"), []byte("hello"), 0o644))
	mustDo(t, os.WriteFile(filepath.Join(work, "d", "g"), []byte("g"), 0o644))
	mustDo(t, os.Symlink("f", filepath.Join(work, "link")))
	mustDo(t, os.Symlink("..", filepath.Join(work, "esc")))
	mustDo(t, os.Symlink("../outside/secret", filepath.Join(work, "escf")))
	return work, outside
}

const (
	rdonly = experimentalsys.O_RDONLY
	creat  = experimentalsys.O_CREAT
)

// openErrno opens name and closes it again, returning only the errno.
func openErrno(c *confinedFS, name string, flag experimentalsys.Oflag) experimentalsys.Errno {
	f, errno := c.OpenFile(name, flag, 0o644)
	if errno == 0 {
		_ = f.Close()
	}
	return errno
}

func newTestFS(t *testing.T, dir string, readOnly bool) *confinedFS {
	t.Helper()
	c := newConfinedFS(dir, readOnly)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestSymlinkTargetConfined(t *testing.T) {
	for target, want := range map[string]bool{
		"f":             true,
		"d/g":           true,
		"./d/g":         true,
		"d/":            true,
		"":              false,
		"/etc":          false,
		"..":            false,
		"../x":          false,
		"d/../f":        false,
		"d/..":          false,
		"a/b/../../..":  false,
		"f\x00":         false,
		"...":           true, // a name, not a climb
		"..d":           true,
		"d/..hidden/x":  true,
		"d//g":          true,
		"d/./g":         true,
		"d/g/../../../": false,
	} {
		if got := symlinkTargetConfined(target); got != want {
			t.Errorf("symlinkTargetConfined(%q) = %v; want %v", target, got, want)
		}
	}
}

func TestRootNameAndErrno(t *testing.T) {
	for in, want := range map[string]string{"": ".", "/": ".", "//a": "a", "a/b": "a/b", "d/": "d/"} {
		if got := rootName(in); got != want {
			t.Errorf("rootName(%q) = %q; want %q", in, got, want)
		}
	}
	for _, tc := range []struct {
		err  error
		want experimentalsys.Errno
	}{
		{nil, 0},
		{&fs.PathError{Op: "openat", Path: "x", Err: syscall.ENOENT}, experimentalsys.ENOENT},
		{&fs.PathError{Op: "openat", Path: "x", Err: fs.ErrClosed}, experimentalsys.EBADF},
		{io.EOF, 0},
		// os.Root's "path escapes from parent" is a plain error.
		{&fs.PathError{Op: "openat", Path: "x", Err: errors.New("path escapes from parent")}, experimentalsys.EPERM},
	} {
		if got := rootErrno(tc.err); got != tc.want {
			t.Errorf("rootErrno(%v) = %v; want %v", tc.err, got, tc.want)
		}
	}
	if omitTime(experimentalsys.UTIME_OMIT) != (time.Time{}) || omitTime(0).IsZero() {
		t.Fatal("omitTime must map only UTIME_OMIT to the zero time")
	}
}

func TestToOSOpenFlag(t *testing.T) {
	for _, tc := range []struct {
		in   experimentalsys.Oflag
		want int
	}{
		{experimentalsys.O_RDONLY, os.O_RDONLY},
		{experimentalsys.O_WRONLY, os.O_WRONLY},
		{experimentalsys.O_RDWR, os.O_RDWR},
		{experimentalsys.O_WRONLY | experimentalsys.O_APPEND | experimentalsys.O_CREAT | experimentalsys.O_EXCL | experimentalsys.O_SYNC | experimentalsys.O_TRUNC,
			os.O_WRONLY | os.O_APPEND | os.O_CREATE | os.O_EXCL | os.O_SYNC | os.O_TRUNC},
		// O_NOFOLLOW is OpenFile's job, not a flag os.Root is handed.
		{experimentalsys.O_NOFOLLOW, os.O_RDONLY},
	} {
		if got := toOSOpenFlag(tc.in); got != tc.want {
			t.Errorf("toOSOpenFlag(%v) = %#x; want %#x", tc.in, got, tc.want)
		}
	}
	if got := toOSOpenFlag(experimentalsys.O_DIRECTORY | experimentalsys.O_NONBLOCK | experimentalsys.O_DSYNC); got == os.O_RDONLY {
		t.Error("directory, non-blocking and dsync flags were dropped")
	}
}

// Every path call refuses to resolve through a link that leaves the mount,
// and answers EPERM for it.
func TestConfinedFSRefusesEscapes(t *testing.T) {
	work, outside := confinedTree(t)
	c := newTestFS(t, work, false)
	cases := map[string]func() experimentalsys.Errno{
		"open dir link":     func() experimentalsys.Errno { return openErrno(c, "esc/outside/secret", rdonly) },
		"open file link":    func() experimentalsys.Errno { return openErrno(c, "escf", rdonly) },
		"create via link":   func() experimentalsys.Errno { return openErrno(c, "esc/new", experimentalsys.O_WRONLY|creat) },
		"stat":              func() experimentalsys.Errno { _, e := c.Stat("escf"); return e },
		"lstat below link":  func() experimentalsys.Errno { _, e := c.Lstat("esc/outside"); return e },
		"readlink below":    func() experimentalsys.Errno { _, e := c.Readlink("esc/work/esc"); return e },
		"mkdir":             func() experimentalsys.Errno { return c.Mkdir("esc/newdir", 0o755) },
		"chmod":             func() experimentalsys.Errno { return c.Chmod("escf", 0o600) },
		"rename from":       func() experimentalsys.Errno { return c.Rename("esc/outside/secret", "stolen") },
		"rename to":         func() experimentalsys.Errno { return c.Rename("f", "esc/f") },
		"rmdir":             func() experimentalsys.Errno { return c.Rmdir("esc/outside") },
		"unlink":            func() experimentalsys.Errno { return c.Unlink("esc/outside/secret") },
		"link from outside": func() experimentalsys.Errno { return c.Link("esc/outside/secret", "hl") },
		"link to outside":   func() experimentalsys.Errno { return c.Link("f", "esc/hl") },
		"symlink climb":     func() experimentalsys.Errno { return c.Symlink("../outside", "x") },
		"symlink below":     func() experimentalsys.Errno { return c.Symlink("f", "esc/x") },
		"utimens":           func() experimentalsys.Errno { return c.Utimens("escf", 0, 0) },
	}
	for name, call := range cases {
		if errno := call(); errno != experimentalsys.EPERM {
			t.Errorf("%s = %v; want EPERM", name, errno)
		}
	}
	data, err := os.ReadFile(filepath.Join(outside, "secret"))
	if err != nil || string(data) != "secret" {
		t.Fatalf("outside file = %q, %v", data, err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 1 {
		t.Fatalf("outside dir has %d entries; want 1", len(entries))
	}
	if fi, err := os.Stat(filepath.Join(outside, "secret")); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("outside file mode changed: %v %v", fi.Mode(), err)
	}
}

func TestConfinedFSPathCalls(t *testing.T) {
	work, _ := confinedTree(t)
	c := newTestFS(t, work, false)
	if c.String() != work {
		t.Fatalf("String() = %q", c.String())
	}
	expect := func(name string, got, want experimentalsys.Errno) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %v; want %v", name, got, want)
		}
	}

	st, errno := c.Stat("link")
	expect("stat link", errno, 0)
	if st.Size != 5 {
		t.Errorf("stat follows an inside link: size %d", st.Size)
	}
	st, errno = c.Lstat("link")
	expect("lstat link", errno, 0)
	if st.Mode&fs.ModeSymlink == 0 {
		t.Error("lstat followed the link")
	}
	_, errno = c.Stat("")
	expect("stat root", errno, 0)
	_, errno = c.Lstat("missing")
	expect("lstat missing", errno, experimentalsys.ENOENT)
	target, errno := c.Readlink("escf")
	expect("readlink", errno, 0)
	if target != "../outside/secret" {
		t.Errorf("readlink = %q", target)
	}
	_, errno = c.Readlink("f")
	expect("readlink regular file", errno, experimentalsys.EINVAL)

	expect("mkdir", c.Mkdir("n", 0o755), 0)
	expect("mkdir exists", c.Mkdir("n", 0o755), experimentalsys.EEXIST)
	expect("mkdir missing parent", c.Mkdir("nope/n", 0o755), experimentalsys.ENOENT)
	expect("mkdir under a file", c.Mkdir("f/n", 0o755), experimentalsys.ENOENT)
	expect("chmod", c.Chmod("f", 0o600), 0)

	expect("symlink inside", c.Symlink("d/g", "lg"), 0)
	expect("symlink exists", c.Symlink("d/g", "lg"), experimentalsys.EEXIST)
	expect("link", c.Link("f", "hl"), 0)

	expect("rename same", c.Rename("f", "f"), 0)
	expect("rename", c.Rename("hl", "d/hl"), 0)
	expect("rename missing", c.Rename("nope", "x"), experimentalsys.ENOENT)
	expect("rename dir over empty dir", c.Rename("d", "n"), 0)
	expect("rename file with a slash", c.Rename("f/", "x"), experimentalsys.ENOTDIR)
	expect("rename missing with a slash", c.Rename("nope/", "x"), experimentalsys.ENOENT)
	expect("rename dir with a slash", c.Rename("n/", "d/"), 0)

	expect("unlink dir", c.Unlink("d"), experimentalsys.EISDIR)
	expect("unlink file with a slash", c.Unlink("f/"), experimentalsys.ENOTDIR)
	expect("unlink missing with a slash", c.Unlink("nope/"), experimentalsys.ENOENT)
	expect("unlink dir with a slash", c.Unlink("d/"), experimentalsys.EISDIR)
	expect("unlink link", c.Unlink("escf"), 0)
	expect("unlink", c.Unlink("d/hl"), 0)
	expect("unlink missing", c.Unlink("d/hl"), experimentalsys.ENOENT)

	expect("rmdir file", c.Rmdir("f"), experimentalsys.ENOTDIR)
	expect("rmdir non-empty", c.Rmdir("d"), experimentalsys.ENOTEMPTY)
	expect("rmdir link to dir", c.Rmdir("esc"), experimentalsys.ENOTDIR)
	mustDo(t, os.Remove(filepath.Join(work, "d", "g")))
	expect("rmdir", c.Rmdir("d/"), 0)
	if _, err := os.Lstat(filepath.Join(work, "esc")); err != nil {
		t.Fatalf("rmdir of a link removed it: %v", err)
	}

	expect("utimens both omitted", c.Utimens("missing", experimentalsys.UTIME_OMIT, experimentalsys.UTIME_OMIT), 0)
	mtime := time.Date(2003, 4, 5, 6, 7, 8, 0, time.UTC)
	expect("utimens", c.Utimens("link", experimentalsys.UTIME_OMIT, mtime.UnixNano()), 0)
	if fi, err := os.Stat(filepath.Join(work, "f")); err != nil || !fi.ModTime().Equal(mtime) {
		t.Errorf("utimens through an inside link: mtime %v, %v", fi.ModTime(), err)
	}
}

// A read-only mount refuses every change up front; a missing or closed one
// fails every call without falling back to anything.
func TestConfinedFSRefusals(t *testing.T) {
	work, _ := confinedTree(t)
	ro := newTestFS(t, work, true)
	missing := newTestFS(t, filepath.Join(work, "no-such-dir"), false)
	closed := newConfinedFS(work, false)
	if _, errno := closed.Stat("f"); errno != 0 {
		t.Fatalf("stat before close: %v", errno)
	}
	mustDo(t, closed.Close())
	mustDo(t, closed.Close())
	never := newConfinedFS(work, false)
	mustDo(t, never.Close()) // closed before any use

	type call func(c *confinedFS) experimentalsys.Errno
	calls := map[string]call{
		"open":     func(c *confinedFS) experimentalsys.Errno { return openErrno(c, "f", rdonly) },
		"open rw":  func(c *confinedFS) experimentalsys.Errno { return openErrno(c, "f", experimentalsys.O_RDWR) },
		"create":   func(c *confinedFS) experimentalsys.Errno { return openErrno(c, "n", creat) },
		"lstat":    func(c *confinedFS) experimentalsys.Errno { _, e := c.Lstat("f"); return e },
		"stat":     func(c *confinedFS) experimentalsys.Errno { _, e := c.Stat("f"); return e },
		"readlink": func(c *confinedFS) experimentalsys.Errno { _, e := c.Readlink("link"); return e },
		"mkdir":    func(c *confinedFS) experimentalsys.Errno { return c.Mkdir("n", 0o755) },
		"chmod":    func(c *confinedFS) experimentalsys.Errno { return c.Chmod("f", 0o600) },
		"rename":   func(c *confinedFS) experimentalsys.Errno { return c.Rename("f", "g") },
		"rmdir":    func(c *confinedFS) experimentalsys.Errno { return c.Rmdir("d") },
		"unlink":   func(c *confinedFS) experimentalsys.Errno { return c.Unlink("f") },
		"link":     func(c *confinedFS) experimentalsys.Errno { return c.Link("f", "g") },
		"symlink":  func(c *confinedFS) experimentalsys.Errno { return c.Symlink("f", "g") },
		"utimens":  func(c *confinedFS) experimentalsys.Errno { return c.Utimens("f", 0, 0) },
	}
	readCalls := map[string]bool{"open": true, "lstat": true, "stat": true, "readlink": true}
	for name, fn := range calls {
		want := experimentalsys.EROFS
		if readCalls[name] {
			want = 0
		}
		if got := fn(ro); got != want {
			t.Errorf("read-only %s = %v; want %v", name, got, want)
		}
		if got := fn(missing); got != experimentalsys.ENOENT {
			t.Errorf("missing dir %s = %v; want ENOENT", name, got)
		}
		for _, c := range []*confinedFS{closed, never} {
			if got := fn(c); got != experimentalsys.EBADF {
				t.Errorf("closed %s = %v; want EBADF", name, got)
			}
		}
	}
	if _, errno := ro.OpenFile("d", experimentalsys.O_DIRECTORY|experimentalsys.O_RDWR, 0); errno != experimentalsys.EISDIR {
		t.Errorf("open dir for write = %v; want EISDIR", errno)
	}
	if data, _ := os.ReadFile(filepath.Join(work, "f")); string(data) != "hello" {
		t.Fatalf("read-only mount changed f to %q", data)
	}
}

func TestConfinedFSOpenNoFollow(t *testing.T) {
	work, _ := confinedTree(t)
	c := newTestFS(t, work, false)
	if _, errno := c.OpenFile("link", experimentalsys.O_RDONLY|experimentalsys.O_NOFOLLOW, 0); errno != experimentalsys.ELOOP {
		t.Errorf("no-follow open of a link = %v; want ELOOP", errno)
	}
	excl := experimentalsys.O_WRONLY | experimentalsys.O_CREAT | experimentalsys.O_EXCL | experimentalsys.O_NOFOLLOW
	if _, errno := c.OpenFile("link", excl, 0o644); errno != experimentalsys.EEXIST {
		t.Errorf("exclusive create over a link = %v; want EEXIST", errno)
	}
	f, errno := c.OpenFile("f", experimentalsys.O_RDONLY|experimentalsys.O_NOFOLLOW, 0)
	if errno != 0 {
		t.Fatalf("no-follow open of a file: %v", errno)
	}
	_ = f.Close()
	if _, errno := c.OpenFile("d", experimentalsys.O_DIRECTORY|experimentalsys.O_WRONLY, 0); errno != experimentalsys.EISDIR {
		t.Errorf("directory opened for write = %v; want EISDIR", errno)
	}
	if _, errno := c.OpenFile("f", experimentalsys.O_DIRECTORY, 0); errno != experimentalsys.ENOTDIR {
		t.Errorf("O_DIRECTORY on a file = %v; want ENOTDIR", errno)
	}
}

func openTestFile(t *testing.T, c *confinedFS, name string, flag experimentalsys.Oflag) *confinedFile {
	t.Helper()
	f, errno := c.OpenFile(name, flag, 0o644)
	if errno != 0 {
		t.Fatalf("open %s: %v", name, errno)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f.(*confinedFile)
}

func TestConfinedFileIO(t *testing.T) {
	work, _ := confinedTree(t)
	c := newTestFS(t, work, false)
	f := openTestFile(t, c, "f", experimentalsys.O_RDWR)

	if dir, errno := f.IsDir(); errno != 0 || dir {
		t.Fatalf("IsDir = %v, %v", dir, errno)
	}
	if _, errno := f.Dev(); errno != 0 {
		t.Fatal(errno)
	}
	if ino, errno := f.Ino(); errno != 0 || ino == 0 {
		t.Fatalf("Ino = %v, %v", ino, errno)
	}
	buf := make([]byte, 5)
	if n, errno := f.Read(buf); errno != 0 || string(buf[:n]) != "hello" {
		t.Fatalf("Read = %q, %v", buf[:n], errno)
	}
	if n, errno := f.Read(buf); errno != 0 || n != 0 {
		t.Fatalf("Read at EOF = %d, %v; want 0, 0", n, errno)
	}
	if n, errno := f.Read(nil); errno != 0 || n != 0 {
		t.Fatalf("empty Read = %d, %v", n, errno)
	}
	if n, errno := f.Pread(buf[:3], 1); errno != 0 || string(buf[:n]) != "ell" {
		t.Fatalf("Pread = %q, %v", buf[:n], errno)
	}
	if n, errno := f.Pread(buf, 10); errno != 0 || n != 0 {
		t.Fatalf("Pread past EOF = %d, %v", n, errno)
	}
	if n, errno := f.Pread(nil, 0); errno != 0 || n != 0 {
		t.Fatalf("empty Pread = %d, %v", n, errno)
	}
	if off, errno := f.Seek(0, io.SeekStart); errno != 0 || off != 0 {
		t.Fatalf("Seek = %d, %v", off, errno)
	}
	if _, errno := f.Seek(0, 7); errno != experimentalsys.EINVAL {
		t.Fatalf("Seek bad whence = %v", errno)
	}
	if _, errno := f.Seek(-1, io.SeekStart); errno != experimentalsys.EINVAL {
		t.Fatalf("Seek negative = %v", errno)
	}
	if n, errno := f.Write([]byte("HE")); errno != 0 || n != 2 {
		t.Fatalf("Write = %d, %v", n, errno)
	}
	if n, errno := f.Write(nil); errno != 0 || n != 0 {
		t.Fatalf("empty Write = %d, %v", n, errno)
	}
	if n, errno := f.Pwrite([]byte("LO"), 3); errno != 0 || n != 2 {
		t.Fatalf("Pwrite = %d, %v", n, errno)
	}
	if n, errno := f.Pwrite(nil, 0); errno != 0 || n != 0 {
		t.Fatalf("empty Pwrite = %d, %v", n, errno)
	}
	if errno := f.Truncate(-1); errno != experimentalsys.EINVAL {
		t.Fatalf("Truncate(-1) = %v", errno)
	}
	if errno := f.Truncate(4); errno != 0 {
		t.Fatal(errno)
	}
	if errno := f.Sync(); errno != 0 {
		t.Fatal(errno)
	}
	if errno := f.Datasync(); errno != 0 {
		t.Fatal(errno)
	}
	if data, _ := os.ReadFile(filepath.Join(work, "f")); string(data) != "HElL" {
		t.Fatalf("file = %q; want HElL", data)
	}
	if _, errno := f.Readdir(1); errno != experimentalsys.ENOTDIR {
		t.Fatalf("Readdir on a file = %v; want ENOTDIR", errno)
	}

	// Times through the descriptor: both, one omitted, none.
	when := time.Date(2004, 5, 6, 7, 8, 9, 0, time.UTC).UnixNano()
	for _, ts := range [][2]int64{{when, when}, {experimentalsys.UTIME_OMIT, when}, {when, experimentalsys.UTIME_OMIT}, {experimentalsys.UTIME_OMIT, experimentalsys.UTIME_OMIT}} {
		if errno := f.Utimens(ts[0], ts[1]); errno != 0 {
			t.Fatalf("Utimens(%v): %v", ts, errno)
		}
	}
	if fi, _ := os.Stat(filepath.Join(work, "f")); !fi.ModTime().Equal(time.Unix(0, when)) {
		t.Fatalf("mtime = %v", fi.ModTime())
	}

	if f.IsNonblock() {
		t.Fatal("new file is non-blocking")
	}
	if errno := f.SetNonblock(true); errno != 0 || !f.IsNonblock() {
		t.Fatalf("SetNonblock(true) = %v", errno)
	}
	if errno := f.SetNonblock(false); errno != 0 || f.IsNonblock() {
		t.Fatalf("SetNonblock(false) = %v", errno)
	}
	if _, errno := f.Poll(experimentalsys.POLLIN, 0); errno != experimentalsys.ENOSYS {
		t.Fatalf("Poll = %v", errno)
	}

	if errno := f.Close(); errno != 0 {
		t.Fatal(errno)
	}
	if errno := f.Close(); errno != 0 {
		t.Fatalf("second Close = %v", errno)
	}
	for name, errno := range map[string]experimentalsys.Errno{
		"Stat":        func() experimentalsys.Errno { _, e := f.Stat(); return e }(),
		"Read":        func() experimentalsys.Errno { _, e := f.Read(buf); return e }(),
		"Write":       func() experimentalsys.Errno { _, e := f.Write(buf); return e }(),
		"Readdir":     func() experimentalsys.Errno { _, e := f.Readdir(1); return e }(),
		"Sync":        f.Sync(),
		"Datasync":    f.Datasync(),
		"Utimens":     f.Utimens(0, 0),
		"SetAppend":   f.SetAppend(true),
		"SetNonblock": f.SetNonblock(true),
	} {
		if errno != experimentalsys.EBADF {
			t.Errorf("%s after Close = %v; want EBADF", name, errno)
		}
	}
}

func TestConfinedFileSetAppend(t *testing.T) {
	work, _ := confinedTree(t)
	c := newTestFS(t, work, false)
	f := openTestFile(t, c, "f", experimentalsys.O_WRONLY)
	if f.IsAppend() {
		t.Fatal("opened without O_APPEND")
	}
	if errno := f.SetAppend(false); errno != 0 {
		t.Fatalf("no-op SetAppend: %v", errno)
	}
	if errno := f.SetAppend(true); errno != 0 || !f.IsAppend() {
		t.Fatalf("SetAppend(true) = %v", errno)
	}
	if _, errno := f.Write([]byte("!")); errno != 0 {
		t.Fatal(errno)
	}
	if data, _ := os.ReadFile(filepath.Join(work, "f")); string(data) != "hello!" {
		t.Fatalf("append wrote %q", data)
	}

	// The reopen must find the same file: if the name now points at another
	// one, the descriptor stays and the call fails.
	mustDo(t, os.Rename(filepath.Join(work, "f"), filepath.Join(work, "f.moved")))
	mustDo(t, os.WriteFile(filepath.Join(work, "f"), []byte("other"), 0o644))
	if errno := f.SetAppend(false); errno != experimentalsys.ENOENT {
		t.Fatalf("SetAppend after a swap = %v; want ENOENT", errno)
	}
	if !f.IsAppend() {
		t.Fatal("a failed SetAppend changed the mode")
	}
	mustDo(t, os.Remove(filepath.Join(work, "f")))
	if errno := f.SetAppend(false); errno != experimentalsys.ENOENT {
		t.Fatalf("SetAppend after removal = %v; want ENOENT", errno)
	}
	mustDo(t, c.Close())
	if errno := f.SetAppend(false); errno != experimentalsys.EBADF {
		t.Fatalf("SetAppend on a closed mount = %v; want EBADF", errno)
	}
	// The open descriptor outlives the mount's directory handle.
	if _, errno := f.Write([]byte("?")); errno != 0 {
		t.Fatalf("write after the mount closed: %v", errno)
	}

	dirFS := newTestFS(t, work, false)
	d := openTestFile(t, dirFS, "d", experimentalsys.O_RDONLY)
	if errno := d.SetAppend(true); errno != 0 {
		t.Fatalf("SetAppend on a directory: %v", errno)
	}
}

func TestConfinedFileReaddir(t *testing.T) {
	work, _ := confinedTree(t)
	c := newTestFS(t, work, false)
	d := openTestFile(t, c, "d", experimentalsys.O_RDONLY|experimentalsys.O_DIRECTORY)
	if dir, errno := d.IsDir(); errno != 0 || !dir {
		t.Fatalf("IsDir = %v, %v", dir, errno)
	}
	ents, errno := d.Readdir(-1)
	if errno != 0 || len(ents) != 1 || ents[0].Name != "g" || ents[0].Ino == 0 {
		t.Fatalf("Readdir = %+v, %v", ents, errno)
	}
	if ents, errno = d.Readdir(1); errno != 0 || len(ents) != 0 {
		t.Fatalf("Readdir at end = %+v, %v", ents, errno)
	}
	// A rewind lists entries made since the directory was opened.
	mustDo(t, os.WriteFile(filepath.Join(work, "d", "h"), nil, 0o644))
	if _, errno := d.Seek(0, io.SeekStart); errno != 0 {
		t.Fatal(errno)
	}
	if ents, errno = d.Readdir(-1); errno != 0 || len(ents) != 2 {
		t.Fatalf("Readdir after rewind = %+v, %v", ents, errno)
	}
	buf := make([]byte, 1)
	if _, errno := d.Read(buf); errno != experimentalsys.EISDIR {
		t.Errorf("Read on a directory = %v; want EISDIR", errno)
	}
	if errno := d.Truncate(0); errno != experimentalsys.EISDIR {
		t.Errorf("Truncate on a directory = %v; want EISDIR", errno)
	}

	root := openTestFile(t, c, ".", experimentalsys.O_RDONLY)
	names := map[string]fs.FileMode{}
	ents, errno = root.Readdir(-1)
	if errno != 0 {
		t.Fatal(errno)
	}
	for _, e := range ents {
		names[e.Name] = e.Type
	}
	if names["esc"] != fs.ModeSymlink || names["d"] != fs.ModeDir || names["f"] != 0 {
		t.Fatalf("root listing types = %v", names)
	}
}

func TestConfinedFileReadOnlyMount(t *testing.T) {
	work, _ := confinedTree(t)
	ro := newTestFS(t, work, true)
	f := openTestFile(t, ro, "f", experimentalsys.O_RDONLY)
	for name, errno := range map[string]experimentalsys.Errno{
		"Write":    func() experimentalsys.Errno { _, e := f.Write([]byte("x")); return e }(),
		"Pwrite":   func() experimentalsys.Errno { _, e := f.Pwrite([]byte("x"), 0); return e }(),
		"Truncate": f.Truncate(0),
		"Utimens":  f.Utimens(0, 0),
	} {
		if errno != experimentalsys.EBADF {
			t.Errorf("read-only %s = %v; want EBADF", name, errno)
		}
	}
	d := openTestFile(t, ro, "d", experimentalsys.O_RDONLY)
	if _, errno := d.Write([]byte("x")); errno != experimentalsys.EISDIR {
		t.Errorf("read-only Write on a directory = %v; want EISDIR", errno)
	}
	if data, _ := os.ReadFile(filepath.Join(work, "f")); string(data) != "hello" {
		t.Fatalf("read-only mount changed f to %q", data)
	}
}

func TestConfinedFileErrorsOnBadDescriptor(t *testing.T) {
	work, _ := confinedTree(t)
	c := newTestFS(t, work, false)
	f := openTestFile(t, c, "f", experimentalsys.O_RDONLY)
	// Close the os.File behind the wrapper's back: every call that reaches
	// the descriptor reports it instead of acting on a reused number.
	mustDo(t, f.file.Close())
	if _, errno := f.Stat(); errno != experimentalsys.EBADF {
		t.Errorf("Stat = %v; want EBADF", errno)
	}
	if errno := f.SetNonblock(true); errno == 0 {
		t.Error("SetNonblock on a closed descriptor succeeded")
	}
	if errno := f.Utimens(0, 0); errno == 0 {
		t.Error("Utimens on a closed descriptor succeeded")
	}
	if errno := f.Datasync(); errno == 0 {
		t.Error("Datasync on a closed descriptor succeeded")
	}
	if errno := f.SetAppend(true); errno == 0 {
		t.Error("SetAppend on a closed descriptor succeeded")
	}
	if _, errno := f.Readdir(1); errno == 0 {
		t.Error("Readdir on a closed descriptor succeeded")
	}
}

// BenchmarkPreopenPathCalls compares a stat and an open+close three
// directories deep through wazero's DirFS and through confinedFS, which walks
// each component with openat instead of letting the kernel resolve the path
// in one call.
func BenchmarkPreopenPathCalls(b *testing.B) {
	dir := b.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "a", "b", "c"), 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "b", "c", "f"), []byte("x"), 0o644); err != nil {
		b.Fatal(err)
	}
	confined := newConfinedFS(dir, false)
	b.Cleanup(func() { _ = confined.Close() })
	for name, fsys := range map[string]experimentalsys.FS{"dirfs": sysfs.DirFS(dir), "confined": confined} {
		b.Run(name+"/stat", func(b *testing.B) {
			for b.Loop() {
				if _, errno := fsys.Stat("a/b/c/f"); errno != 0 {
					b.Fatal(errno)
				}
			}
		})
		b.Run(name+"/open", func(b *testing.B) {
			for b.Loop() {
				f, errno := fsys.OpenFile("a/b/c/f", experimentalsys.O_RDONLY, 0)
				if errno != 0 {
					b.Fatal(errno)
				}
				_ = f.Close()
			}
		})
	}
}

// The mounts' directory handles go when the module goes: through wazero's
// close notifier on Close, or straight away when instantiation fails.
func TestInstantiateReleasingReleasesMounts(t *testing.T) {
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	t.Cleanup(func() { _ = r.Close(ctx) })
	bin, err := os.ReadFile(wasmmod.WriteMinimalWasm(t, t.TempDir(), "minimal.wasm"))
	mustDo(t, err)
	compiled, err := r.CompileModule(ctx, bin)
	mustDo(t, err)

	released := 0
	mod, err := instantiateReleasing(ctx, r, compiled, wazero.NewModuleConfig().WithName("a"), wazero.NewFSConfig(), func() { released++ })
	mustDo(t, err)
	if released != 0 {
		t.Fatalf("released %d times while the module is live", released)
	}
	mustDo(t, mod.Close(ctx))
	mustDo(t, mod.Close(ctx))
	if released != 1 {
		t.Fatalf("released %d times after Close; want 1", released)
	}

	_, err = instantiateReleasing(ctx, r, compiled, wazero.NewModuleConfig().WithName("b"), wazero.NewFSConfig(), func() {})
	mustDo(t, err)
	failed := 0
	if _, err := instantiateReleasing(ctx, r, compiled, wazero.NewModuleConfig().WithName("b"), wazero.NewFSConfig(), func() { failed++ }); err == nil {
		t.Fatal("a duplicate module name instantiated")
	}
	if failed != 1 {
		t.Fatalf("a failed instantiation released %d times; want 1", failed)
	}

	// No preopens: nothing to mount, nothing to release.
	none := 0
	mod, err = instantiateReleasing(ctx, r, compiled, wazero.NewModuleConfig().WithName("c"), nil, func() { none++ })
	mustDo(t, err)
	mustDo(t, mod.Close(ctx))
	if none != 0 {
		t.Fatalf("released %d times with no mounts", none)
	}
}

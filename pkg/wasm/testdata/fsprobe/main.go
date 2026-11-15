//go:build wasip1

// Command fsprobe is the AerolVM wasip1 file-system test guest. It runs the
// file operations named on its command line against its directory pre-opens
// and prints one line per operation, so a host test can check exactly which
// calls the mount allowed:
//
//	<op> ok [<result>]
//	<op> err <ERRNO> <message>
//
// Operations are separated by a ";" argument, for example:
//
//	fsprobe write /work/a.txt hi ";" read /work/a.txt
package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
)

func main() {
	var op []string
	for _, arg := range append(os.Args[1:], ";") {
		if arg != ";" {
			op = append(op, arg)
			continue
		}
		if len(op) > 0 {
			run(op)
		}
		op = nil
	}
}

func run(op []string) {
	result, err := do(op)
	if err != nil {
		fmt.Printf("%s err %s %v\n", op[0], errnoName(err), err)
		return
	}
	fmt.Printf("%s ok %s\n", op[0], result)
}

func arg(op []string, i int) string {
	if i < len(op) {
		return op[i]
	}
	return ""
}

func do(op []string) (string, error) {
	a, b := arg(op, 1), arg(op, 2)
	switch op[0] {
	case "read":
		data, err := os.ReadFile(a)
		return strings.TrimSpace(string(data)), err
	case "write":
		return "", os.WriteFile(a, []byte(b), 0o644)
	case "append":
		f, err := os.OpenFile(a, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
		if err != nil {
			return "", err
		}
		_, err = f.WriteString(b)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return "", err
	case "truncate":
		return "", os.Truncate(a, 0)
	case "mkdir":
		return "", os.Mkdir(a, 0o755)
	case "rmdir":
		return "", syscall.Rmdir(a)
	case "unlink":
		return "", syscall.Unlink(a)
	case "rename":
		// syscall, not os.Rename: os refuses to replace a directory itself,
		// before path_rename is ever called.
		return "", syscall.Rename(a, b)
	case "symlink":
		return "", os.Symlink(a, b)
	case "link":
		return "", os.Link(a, b)
	case "readlink":
		return os.Readlink(a)
	case "stat", "lstat":
		stat := os.Stat
		if op[0] == "lstat" {
			stat = os.Lstat
		}
		fi, err := stat(a)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s size=%d", fi.Mode().Type(), fi.Size()), nil
	case "readdir":
		entries, err := os.ReadDir(a)
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		return strings.Join(names, ","), err
	case "chtimes":
		t := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
		return "", os.Chtimes(a, t, t)
	case "futimes":
		// fd_filestat_set_times on an open descriptor.
		f, err := os.OpenFile(a, os.O_WRONLY, 0)
		if err != nil {
			return "", err
		}
		defer f.Close()
		ns := uint64(time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC).UnixNano())
		const atim, mtim = 1, 4 // __WASI_FSTFLAGS_ATIM, __WASI_FSTFLAGS_MTIM
		if errno := fdFilestatSetTimes(int32(f.Fd()), ns, ns, atim|mtim); errno != 0 {
			return "", syscall.Errno(errno)
		}
		return "", nil
	case "openexcl":
		f, err := os.OpenFile(a, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return "", err
		}
		return "", f.Close()
	}
	return "", fmt.Errorf("unknown op %q", op[0])
}

// The Go standard library has no futimes on wasip1; this is the WASI call it
// would make.
//
//go:wasmimport wasi_snapshot_preview1 fd_filestat_set_times
func fdFilestatSetTimes(fd int32, atim, mtim uint64, fstflags uint32) uint32

func errnoName(err error) string {
	for _, e := range []struct {
		errno syscall.Errno
		name  string
	}{
		{syscall.EPERM, "EPERM"},
		{syscall.EACCES, "EACCES"},
		{syscall.ENOTCAPABLE, "ENOTCAPABLE"},
		{syscall.ENOENT, "ENOENT"},
		{syscall.EEXIST, "EEXIST"},
		{syscall.ELOOP, "ELOOP"},
		{syscall.ENOTDIR, "ENOTDIR"},
		{syscall.EISDIR, "EISDIR"},
		{syscall.ENOTEMPTY, "ENOTEMPTY"},
		{syscall.EROFS, "EROFS"},
		{syscall.EBADF, "EBADF"},
		{syscall.EXDEV, "EXDEV"},
		{syscall.ENOSYS, "ENOSYS"},
		{syscall.EINVAL, "EINVAL"},
	} {
		if errors.Is(err, e.errno) {
			return e.name
		}
	}
	return "E?"
}

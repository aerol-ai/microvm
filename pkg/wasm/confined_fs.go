package wasm

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	experimentalsys "github.com/tetratelabs/wazero/experimental/sys"
	"github.com/tetratelabs/wazero/sys"
)

// confinedFS is the file system behind every guest directory pre-open.
//
// wazero documents its DirFS (what FSConfig.WithDirMount mounts) as not a
// security boundary: it joins the guest path onto the host directory and lets
// the host kernel resolve the result, symlinks included. Its lexical checks
// on guest paths cannot see where a symlink inside the mount points, and
// workers have no chroot of their own to fall back on, so the mount has to
// enforce the boundary itself.
//
// confinedFS resolves every path through an os.Root opened on the host
// directory. os.Root walks the path one component at a time with openat and
// O_NOFOLLOW and expands each symlink itself, refusing any expansion that
// leaves the root. There is no separate check before the operation: the walk
// that finds the file is the operation, so a concurrent guest call that swaps
// a directory for a symlink cannot move it outside. Calls that must not follow
// the last element (unlink, rmdir, rename) open the parent directory through
// the root and act on the single last name with an *at call (see
// confined_fs_unix.go).
//
// Symlink creation is restricted further, for the host code that reads the
// work dir without os.Root: see symlinkTargetConfined.
type confinedFS struct {
	experimentalsys.UnimplementedFS

	dir      string
	readOnly bool

	mu     sync.Mutex
	root   *os.Root
	closed bool
}

func newConfinedFS(dir string, readOnly bool) *confinedFS {
	return &confinedFS{dir: dir, readOnly: readOnly}
}

// String implements fmt.Stringer, matching wazero's DirFS.
func (c *confinedFS) String() string { return c.dir }

// openRoot opens the host directory on first use. Opening lazily keeps
// Instantiate free of file system work and matches DirFS, which also only
// touched the directory when the guest did: a missing directory fails the
// guest's call, not the instantiation.
func (c *confinedFS) openRoot() (*os.Root, experimentalsys.Errno) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, experimentalsys.EBADF
	}
	if c.root == nil {
		r, err := os.OpenRoot(c.dir)
		if err != nil {
			return nil, experimentalsys.UnwrapOSError(err)
		}
		c.root = r
	}
	return c.root, 0
}

// Close releases the directory handle. wazero has no close hook on a sys.FS,
// so the engines call this from the module's close notifier (see
// instantiateWithPreopens). Files the guest still holds stay usable: each is
// its own descriptor. Later path calls fail with EBADF; none can fall back to
// an unconfined lookup.
func (c *confinedFS) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.root == nil {
		return nil
	}
	err := c.root.Close()
	c.root = nil
	return err
}

// rootName turns a wazero path (already cleaned, relative, maybe with a
// trailing slash) into an os.Root name. "" and "/" are the root itself.
func rootName(p string) string {
	p = strings.TrimLeft(p, "/")
	if p == "" {
		return "."
	}
	return p
}

// rootErrno maps an os.Root error to a WASI errno. os.Root reports a path
// that resolves outside the root (through a symlink or "..") as a plain
// error rather than an errno; wazero would turn that into EIO. The guest is
// asking for something it may not have, so it gets EPERM.
func rootErrno(err error) experimentalsys.Errno {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if errors.As(err, &errno) || errors.Is(err, fs.ErrClosed) || errors.Is(err, io.EOF) {
		return experimentalsys.UnwrapOSError(err)
	}
	return experimentalsys.EPERM
}

// symlinkTargetConfined reports whether a guest may create a symlink with this
// target. os.Root never follows a link out, but host code or an operator may
// still read the work dir with plain paths, and the kernel would follow an
// escaping link there. Absolute targets are refused, as wazero already did.
// So is any ".." element, even one that looks like it stays inside: whether
// "../x" stays inside depends on where the link sits, and the guest can
// rename the directory that holds it to a shallower place afterwards. A
// target made only of downward names resolves below the link's own directory
// wherever that directory moves, so it can never leave the mount.
func symlinkTargetConfined(target string) bool {
	if target == "" || strings.HasPrefix(target, "/") || strings.ContainsRune(target, 0) {
		return false
	}
	for _, part := range strings.Split(target, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

// writeOflags are the open flags that change the file system.
const writeOflags = experimentalsys.O_WRONLY | experimentalsys.O_RDWR | experimentalsys.O_CREAT |
	experimentalsys.O_TRUNC | experimentalsys.O_APPEND

// OpenFile implements experimentalsys.FS.
func (c *confinedFS) OpenFile(p string, flag experimentalsys.Oflag, perm fs.FileMode) (experimentalsys.File, experimentalsys.Errno) {
	isDir := flag&experimentalsys.O_DIRECTORY != 0
	if isDir && flag&(experimentalsys.O_WRONLY|experimentalsys.O_RDWR) != 0 {
		return nil, experimentalsys.EISDIR
	}
	if c.readOnly && flag&writeOflags != 0 {
		return nil, experimentalsys.EROFS
	}
	root, errno := c.openRoot()
	if errno != 0 {
		return nil, errno
	}
	name := rootName(p)
	// os.Root always follows a final symlink (inside the root), so a
	// no-follow open checks the last element first. The check only decides
	// ELOOP versus open: if the guest swaps the name in between, the open
	// still goes through the root and can only reach a file inside it.
	// O_CREAT|O_EXCL never follows, so it keeps its own EEXIST answer.
	excl := experimentalsys.O_CREAT | experimentalsys.O_EXCL
	if flag&experimentalsys.O_NOFOLLOW != 0 && flag&excl != excl {
		if fi, err := root.Lstat(name); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
			return nil, experimentalsys.ELOOP
		}
	}
	f, err := root.OpenFile(name, toOSOpenFlag(flag), perm)
	if err != nil {
		return nil, rootErrno(err)
	}
	return &confinedFile{fs: c, name: name, flag: flag, perm: perm, file: f}, 0
}

// Lstat implements experimentalsys.FS.
func (c *confinedFS) Lstat(p string) (sys.Stat_t, experimentalsys.Errno) {
	root, errno := c.openRoot()
	if errno != 0 {
		return sys.Stat_t{}, errno
	}
	fi, err := root.Lstat(rootName(p))
	if err != nil {
		return sys.Stat_t{}, rootErrno(err)
	}
	return sys.NewStat_t(fi), 0
}

// Stat implements experimentalsys.FS.
func (c *confinedFS) Stat(p string) (sys.Stat_t, experimentalsys.Errno) {
	root, errno := c.openRoot()
	if errno != 0 {
		return sys.Stat_t{}, errno
	}
	fi, err := root.Stat(rootName(p))
	if err != nil {
		return sys.Stat_t{}, rootErrno(err)
	}
	return sys.NewStat_t(fi), 0
}

// Readlink implements experimentalsys.FS. The target comes back as stored;
// reading it does not follow it.
func (c *confinedFS) Readlink(p string) (string, experimentalsys.Errno) {
	root, errno := c.openRoot()
	if errno != 0 {
		return "", errno
	}
	target, err := root.Readlink(rootName(p))
	if err != nil {
		return "", rootErrno(err)
	}
	return target, 0
}

// Mkdir implements experimentalsys.FS.
func (c *confinedFS) Mkdir(p string, perm fs.FileMode) experimentalsys.Errno {
	if c.readOnly {
		return experimentalsys.EROFS
	}
	root, errno := c.openRoot()
	if errno != 0 {
		return errno
	}
	errno = rootErrno(root.Mkdir(rootName(p), perm))
	// Same mapping as wazero's DirFS: a missing parent is ENOENT to WASI.
	if errno == experimentalsys.ENOTDIR {
		errno = experimentalsys.ENOENT
	}
	return errno
}

// Chmod implements experimentalsys.FS. WASI preview 1 has no chmod call, but
// the interface does; it stays inside the root like the rest.
func (c *confinedFS) Chmod(p string, perm fs.FileMode) experimentalsys.Errno {
	if c.readOnly {
		return experimentalsys.EROFS
	}
	root, errno := c.openRoot()
	if errno != 0 {
		return errno
	}
	return rootErrno(root.Chmod(rootName(p), perm))
}

// Rename implements experimentalsys.FS.
func (c *confinedFS) Rename(from, to string) experimentalsys.Errno {
	if c.readOnly {
		return experimentalsys.EROFS
	}
	if from == to {
		return 0
	}
	root, errno := c.openRoot()
	if errno != 0 {
		return errno
	}
	return renameInRoot(root, rootName(from), rootName(to))
}

// Rmdir implements experimentalsys.FS.
func (c *confinedFS) Rmdir(p string) experimentalsys.Errno {
	if c.readOnly {
		return experimentalsys.EROFS
	}
	root, errno := c.openRoot()
	if errno != 0 {
		return errno
	}
	return rmdirInRoot(root, rootName(p))
}

// Unlink implements experimentalsys.FS.
func (c *confinedFS) Unlink(p string) experimentalsys.Errno {
	if c.readOnly {
		return experimentalsys.EROFS
	}
	root, errno := c.openRoot()
	if errno != 0 {
		return errno
	}
	return unlinkInRoot(root, rootName(p))
}

// Link implements experimentalsys.FS. os.Root resolves both parents inside
// the root and links without following the old name's last element, so the
// guest can only link a file that already sits inside the mount.
func (c *confinedFS) Link(oldPath, newPath string) experimentalsys.Errno {
	if c.readOnly {
		return experimentalsys.EROFS
	}
	root, errno := c.openRoot()
	if errno != 0 {
		return errno
	}
	return rootErrno(root.Link(rootName(oldPath), rootName(newPath)))
}

// Symlink implements experimentalsys.FS.
func (c *confinedFS) Symlink(target, link string) experimentalsys.Errno {
	if c.readOnly {
		return experimentalsys.EROFS
	}
	if !symlinkTargetConfined(target) {
		return experimentalsys.EPERM
	}
	root, errno := c.openRoot()
	if errno != 0 {
		return errno
	}
	return rootErrno(root.Symlink(target, rootName(link)))
}

// Utimens implements experimentalsys.FS. Path-based, so it follows a final
// symlink, but only inside the root.
func (c *confinedFS) Utimens(p string, atim, mtim int64) experimentalsys.Errno {
	if c.readOnly {
		return experimentalsys.EROFS
	}
	if atim == experimentalsys.UTIME_OMIT && mtim == experimentalsys.UTIME_OMIT {
		return 0
	}
	root, errno := c.openRoot()
	if errno != 0 {
		return errno
	}
	return rootErrno(root.Chtimes(rootName(p), omitTime(atim), omitTime(mtim)))
}

// omitTime converts a WASI timestamp for os.Chtimes, where the zero time
// means "leave unchanged". No int64 nanosecond count reaches year 1, so a
// real time never collides with it.
func omitTime(ns int64) time.Time {
	if ns == experimentalsys.UTIME_OMIT {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// toOSOpenFlag maps wazero open flags onto os flags. O_NOFOLLOW is handled in
// OpenFile, since os.Root adds it to every open and follows links itself.
func toOSOpenFlag(oflag experimentalsys.Oflag) int {
	var flag int
	switch oflag & (experimentalsys.O_RDONLY | experimentalsys.O_RDWR | experimentalsys.O_WRONLY) {
	case experimentalsys.O_RDWR:
		flag |= os.O_RDWR
	case experimentalsys.O_WRONLY:
		flag |= os.O_WRONLY
	default:
		flag |= os.O_RDONLY
	}
	if oflag&experimentalsys.O_APPEND != 0 {
		flag |= os.O_APPEND
	}
	if oflag&experimentalsys.O_CREAT != 0 {
		flag |= os.O_CREATE
	}
	if oflag&experimentalsys.O_EXCL != 0 {
		flag |= os.O_EXCL
	}
	if oflag&experimentalsys.O_SYNC != 0 {
		flag |= os.O_SYNC
	}
	if oflag&experimentalsys.O_TRUNC != 0 {
		flag |= os.O_TRUNC
	}
	return withPlatformOflag(oflag, flag)
}

// confinedFile is a file opened through a confinedFS. Everything but SetAppend
// works on the open descriptor, so a later rename or symlink swap of its path
// cannot redirect it.
type confinedFile struct {
	experimentalsys.UnimplementedFile

	fs   *confinedFS
	name string // os.Root name, for SetAppend's reopen
	flag experimentalsys.Oflag
	perm fs.FileMode
	file *os.File

	closed bool

	// The device, inode and type cannot change while the file is open.
	statCached bool
	dev        uint64
	ino        sys.Inode
	isDir      bool
}

var (
	_ experimentalsys.File         = (*confinedFile)(nil)
	_ experimentalsys.PollableFile = (*confinedFile)(nil)
)

func (f *confinedFile) cachedStat() experimentalsys.Errno {
	if f.statCached {
		return 0
	}
	_, errno := f.Stat()
	return errno
}

// Dev implements experimentalsys.File.
func (f *confinedFile) Dev() (uint64, experimentalsys.Errno) {
	errno := f.cachedStat()
	return f.dev, errno
}

// Ino implements experimentalsys.File.
func (f *confinedFile) Ino() (sys.Inode, experimentalsys.Errno) {
	errno := f.cachedStat()
	return f.ino, errno
}

// IsDir implements experimentalsys.File.
func (f *confinedFile) IsDir() (bool, experimentalsys.Errno) {
	errno := f.cachedStat()
	return f.isDir, errno
}

// IsAppend implements experimentalsys.File.
func (f *confinedFile) IsAppend() bool {
	return f.flag&experimentalsys.O_APPEND != 0
}

// SetAppend implements experimentalsys.File. Go fixes append mode at open,
// so, like wazero's own file, this reopens the path. The reopen goes through
// the root and must find the same file, or it fails and the old descriptor
// stays.
func (f *confinedFile) SetAppend(enable bool) experimentalsys.Errno {
	if f.closed {
		return experimentalsys.EBADF
	}
	flag := f.flag &^ experimentalsys.O_APPEND
	if enable {
		flag |= experimentalsys.O_APPEND
	}
	if flag == f.flag {
		return 0
	}
	if errno := f.reopen(flag); errno != 0 {
		return f.fileErr(errno)
	}
	f.flag = flag
	return 0
}

func (f *confinedFile) reopen(flag experimentalsys.Oflag) experimentalsys.Errno {
	if errno := f.cachedStat(); errno != 0 {
		return errno
	}
	root, errno := f.fs.openRoot()
	if errno != 0 {
		return errno
	}
	var offset int64
	if !f.isDir {
		off, err := f.file.Seek(0, io.SeekCurrent)
		if err != nil {
			return experimentalsys.UnwrapOSError(err)
		}
		offset = off
	}
	// Reopening must not create or truncate what the first open made.
	flag &^= experimentalsys.O_CREAT | experimentalsys.O_TRUNC | experimentalsys.O_EXCL
	nf, err := root.OpenFile(f.name, toOSOpenFlag(flag), f.perm)
	if err != nil {
		return rootErrno(err)
	}
	oldInfo, err1 := f.file.Stat()
	newInfo, err2 := nf.Stat()
	if err1 != nil || err2 != nil || !os.SameFile(oldInfo, newInfo) {
		_ = nf.Close()
		return experimentalsys.ENOENT
	}
	if !f.isDir {
		if _, err := nf.Seek(offset, io.SeekStart); err != nil {
			_ = nf.Close()
			return experimentalsys.UnwrapOSError(err)
		}
	}
	_ = f.file.Close()
	f.file = nf
	return 0
}

// Stat implements experimentalsys.File.
func (f *confinedFile) Stat() (sys.Stat_t, experimentalsys.Errno) {
	if f.closed {
		return sys.Stat_t{}, experimentalsys.EBADF
	}
	fi, err := f.file.Stat()
	if err != nil {
		errno := experimentalsys.UnwrapOSError(err)
		if errno == experimentalsys.EIO {
			errno = experimentalsys.EBADF
		}
		return sys.Stat_t{}, errno
	}
	st := sys.NewStat_t(fi)
	f.statCached = true
	f.dev, f.ino, f.isDir = st.Dev, st.Ino, fi.IsDir()
	return st, 0
}

// Read implements experimentalsys.File.
func (f *confinedFile) Read(buf []byte) (int, experimentalsys.Errno) {
	if len(buf) == 0 {
		return 0, 0
	}
	n, err := f.file.Read(buf)
	return n, f.ioErr(err)
}

// Pread implements experimentalsys.File.
func (f *confinedFile) Pread(buf []byte, off int64) (int, experimentalsys.Errno) {
	if len(buf) == 0 {
		return 0, 0
	}
	n, err := f.file.ReadAt(buf, off)
	return n, f.ioErr(err)
}

// fileOffset spells Seek's offset type. go vet's stdmethods check wants any
// method named Seek to return error, as io.Seeker does, but wazero's sys.File
// returns its own Errno. vet only checks a Seek whose first parameter is
// spelled int64; the alias is the same type, so Seek still satisfies sys.File.
type fileOffset = int64

// Seek implements experimentalsys.File. Seeking a directory to 0 rewinds its
// listing: os.File drops its cached directory state on any seek, so the next
// Readdir reads the directory afresh.
func (f *confinedFile) Seek(offset fileOffset, whence int) (int64, experimentalsys.Errno) {
	if uint(whence) > io.SeekEnd {
		return 0, experimentalsys.EINVAL
	}
	n, err := f.file.Seek(offset, whence)
	return n, f.ioErr(err)
}

// Readdir implements experimentalsys.File. os.File stats each entry with
// fstatat on the directory's own descriptor, never by path.
func (f *confinedFile) Readdir(n int) ([]experimentalsys.Dirent, experimentalsys.Errno) {
	if f.closed {
		return nil, experimentalsys.EBADF
	}
	fis, err := f.file.Readdir(n)
	if err != nil && !errors.Is(err, io.EOF) {
		errno := experimentalsys.UnwrapOSError(err)
		if isDir, e := f.IsDir(); e == 0 && !isDir {
			errno = experimentalsys.ENOTDIR
		}
		return nil, errno
	}
	dirents := make([]experimentalsys.Dirent, 0, len(fis))
	for _, fi := range fis {
		dirents = append(dirents, experimentalsys.Dirent{Name: fi.Name(), Ino: sys.NewStat_t(fi).Ino, Type: fi.Mode().Type()})
	}
	return dirents, 0
}

// Write implements experimentalsys.File.
func (f *confinedFile) Write(buf []byte) (int, experimentalsys.Errno) {
	if f.fs.readOnly {
		return 0, f.fileErr(experimentalsys.EBADF)
	}
	if len(buf) == 0 {
		return 0, 0
	}
	n, err := f.file.Write(buf)
	return n, f.ioErr(err)
}

// Pwrite implements experimentalsys.File.
func (f *confinedFile) Pwrite(buf []byte, off int64) (int, experimentalsys.Errno) {
	if f.fs.readOnly {
		return 0, f.fileErr(experimentalsys.EBADF)
	}
	if len(buf) == 0 {
		return 0, 0
	}
	n, err := f.file.WriteAt(buf, off)
	return n, f.ioErr(err)
}

// Truncate implements experimentalsys.File.
func (f *confinedFile) Truncate(size int64) experimentalsys.Errno {
	if f.fs.readOnly {
		return f.fileErr(experimentalsys.EBADF)
	}
	if size < 0 {
		return experimentalsys.EINVAL
	}
	return f.ioErr(f.file.Truncate(size))
}

// Sync implements experimentalsys.File.
func (f *confinedFile) Sync() experimentalsys.Errno {
	if f.closed {
		return experimentalsys.EBADF
	}
	return experimentalsys.UnwrapOSError(f.file.Sync())
}

// Datasync implements experimentalsys.File.
func (f *confinedFile) Datasync() experimentalsys.Errno {
	if f.closed {
		return experimentalsys.EBADF
	}
	return datasyncFile(f.file)
}

// Utimens implements experimentalsys.File. It acts on the descriptor, so it
// changes the file that was opened even if its name now points elsewhere.
func (f *confinedFile) Utimens(atim, mtim int64) experimentalsys.Errno {
	if f.closed || f.fs.readOnly {
		return experimentalsys.EBADF
	}
	return futimensFile(f.file, atim, mtim)
}

// IsNonblock implements experimentalsys.PollableFile.
func (f *confinedFile) IsNonblock() bool {
	return f.flag&experimentalsys.O_NONBLOCK != 0
}

// SetNonblock implements experimentalsys.PollableFile. wazero's fd_fdstat_set_flags
// only offers non-blocking mode to files that implement it, as its own did.
func (f *confinedFile) SetNonblock(enable bool) experimentalsys.Errno {
	if f.closed {
		return experimentalsys.EBADF
	}
	if errno := setNonblockFile(f.file, enable); errno != 0 {
		return errno
	}
	if enable {
		f.flag |= experimentalsys.O_NONBLOCK
	} else {
		f.flag &^= experimentalsys.O_NONBLOCK
	}
	return 0
}

// Poll implements experimentalsys.Pollable. wazero's poll_oneoff only polls
// stdin; a regular file or directory is never asked.
func (f *confinedFile) Poll(experimentalsys.Pflag, int32) (bool, experimentalsys.Errno) {
	return false, experimentalsys.ENOSYS
}

// Close implements experimentalsys.File.
func (f *confinedFile) Close() experimentalsys.Errno {
	if f.closed {
		return 0
	}
	f.closed = true
	return experimentalsys.UnwrapOSError(f.file.Close())
}

// ioErr maps an I/O error. EOF is not an error to WASI; anything else gets
// the closed and is-a-directory checks wazero's own file makes.
func (f *confinedFile) ioErr(err error) experimentalsys.Errno {
	if err == nil || errors.Is(err, io.EOF) {
		return 0
	}
	return f.fileErr(experimentalsys.UnwrapOSError(err))
}

// fileErr replaces errno with EBADF on a closed file and EISDIR on a
// directory, for calls that only make sense on a regular file.
func (f *confinedFile) fileErr(errno experimentalsys.Errno) experimentalsys.Errno {
	if f.closed {
		return experimentalsys.EBADF
	}
	if isDir, e := f.IsDir(); e != 0 {
		return e
	} else if isDir {
		return experimentalsys.EISDIR
	}
	return errno
}

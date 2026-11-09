//go:build linux

package main

// watch_linux.go is the inotify half of the file watcher (watch.go has the
// rest). It uses golang.org/x/sys/unix, already a dependency, rather than
// fsnotify (plan F5, eng review). inotify watches one folder per watch and
// does not recurse, so recursion is done here: watch every folder under the
// root at start, watch each new folder as it appears, and drop the watches
// of a folder that moves away.

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

var newDirWatcherFn dirWatcherFactory = newInotifyWatcher

// inotifyMask is what every folder watch asks for. IN_ONLYDIR refuses a path
// that turned into a file between the readdir and the add. IN_EXCL_UNLINK
// skips writes to a file that is already deleted but still open (a log a
// process keeps writing after rm), which nobody watching the folder can see.
const inotifyMask = unix.IN_CREATE | unix.IN_MODIFY | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO |
	unix.IN_ATTRIB | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_ONLYDIR | unix.IN_EXCL_UNLINK

// inotifyReadBuffer holds many events per read; one event is at most
// SizeofInotifyEvent + NAME_MAX + 1 bytes.
const inotifyReadBuffer = 64 * 1024

type inotifyWatcher struct {
	root      string
	recursive bool
	batch     *watchBatch
	budget    *watchBudget
	maxDirs   int

	// file owns the inotify fd. It is non-blocking, so os.File parks Read on
	// the runtime poller and Close wakes it: closing the socket's watch never
	// leaves a goroutine stuck in read(2). The fd is only ever used through
	// conn.Control, never file.Fd(), which would switch it back to blocking.
	file *os.File
	conn syscall.RawConn

	// The maps are touched by the constructor, then only by the reader
	// goroutine, then by Close once the reader is gone: no lock needed.
	byWD   map[int32]string
	byPath map[string]int32
	rootWD int32

	done      chan struct{}
	reason    string
	closing   atomic.Bool
	closeOnce sync.Once
}

func newInotifyWatcher(root string, recursive bool, batch *watchBatch, budget *watchBudget, maxDirs int) (dirWatcher, error) {
	w, err := openInotifyWatcher(root, recursive, batch, budget, maxDirs)
	if err != nil {
		return nil, err
	}
	go w.read()
	return w, nil
}

// openInotifyWatcher arms the watches but does not start reading; the caller
// starts w.read. Split out so a test can fill the kernel queue first.
func openInotifyWatcher(root string, recursive bool, batch *watchBatch, budget *watchBudget, maxDirs int) (*inotifyWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "inotify")
	conn, err := file.SyscallConn()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	w := &inotifyWatcher{
		root:      root,
		recursive: recursive,
		batch:     batch,
		budget:    budget,
		maxDirs:   maxDirs,
		file:      file,
		conn:      conn,
		byWD:      map[int32]string{},
		byPath:    map[string]int32{},
		done:      make(chan struct{}),
	}
	// The root may be a symlink to a folder, so it is followed; nothing
	// under it is (a link back up the tree would loop forever).
	wd, err := w.addWatch(root, true)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	w.rootWD = wd
	if recursive {
		// Folders created while this walk runs are caught twice at worst:
		// by the walk and by their parent's IN_CREATE.
		w.watchTree(root, false)
	}
	return w, nil
}

func (w *inotifyWatcher) Done() <-chan struct{} { return w.done }

func (w *inotifyWatcher) Reason() string { return w.reason }

func (w *inotifyWatcher) Close() {
	w.closeOnce.Do(func() {
		w.closing.Store(true)
		// Close waits for any add/rm still inside conn.Control and wakes
		// the parked Read, so the reader returns and done closes.
		_ = w.file.Close()
		<-w.done
		// The kernel dropped every watch with the fd; return their budget.
		w.budget.giveDirs(len(w.byWD))
		clear(w.byWD)
		clear(w.byPath)
	})
}

// addWatch watches one folder, counting it against the stream's and
// toolboxd's caps.
//
// It asks the kernel first and charges the caps only for a watch the kernel
// says is new. One folder is often added twice: under mkdir -p, the scan of
// a new parent watches a subfolder whose own IN_CREATE is still queued.
// Charging first made that second add take a slot just to give it back, so
// for a moment the shared budget counted the folder twice, and at a cap a
// folder watched all along was refused and reported as a watch_limit
// overflow.
func (w *inotifyWatcher) addWatch(path string, follow bool) (int32, error) {
	mask := uint32(inotifyMask)
	if !follow {
		mask |= unix.IN_DONT_FOLLOW
	}
	var wd int
	var addErr error
	if err := w.conn.Control(func(fd uintptr) {
		wd, addErr = unix.InotifyAddWatch(int(fd), path, mask)
	}); err != nil {
		addErr = err
	}
	if addErr != nil {
		if errors.Is(addErr, unix.ENOSPC) {
			// fs.inotify.max_user_watches: the kernel's own cap.
			return 0, errWatchLimit
		}
		return 0, addErr
	}
	id := int32(wd)
	if old, ok := w.byWD[id]; ok {
		// The kernel gives one watch per folder, so this folder is already
		// watched and paid for: by this path, or by another one (a bind
		// mount). Keep the newer path.
		delete(w.byPath, old)
	} else if len(w.byWD) >= w.maxDirs || !w.budget.takeDir() {
		// Over a cap: drop the watch just made. Its events, IN_IGNORED
		// included, name a wd never recorded, so handleEvent skips them.
		_ = w.conn.Control(func(fd uintptr) {
			_, _ = unix.InotifyRmWatch(int(fd), uint32(wd))
		})
		return 0, errWatchLimit
	}
	w.byWD[id] = path
	w.byPath[path] = id
	return id, nil
}

// watchTree watches every folder below dir that is not watched yet. With
// synthetic set it also reports a create for every entry it finds: a folder
// that just appeared may already hold files made before its watch was in
// place (mkdir -p a/b && touch a/b/f), and without these the client would
// never hear of them. On the start walk and the rescan after an overflow it
// reports nothing; those entries are not new.
func (w *inotifyWatcher) watchTree(dir string, synthetic bool) {
	stack := []string{dir}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		entries, err := os.ReadDir(cur)
		if err != nil {
			// Gone or unreadable: its parent's events say what happened.
			continue
		}
		for _, entry := range entries {
			child := filepath.Join(cur, entry.Name())
			// DirEntry.IsDir is false for a symlink, so links are not followed.
			isDir := entry.IsDir()
			if synthetic {
				w.batch.add(watchEvent{Type: watchEventCreate, Path: child, IsDir: isDir})
			}
			if !isDir {
				continue
			}
			if _, watched := w.byPath[child]; !watched {
				if _, err := w.addWatch(child, false); err != nil {
					if errors.Is(err, errWatchLimit) {
						w.batch.addOverflow(watchOverflowLimit, child)
						return
					}
					continue // vanished, or no longer a folder
				}
			}
			stack = append(stack, child)
		}
	}
}

// unwatchTree drops the watches of path and every folder below it, after
// path moved out from under its parent: inotify watches follow the folder,
// so their events would arrive under paths that no longer exist. If it moved
// somewhere else in the tree, the IN_MOVED_TO that follows watches it again.
func (w *inotifyWatcher) unwatchTree(path string) {
	prefix := path + string(filepath.Separator)
	for wd, p := range w.byWD {
		if wd == w.rootWD || (p != path && !strings.HasPrefix(p, prefix)) {
			continue
		}
		_ = w.conn.Control(func(fd uintptr) {
			_, _ = unix.InotifyRmWatch(int(fd), uint32(wd))
		})
		w.forget(wd)
	}
}

func (w *inotifyWatcher) forget(wd int32) {
	path, ok := w.byWD[wd]
	if !ok {
		return
	}
	delete(w.byWD, wd)
	if w.byPath[path] == wd {
		delete(w.byPath, path)
	}
	w.budget.giveDirs(1)
}

func (w *inotifyWatcher) read() {
	defer close(w.done)
	buf := make([]byte, inotifyReadBuffer)
	for {
		n, err := w.file.Read(buf)
		if err != nil {
			if !w.closing.Load() {
				w.reason = "file watch stopped: " + err.Error()
			}
			return
		}
		if w.handle(buf[:n]) {
			return
		}
	}
}

// handle parses one read's worth of events. It returns true when the watch
// has ended (the root is gone).
func (w *inotifyWatcher) handle(buf []byte) bool {
	for len(buf) >= unix.SizeofInotifyEvent {
		wd := int32(binary.NativeEndian.Uint32(buf[0:4]))
		mask := binary.NativeEndian.Uint32(buf[4:8])
		nameLen := int(binary.NativeEndian.Uint32(buf[12:16]))
		end := unix.SizeofInotifyEvent + nameLen
		if end > len(buf) {
			// The kernel never splits an event across reads.
			return false
		}
		// The name is NUL-padded to an alignment boundary.
		name := strings.TrimRight(string(buf[unix.SizeofInotifyEvent:end]), "\x00")
		buf = buf[end:]
		if w.handleEvent(wd, mask, name) {
			return true
		}
	}
	return false
}

func (w *inotifyWatcher) handleEvent(wd int32, mask uint32, name string) bool {
	if mask&unix.IN_Q_OVERFLOW != 0 {
		if w.recursive {
			// Folders created in the lost events are not watched yet. Rescan
			// before reporting, so a client that re-lists on the overflow
			// finds every folder already watched.
			w.watchTree(w.root, false)
		}
		w.batch.addOverflow(watchOverflowKernel, "")
		return false
	}
	dir, known := w.byWD[wd]
	if mask&unix.IN_IGNORED != 0 {
		// The kernel removed this watch: its folder was deleted, or we
		// removed it in unwatchTree (then it is already forgotten).
		w.forget(wd)
		if wd == w.rootWD && w.reason == "" {
			w.reason = "the watched folder is gone"
			return true
		}
		return false
	}
	if !known {
		// A late event for a watch unwatchTree dropped.
		return false
	}
	isDir := mask&unix.IN_ISDIR != 0
	if name == "" {
		// An event on a watched folder itself. A subfolder's own changes also
		// reach its parent's watch by name, so only the root's count here.
		if wd != w.rootWD {
			return false
		}
		switch {
		case mask&unix.IN_ATTRIB != 0:
			w.batch.add(watchEvent{Type: watchEventChmod, Path: w.root, IsDir: true})
		case mask&unix.IN_DELETE_SELF != 0:
			w.batch.add(watchEvent{Type: watchEventRemove, Path: w.root, IsDir: true})
			w.reason = "the watched folder was removed"
			return true
		case mask&unix.IN_MOVE_SELF != 0:
			w.batch.add(watchEvent{Type: watchEventRename, Path: w.root, IsDir: true})
			w.reason = "the watched folder was moved"
			return true
		case mask&unix.IN_UNMOUNT != 0:
			w.reason = "the filesystem holding the watched folder was unmounted"
			return true
		}
		return false
	}
	path := filepath.Join(dir, name)
	switch {
	case mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0:
		if !isDir || !w.recursive {
			w.batch.add(watchEvent{Type: watchEventCreate, Path: path, IsDir: isDir})
			break
		}
		// Watch first, report second: a client that writes into the new
		// folder as soon as it hears of it is then always seen.
		_, err := w.addWatch(path, false)
		w.batch.add(watchEvent{Type: watchEventCreate, Path: path, IsDir: true})
		if err != nil {
			if errors.Is(err, errWatchLimit) {
				w.batch.addOverflow(watchOverflowLimit, path)
			}
			break
		}
		w.watchTree(path, true)
	case mask&unix.IN_MODIFY != 0:
		w.batch.add(watchEvent{Type: watchEventWrite, Path: path})
	case mask&unix.IN_ATTRIB != 0:
		w.batch.add(watchEvent{Type: watchEventChmod, Path: path, IsDir: isDir})
	case mask&unix.IN_DELETE != 0:
		w.batch.add(watchEvent{Type: watchEventRemove, Path: path, IsDir: isDir})
	case mask&unix.IN_MOVED_FROM != 0:
		// Unwatch before reporting, for the same reason as above.
		if isDir && w.recursive {
			w.unwatchTree(path)
		}
		w.batch.add(watchEvent{Type: watchEventRename, Path: path, IsDir: isDir})
	}
	return false
}

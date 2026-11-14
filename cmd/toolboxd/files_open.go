package main

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// openFile opens path as os.OpenFile does, but never waits on a named pipe.
// A plain open of a FIFO blocks until another process opens its other end:
// a download of one hung until something wrote to it, an upload hung until
// something read it, and each held a toolboxd thread after the caller gave
// up (agent-sandbox fixed the same in v1.0.11, kubernetes-sigs/agent-sandbox
// #2222). O_NONBLOCK makes the open itself return at once; the file's type
// is then checked on the open file, so a pipe put in place after a stat
// cannot slip through. A pipe or a socket is refused with a fileKindError
// (409); anything else goes back to blocking I/O and is returned with its
// FileInfo.
func openFile(path string, flag int, perm fs.FileMode) (*os.File, fs.FileInfo, error) {
	f, err := os.OpenFile(path, flag|syscall.O_NONBLOCK, perm)
	if err != nil {
		// A write-only open of a pipe with no reader, and any open of a
		// socket, fail with ENXIO instead of waiting.
		if errors.Is(err, syscall.ENXIO) {
			if info, statErr := os.Stat(path); statErr == nil && notAFile(info.Mode()) {
				return nil, nil, notAFileError(path, info.Mode())
			}
		}
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if notAFile(info.Mode()) {
		_ = f.Close()
		return nil, nil, notAFileError(path, info.Mode())
	}
	// Reads and writes block again: a device (/dev/null) is still served,
	// and a short read must not come back as EAGAIN.
	if err := syscall.SetNonblock(int(f.Fd()), false); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// notAFile reports a named pipe or a socket: a path whose open or I/O waits
// on another process.
func notAFile(mode fs.FileMode) bool {
	return mode&(fs.ModeNamedPipe|fs.ModeSocket) != 0
}

func notAFileError(path string, mode fs.FileMode) error {
	kind := "a named pipe"
	if mode&fs.ModeSocket != 0 {
		kind = "a socket"
	}
	return &fileKindError{msg: path + " is " + kind + ", not a file: it is not read or written"}
}

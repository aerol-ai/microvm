//go:build linux

package hostproc

import (
	"os"

	"golang.org/x/sys/unix"
)

// openJournalStream connects a new stream to journald for a process
// identified as identifier, ready to be its stdout and stderr. The connect
// does not wait: a journald whose queue is full fails it (EAGAIN) rather
// than hold up the start, and the process then gets /dev/null.
func openJournalStream(identifier string) (*os.File, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: JournalStdoutSocket}); err != nil {
		return fail(err)
	}
	// Write-only, with sd_journal_stream_fd's large send buffer so a burst
	// of lines does not stall the writer on journald (best effort).
	_ = unix.Shutdown(fd, unix.SHUT_RD)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 8<<20)
	// The process gets a blocking stream, as systemd gives a service.
	if err := unix.SetNonblock(fd, false); err != nil {
		return fail(err)
	}
	// A few dozen bytes into an empty send buffer: written at once.
	header := journalHeader(identifier, ownUnit())
	for len(header) > 0 {
		n, err := unix.Write(fd, header)
		if err != nil {
			return fail(err)
		}
		header = header[n:]
	}
	return os.NewFile(uintptr(fd), "journal-stream"), nil
}

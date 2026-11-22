package hostproc

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// A process sandboxd starts that runs tenant code (a WASM worker) must not
// share sandboxd's stdout or stderr when they are a socket. Under systemd
// they are one stream socket to journald, and shutdown(2) acts on the
// socket, not on a descriptor: a process that shut it would fail every
// later log line of sandboxd's with EPIPE. OwnOutput gives such a process
// a journal stream of its own, which sandboxd connects as root before the
// start: the process can shut or stall only its own lines, and they keep
// reaching the journal after sandboxd restarts (the process outlives it).
//
// Output that is not a socket (a pipe in a container, a terminal, a file)
// stays shared: shutdown(2) does not apply to it. The most a process can do
// to a shared pipe is set O_NONBLOCK on it, so that sandboxd's writes fail
// while the pipe is full: lost lines, never a stopped sandboxd. In a pod the
// cgroup's processes write to a log file of their own anyway (SetLogFile).

// JournalStdoutSocket is journald's stream socket (sd_journal_stream_fd).
var JournalStdoutSocket = "/run/systemd/journal/stdout"

// OwnOutput points cmd's stdout and stderr, where they are this process's
// own and a socket, at an output of cmd's own: a new journal stream when
// they are the journal (JOURNAL_STREAM names them), /dev/null for any other
// socket or when the stream cannot be made. Anything else is left as it is.
// It returns the files it opened; the caller closes them once cmd has
// started or failed to (the child has its own copies by then).
func OwnOutput(cmd *exec.Cmd, identifier string) []*os.File {
	var (
		stream *os.File
		opened []*os.File
		failed bool
	)
	pick := func(w io.Writer) io.Writer {
		own, ok := w.(*os.File)
		if !ok || (own != os.Stdout && own != os.Stderr) {
			return w
		}
		socket, journal := outputKind(own)
		if !socket {
			return w
		}
		if journal && stream == nil && !failed {
			f, err := openJournalStream(identifier)
			if err != nil {
				failed = true
			} else {
				stream = f
				opened = append(opened, f)
			}
		}
		if !journal || stream == nil {
			// os/exec gives the process /dev/null.
			return nil
		}
		return stream
	}
	cmd.Stdout = pick(cmd.Stdout)
	cmd.Stderr = pick(cmd.Stderr)
	return opened
}

// outputKind reports whether f is a socket, and whether it is the journal
// stream systemd gave this process (JOURNAL_STREAM is its device and inode,
// as systemd.exec documents for telling the stream from a redirect). It
// asks SO_TYPE first, which fails with ENOTSOCK on anything else without
// asking its file system: every worker start comes here, and an fstat of a
// log file on a network or shared mount can cost a round trip. It reads f
// through Control: Fd would put it into blocking mode.
func outputKind(f *os.File) (socket, journal bool) {
	rc, err := f.SyscallConn()
	if err != nil {
		return false, false
	}
	var (
		st   unix.Stat_t
		serr error
	)
	if err := rc.Control(func(fd uintptr) {
		if _, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE); serr == nil {
			serr = unix.Fstat(int(fd), &st)
		}
	}); err != nil || serr != nil {
		return false, false
	}
	if uint32(st.Mode)&unix.S_IFMT != unix.S_IFSOCK {
		return false, false
	}
	dev, ino, ok := strings.Cut(strings.TrimSpace(os.Getenv("JOURNAL_STREAM")), ":")
	if !ok {
		return true, false
	}
	d, derr := strconv.ParseUint(dev, 10, 64)
	i, ierr := strconv.ParseUint(ino, 10, 64)
	return true, derr == nil && ierr == nil && d == uint64(st.Dev) && i == st.Ino
}

// journalHeader is the stream's first lines, as sd_journal_stream_fd and
// systemd's own service streams write them: identifier, unit, priority
// (info), level prefix (on, as systemd's default), and no forwarding to
// syslog, kmsg or the console. journald takes the unit only from a root
// peer, which sandboxd is; it keeps the lines with sandboxd's unit after
// sandboxd's own process is gone.
func journalHeader(identifier, unit string) []byte {
	return []byte(identifier + "\n" + unit + "\n6\n1\n0\n0\n0\n")
}

// ownUnit is the systemd unit this process runs in ("" outside one), from
// its cgroup path: the deepest *.service element.
var ownUnit = sync.OnceValue(ownUnitFrom)

func ownUnitFrom() string {
	f, err := os.Open(procCgroupFile)
	if err != nil {
		return ""
	}
	defer f.Close()
	return unitFromCgroup(f)
}

// procCgroupFile lists this process's cgroups; tests point it elsewhere.
var procCgroupFile = "/proc/self/cgroup"

func unitFromCgroup(r io.Reader) string {
	unit := ""
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// "hierarchy:controllers:path"; the path may hold ':'.
		parts := strings.SplitN(sc.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, el := range strings.Split(parts[2], "/") {
			if strings.HasSuffix(el, ".service") && validUnitName(el) {
				unit = el
			}
		}
	}
	return unit
}

// validUnitName keeps a unit name to systemd's characters, so it cannot
// break the header's lines.
func validUnitName(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(":-_.\\@", c)) {
			return false
		}
	}
	return true
}

var sigpipeOnce sync.Once

// CatchSIGPIPE keeps a write to a broken stdout or stderr from stopping
// the process: Go's runtime raises SIGPIPE on EPIPE from descriptor 1 or 2
// unless the program asked for that signal, and with it asked for, the
// write only fails. Notify, never Ignore: an ignored signal stays ignored
// across exec in every child the process starts (container shims, skopeo,
// rclone, workers), while a caught one is reset to the default there.
func CatchSIGPIPE() {
	sigpipeOnce.Do(func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGPIPE)
		go func() {
			for range ch {
			}
		}()
	})
}

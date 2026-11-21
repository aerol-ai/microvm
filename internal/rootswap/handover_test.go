package rootswap

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// rawDup is a descriptor of f's that only the code under test owns: it
// closes what it takes, and the test's own *os.File stays valid.
func rawDup(t *testing.T, f *os.File) int {
	t.Helper()
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

func envOf(kv ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(k string) string { return m[k] }
}

func TestHandoverEnv(t *testing.T) {
	if got := strings.Join(HandoverEnv(), " "); got != "SB_ROOTD_LISTEN_FD=3 SB_ROOTD_READY_FD=4" {
		t.Fatalf("HandoverEnv = %s", got)
	}
}

// TestInheritedListener: the supervisor's socket is served as it is, and
// closing it leaves the socket file for the next helper; anything that is
// not a listening Unix socket is refused.
func TestInheritedListener(t *testing.T) {
	if ln, err := InheritedListener(envOf()); ln != nil || err != nil {
		t.Fatalf("no socket passed = %v, %v; want the helper to make its own", ln, err)
	}
	dir := shortDir(t)
	path := filepath.Join(dir, "root.sock")
	sup, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer sup.Close()
	f, err := sup.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ln, err := InheritedListener(envOf(ListenFDEnv, strconv.Itoa(rawDup(t, f))))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if c, err := net.Dial("unix", path); err == nil {
			_, _ = c.Write([]byte("x"))
			_ = c.Close()
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_ = ln.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("closing the inherited listener removed the socket: %v", err)
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	sfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(bound, &unix.SockaddrUnix{Name: filepath.Join(dir, "b.sock")}); err != nil {
		t.Fatal(err)
	}
	dgram, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(dgram, &unix.SockaddrUnix{Name: filepath.Join(dir, "d.sock")}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"not a number":        "three",
		"stdin":               "0",
		"stderr":              "2",
		"a pipe":              strconv.Itoa(rawDup(t, pr)),
		"a socket not bound":  strconv.Itoa(sfd),
		"a closed descriptor": "987",
		"a datagram socket":   strconv.Itoa(dgram),
	}
	if runtime.GOOS == "linux" {
		// Only Linux says whether a Unix socket listens.
		cases["bound, not listening"] = strconv.Itoa(bound)
	} else {
		_ = unix.Close(bound)
	}
	for name, v := range cases {
		if ln, err := InheritedListener(envOf(ListenFDEnv, v)); err == nil {
			_ = ln.Close()
			t.Errorf("%s: InheritedListener took it", name)
		}
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	tf, err := tcp.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer tf.Close()
	if ln, err := InheritedListener(envOf(ListenFDEnv, strconv.Itoa(rawDup(t, tf)))); err == nil || !strings.Contains(err.Error(), "not a Unix socket bound to a path") {
		if ln != nil {
			_ = ln.Close()
		}
		t.Fatalf("a TCP socket = %v", err)
	}
}

// TestNotifyReady writes one byte and closes the pipe; without a pipe it
// does nothing; a pipe nobody reads is an error, not a crash.
func TestNotifyReady(t *testing.T) {
	if err := NotifyReady(envOf()); err != nil {
		t.Fatal(err)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	fd := rawDup(t, pw)
	_ = pw.Close()
	if err := NotifyReady(envOf(ReadyFDEnv, strconv.Itoa(fd))); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	n, err := pr.Read(b)
	if err != nil || n != 1 || b[0] != '1' {
		t.Fatalf("read %q, %v", b[:n], err)
	}
	if _, err := pr.Read(b); err == nil {
		t.Fatal("the pipe was left open")
	}

	pr2, pw2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	fd2 := rawDup(t, pw2)
	_ = pw2.Close()
	_ = pr2.Close()
	if err := NotifyReady(envOf(ReadyFDEnv, strconv.Itoa(fd2))); err == nil {
		t.Fatal("a pipe nobody reads took the byte")
	}
	if err := NotifyReady(envOf(ReadyFDEnv, "1")); err == nil {
		t.Fatal("stdout taken as the ready pipe")
	}
	if err := NotifyReady(envOf(ReadyFDEnv, "988")); err == nil {
		t.Fatal("a closed descriptor took the byte")
	}
}

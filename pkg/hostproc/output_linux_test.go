//go:build linux

package hostproc

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// journaldStandIn listens where JournalStdoutSocket points for the test
// and hands over each stream it accepts.
func journaldStandIn(t *testing.T) chan net.Conn {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdout")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	prev := JournalStdoutSocket
	JournalStdoutSocket = path
	t.Cleanup(func() { JournalStdoutSocket = prev })
	streams := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			streams <- c
		}
	}()
	return streams
}

// journalOutput is a stream socket standing in for the journal stream
// systemd gives sandboxd, made this process's stdout and stderr, with
// JOURNAL_STREAM naming it. It returns the far end.
func journalOutput(t *testing.T) *os.File {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	mine, far := os.NewFile(uintptr(fds[0]), "mine"), os.NewFile(uintptr(fds[1]), "far")
	t.Cleanup(func() { _ = mine.Close(); _ = far.Close() })
	var st syscall.Stat_t
	if err := syscall.Fstat(fds[0], &st); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JOURNAL_STREAM", fmt.Sprintf("%d:%d", st.Dev, st.Ino))
	swapOutput(t, mine)
	return far
}

// Review round 4, F3: where this process's output is the journal, a
// process it starts gets a journal stream of its own (one for stdout and
// stderr), with the header journald reads first; shutting that stream
// leaves this process's own writable.
func TestOwnOutputGivesAJournalStreamOfItsOwn(t *testing.T) {
	streams := journaldStandIn(t)
	far := journalOutput(t)
	cmd := exec.Command("true")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	opened := OwnOutput(cmd, "sandboxd-wasm-worker")
	if len(opened) != 1 || cmd.Stdout != opened[0] || cmd.Stderr != opened[0] {
		t.Fatalf("opened %v, stdout %v, stderr %v", opened, cmd.Stdout, cmd.Stderr)
	}
	defer opened[0].Close()
	var stream net.Conn
	select {
	case stream = <-streams:
	case <-time.After(5 * time.Second):
		t.Fatal("journald got no stream")
	}
	defer stream.Close()
	if _, err := opened[0].Write([]byte("worker line\n")); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	sc := bufio.NewScanner(stream)
	var lines []string
	for len(lines) < 8 && sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) != 8 || lines[0] != "sandboxd-wasm-worker" || strings.Join(lines[2:], ",") != "6,1,0,0,0,worker line" {
		t.Fatalf("journald read %q", lines)
	}
	// What the process does to its stream stays there.
	if err := syscall.Shutdown(int(opened[0].Fd()), syscall.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.Write([]byte("sandboxd line\n")); err != nil {
		t.Fatalf("sandboxd's own output after the process shut its stream: %v", err)
	}
	got := make([]byte, 64)
	_ = far.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := far.Read(got); err != nil || string(got[:n]) != "sandboxd line\n" {
		t.Fatalf("sandboxd's line: %q %v", got[:n], err)
	}
}

// With no journald to connect to, the process gets /dev/null, never the
// shared stream.
func TestOwnOutputWithoutJournald(t *testing.T) {
	prev := JournalStdoutSocket
	JournalStdoutSocket = filepath.Join(t.TempDir(), "none")
	t.Cleanup(func() { JournalStdoutSocket = prev })
	journalOutput(t)
	cmd := exec.Command("true")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if opened := OwnOutput(cmd, "x"); len(opened) != 0 || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Fatalf("opened %v, stdout %v, stderr %v", opened, cmd.Stdout, cmd.Stderr)
	}
}

func TestOwnUnitReadsProc(t *testing.T) {
	prev := procCgroupFile
	t.Cleanup(func() { procCgroupFile = prev })
	procCgroupFile = filepath.Join(t.TempDir(), "missing")
	if got := ownUnitFrom(); got != "" {
		t.Fatalf("missing file: %q", got)
	}
	procCgroupFile = filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(procCgroupFile, []byte("0::/system.slice/sandboxd.service\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ownUnitFrom(); got != "sandboxd.service" {
		t.Fatalf("unit = %q", got)
	}
}

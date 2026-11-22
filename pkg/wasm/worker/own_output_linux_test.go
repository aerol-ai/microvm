//go:build linux

package worker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const outputChildEnv = "AEROL_WASM_OUTPUT_CHILD"

// TestOutputChild plays both halves of TestWorkerCannotShutSandboxdsOutput.
// "sandboxd": its stdout and stderr are one stream socket, which
// JOURNAL_STREAM names as the journal, as systemd sets them up; it starts a
// worker through a Supervisor with DefaultSpawner's output, waits until the
// worker has shut its stdout, then logs a line. "worker": shuts down fd 1
// for writing, says so on fd 3, and waits to be stopped.
func TestOutputChild(t *testing.T) {
	switch os.Getenv(outputChildEnv) {
	case "":
		t.Skip("child half of TestWorkerCannotShutSandboxdsOutput")
	case "worker":
		if os.Getenv(confineEnv) != "" {
			if err := confineFromEnv(); err != nil {
				os.Exit(4)
			}
		}
		report := os.NewFile(3, "report")
		_, _ = fmt.Fprintf(report, "shut(1, SHUT_WR) as uid %d: %v\n", os.Getuid(), unix.Shutdown(1, unix.SHUT_WR))
		_ = report.Close()
		// Until stopped, or its sandboxd stand-in is gone (Pdeathsig).
		time.Sleep(30 * time.Second)
	case "sandboxd":
		r, w, err := os.Pipe()
		if err != nil {
			os.Exit(5)
		}
		spawn := Spawner(func(context.Context, string) (*exec.Cmd, error) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestOutputChild$")
			cmd.Env = append(os.Environ(), outputChildEnv+"=worker")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr // as DefaultSpawner
			cmd.ExtraFiles = []*os.File{w}
			cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
			return cmd, nil
		})
		if os.Getenv(outputChildEnv+"_CONFINE") != "" {
			spawn = Confine(spawn, Confinement{UID: e2eWorkerUID, GID: e2eWorkerUID})
		}
		sup := NewSupervisor(spawn)
		if err := sup.Ensure(context.Background(), "sb-output", filepath.Join(os.TempDir(), "aerol-output-test.sock")); err != nil {
			fmt.Fprintln(os.Stderr, "ensure:", err)
			os.Exit(6)
		}
		_ = w.Close()
		line, _ := bufio.NewReader(r).ReadString('\n')
		fmt.Fprint(os.Stderr, "WORKER ", line)
		_, err = os.Stdout.Write([]byte("sandboxd: a line after the worker\n"))
		fmt.Fprintf(os.Stderr, "SANDBOXD WROTE %v\n", err)
		_ = sup.Stop("sb-output")
		os.Exit(0)
	}
}

// Review round 4, F3: under systemd sandboxd's stdout and stderr are one
// stream socket to journald. A worker that shares it can shut it down
// (shutdown(2) acts on the socket, not the descriptor), and sandboxd's
// next log line then fails with EPIPE, which stops a Go program that did
// not ask for SIGPIPE. A worker gets output of its own: whatever it does
// to it, sandboxd's own stream keeps working.
func TestWorkerCannotShutSandboxdsOutput(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	journal, stream := os.NewFile(uintptr(fds[0]), "journal"), os.NewFile(uintptr(fds[1]), "stream")
	defer journal.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fds[1], &st); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestOutputChild$")
	cmd.Env = append(os.Environ(), outputChildEnv+"=sandboxd", fmt.Sprintf("JOURNAL_STREAM=%d:%d", st.Dev, st.Ino))
	if os.Geteuid() == 0 && canMakePIDNamespace() {
		cmd.Env = append(cmd.Env, outputChildEnv+"_CONFINE=1")
	}
	cmd.Stdout = stream
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	// A worker left behind by a stand-in that died holds its stderr: do
	// not wait for it to report how the stand-in ended.
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	got := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(journal)
		got <- string(b)
	}()
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case err = <-waitErr:
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("the sandboxd stand-in hung:\n%s", errBuf.String())
	}
	t.Logf("sandboxd stand-in: %v\n%s", err, errBuf.String())
	if err != nil {
		t.Fatalf("the sandboxd stand-in died: %v", err)
	}
	if !strings.Contains(errBuf.String(), "SANDBOXD WROTE <nil>") {
		t.Fatalf("sandboxd's line after the worker did not go out:\n%s", errBuf.String())
	}
	_ = journal.SetReadDeadline(time.Now().Add(5 * time.Second))
	if out := <-got; !strings.Contains(out, "sandboxd: a line after the worker") {
		t.Fatalf("the journal stand-in got %q", out)
	}
}

//go:build unix

package daemon

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

const brokenOutputChildEnv = "AEROL_DAEMON_BROKEN_OUTPUT_CHILD"

// TestRunBrokenOutputChild runs Run with a stdout whose write side was
// shut (as a process sharing journald's stream with sandboxd could shut
// it), then writes a log line.
func TestRunBrokenOutputChild(t *testing.T) {
	if os.Getenv(brokenOutputChildEnv) == "" {
		t.Skip("child half of TestRunSurvivesABrokenStdout")
	}
	_ = syscall.Shutdown(1, syscall.SHUT_WR)
	// A config that fails to load: Run returns before it starts anything.
	t.Setenv("SB_TOOLBOX_MOUNT_PATH", "relative")
	runErr := Run(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	_, err := os.Stdout.Write([]byte("sandboxd: a line\n"))
	os.Stderr.WriteString("RUN " + errText(runErr) + "\nWROTE " + errText(err) + "\n")
	os.Exit(0)
}

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// Review round 4, F3: a write to a stdout or stderr that someone shut
// raises SIGPIPE, which stops a Go program that did not ask for the
// signal. Run asks for it first thing, so a broken log stream costs log
// lines, never the daemon.
func TestRunSurvivesABrokenStdout(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	mine, theirs := os.NewFile(uintptr(fds[0]), "mine"), os.NewFile(uintptr(fds[1]), "theirs")
	defer mine.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunBrokenOutputChild$")
	cmd.Env = append(os.Environ(), brokenOutputChildEnv+"=1")
	cmd.Stdout = theirs
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	err = cmd.Run()
	_ = theirs.Close()
	if err != nil {
		t.Fatalf("the daemon died writing to a broken stdout: %v\n%s", err, errBuf.String())
	}
	if out := errBuf.String(); !strings.Contains(out, "load config") || !strings.Contains(out, "WROTE") || !strings.Contains(out, "broken pipe") {
		t.Fatalf("child said %q", out)
	}
}

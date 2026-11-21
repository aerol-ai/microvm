package hostproc

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestUnitFromCgroup(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"0::/system.slice/sandboxd.service\n", "sandboxd.service"},
		{"12:pids:/system.slice/other.service/x\n0::/system.slice/sandboxd.service/daemon\n", "sandboxd.service"},
		{"1:name=systemd:/system.slice/sandboxd@a.service\n", "sandboxd@a.service"},
		{"0::/user.slice/user-1000.slice/session-3.scope\n", ""},
		{"0::/system.slice/bad name.service\n", ""},
		{"garbage\n", ""},
		{"", ""},
	} {
		if got := unitFromCgroup(strings.NewReader(tc.in)); got != tc.want {
			t.Errorf("%q: %q, want %q", tc.in, got, tc.want)
		}
	}
	if validUnitName(strings.Repeat("a", 300)) || validUnitName("") {
		t.Fatal("an over-long or empty unit name passed")
	}
}

func TestJournalHeader(t *testing.T) {
	if got := string(journalHeader("sandboxd-wasm-worker", "sandboxd.service")); got != "sandboxd-wasm-worker\nsandboxd.service\n6\n1\n0\n0\n0\n" {
		t.Fatalf("header = %q", got)
	}
}

// swapOutput makes f this process's os.Stdout and os.Stderr for the test.
func swapOutput(t *testing.T, f *os.File) {
	t.Helper()
	out, errOut := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = f, f
	t.Cleanup(func() { os.Stdout, os.Stderr = out, errOut })
}

// Output that is not a socket stays shared (shutdown(2) does not apply to
// it), and writers that are not this process's own are left alone.
func TestOwnOutputLeavesWhatIsNotASocket(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	swapOutput(t, w)
	cmd := exec.Command("true")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if opened := OwnOutput(cmd, "x"); len(opened) != 0 || cmd.Stdout != w || cmd.Stderr != w {
		t.Fatalf("a pipe was replaced: %v %v %v", opened, cmd.Stdout, cmd.Stderr)
	}
	var buf bytes.Buffer
	other, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	cmd.Stdout, cmd.Stderr = &buf, other
	if opened := OwnOutput(cmd, "x"); len(opened) != 0 || cmd.Stdout != &buf || cmd.Stderr != other {
		t.Fatal("a writer of the caller's own was replaced")
	}
	// A closed own output reads as no socket: left as it is.
	_ = w.Close()
	cmd.Stdout = os.Stdout
	if OwnOutput(cmd, "x"); cmd.Stdout != w {
		t.Fatal("a closed output was replaced")
	}
}

// A socket that is not the journal (no JOURNAL_STREAM, or another one)
// is never shared: the process gets /dev/null.
func TestOwnOutputOtherSocketGetsNothing(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	mine, peer := os.NewFile(uintptr(fds[0]), "mine"), os.NewFile(uintptr(fds[1]), "peer")
	defer mine.Close()
	defer peer.Close()
	swapOutput(t, mine)
	for _, js := range []string{"", "1:2", "x:y"} {
		t.Setenv("JOURNAL_STREAM", js)
		cmd := exec.Command("true")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if opened := OwnOutput(cmd, "x"); len(opened) != 0 || cmd.Stdout != nil || cmd.Stderr != nil {
			t.Fatalf("JOURNAL_STREAM=%q: the socket was shared: %v %v", js, cmd.Stdout, cmd.Stderr)
		}
	}
}

const sigpipeChildEnv = "AEROL_HOSTPROC_SIGPIPE_CHILD"

// TestCatchSIGPIPEChild writes to a stdout whose write side it shut first,
// as a process sharing it could shut it.
func TestCatchSIGPIPEChild(t *testing.T) {
	mode := os.Getenv(sigpipeChildEnv)
	if mode == "" {
		t.Skip("child half of TestCatchSIGPIPE")
	}
	if mode == "catch" {
		CatchSIGPIPE()
		CatchSIGPIPE()
	}
	_ = syscall.Shutdown(1, syscall.SHUT_WR)
	_, err := os.Stdout.Write([]byte("line\n"))
	os.Stderr.WriteString("WROTE " + errString(err) + "\n")
	os.Exit(0)
}

func errString(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// Review round 4, F3: a write to a stdout someone shut raises SIGPIPE,
// which stops a Go program unless it asked for the signal; with
// CatchSIGPIPE the write fails and the program goes on.
func TestCatchSIGPIPE(t *testing.T) {
	run := func(mode string) (string, error) {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		mine, peer := os.NewFile(uintptr(fds[0]), "mine"), os.NewFile(uintptr(fds[1]), "peer")
		defer peer.Close()
		cmd := exec.Command(os.Args[0], "-test.run=^TestCatchSIGPIPEChild$")
		cmd.Env = append(os.Environ(), sigpipeChildEnv+"="+mode)
		cmd.Stdout = mine
		var errBuf strings.Builder
		cmd.Stderr = &errBuf
		err = cmd.Run()
		_ = mine.Close()
		return errBuf.String(), err
	}
	if out, err := run("catch"); err != nil || !strings.Contains(out, "WROTE") || !strings.Contains(out, "broken pipe") {
		t.Fatalf("with CatchSIGPIPE: %v, %q", err, out)
	}
	if out, err := run("plain"); err == nil || !strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("without it the write should stop the process: %v, %q", err, out)
	}
}

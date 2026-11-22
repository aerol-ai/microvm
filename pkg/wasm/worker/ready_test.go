package worker

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTakeReadyFD(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	reg, err := os.CreateTemp(t.TempDir(), "f")
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	for name, raw := range map[string]string{"unset": "", "not a number": "x", "stdio": "1", "a regular file": strconv.Itoa(int(reg.Fd())), "closed": "999"} {
		t.Setenv(ReadyFDEnv, raw)
		if f := takeReadyFD(); f != nil {
			t.Errorf("%s: took %v", name, f.Name())
		}
		if raw != "" && os.Getenv(ReadyFDEnv) != "" {
			t.Errorf("%s: %s left in the environment", name, ReadyFDEnv)
		}
	}
	if st, _ := reg.Stat(); st.Size() != 0 {
		t.Fatal("something was written to a descriptor that is not a pipe")
	}
	// A pipe is taken, made close-on-exec, and written once.
	dup, err := unix.Dup(int(w.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(ReadyFDEnv, strconv.Itoa(dup))
	f := takeReadyFD()
	if f == nil {
		t.Fatal("the pipe was not taken")
	}
	if flags, err := unix.FcntlInt(uintptr(dup), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("the pipe is not close-on-exec: %#x %v", flags, err)
	}
	signalReady(f)
	signalReady(nil)
	_ = w.Close()
	got, err := io.ReadAll(r)
	if err != nil || len(got) != 1 {
		t.Fatalf("read %v %v, want one byte and the end of the pipe", got, err)
	}
}

func TestAttachReadyPipe(t *testing.T) {
	cmd := exec.Command("true")
	other, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	cmd.ExtraFiles = []*os.File{other}
	r, w, err := attachReadyPipe(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if len(cmd.ExtraFiles) != 2 || cmd.ExtraFiles[1] != w || cmd.Env[len(cmd.Env)-1] != ReadyFDEnv+"=4" {
		t.Fatalf("extra files %v, env tail %q", cmd.ExtraFiles, cmd.Env[len(cmd.Env)-1])
	}
	cmd = exec.Command("true")
	cmd.Env = []string{"A=1"}
	r2, w2, err := attachReadyPipe(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	defer w2.Close()
	if strings.Join(cmd.Env, " ") != "A=1 "+ReadyFDEnv+"=3" {
		t.Fatalf("env %v", cmd.Env)
	}
}

// waitWatchers waits for the ready watchers to come back to n.
func waitWatchers(t *testing.T, n int64) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if readyWatchers.Load() == n {
			return
		}
	}
	t.Fatalf("ready watchers = %d, want %d", readyWatchers.Load(), n)
}

// The watcher closes ready on the byte and only on it, and ends when the
// worker's end closes or sandboxd closes its own.
func TestWatchReady(t *testing.T) {
	base := readyWatchers.Load()
	for _, tc := range []struct {
		name  string
		act   func(r, w *os.File)
		ready bool
	}{
		{"byte", func(_, w *os.File) { _, _ = w.Write([]byte{1, 2, 3}) }, true},
		{"worker gone", func(_, w *os.File) { _ = w.Close() }, false},
		{"slot ended", func(r, _ *os.File) { _ = r.Close() }, false},
	} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		ready := make(chan struct{})
		done := make(chan struct{})
		go func() { watchReady(r, ready); close(done) }()
		tc.act(r, w)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the watcher did not end", tc.name)
		}
		select {
		case <-ready:
			if !tc.ready {
				t.Errorf("%s: ready closed", tc.name)
			}
		default:
			if tc.ready {
				t.Errorf("%s: ready not closed", tc.name)
			}
		}
		// Its end is closed: later writes fail, they fill nothing.
		if _, err := w.Write([]byte{1}); err == nil {
			t.Errorf("%s: a write after the watcher ended went into the pipe", tc.name)
		}
		_ = w.Close()
	}
	waitWatchers(t, base)
}

const readyChildEnv = "AEROL_WASM_READY_CHILD"

// TestReadyChild is a worker for the tests below. "serve": a real worker
// (RunCLI), which says it serves. "early": writes the ready byte and never
// listens. "silent": a real worker that is not told of the pipe, so it
// serves and never writes, while the pipe stays open in it. "never": holds
// the pipe, never writes, never listens.
func TestReadyChild(t *testing.T) {
	mode, sock := os.Getenv(readyChildEnv), os.Getenv(readyChildEnv+"_SOCK")
	switch mode {
	case "":
		t.Skip("child half of the ready tests")
	case "serve":
		_ = RunCLI([]string{sock})
	case "early":
		signalReady(takeReadyFD())
		time.Sleep(time.Minute)
	case "silent":
		_ = os.Unsetenv(ReadyFDEnv)
		_ = RunCLI([]string{sock})
	case "never":
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}

func readySupervisor(t *testing.T, mode string) (*Supervisor, string) {
	t.Helper()
	sup := NewSupervisor(func(ctx context.Context, socketPath string) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestReadyChild$")
		cmd.Env = append(os.Environ(), readyChildEnv+"="+mode, readyChildEnv+"_SOCK="+socketPath)
		return cmd, nil
	})
	sock := shortTempDir(t) + "/r.sock"
	t.Cleanup(func() { _ = sup.Stop("sb-ready") })
	if err := sup.Ensure(context.Background(), "sb-ready", sock); err != nil {
		t.Fatal(err)
	}
	return sup, sock
}

func readyWithin(ch <-chan struct{}, d time.Duration) bool {
	select {
	case <-ch:
		return true
	default:
	}
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}

// A worker says it serves, and does: the first ping after the signal
// answers.
func TestSupervisorReadySignal(t *testing.T) {
	sup, sock := readySupervisor(t, "serve")
	if !readyWithin(sup.Ready("sb-ready"), 20*time.Second) {
		t.Fatal("the worker never said it serves")
	}
	if err := NewClient(sock).Ping("sb-ready"); err != nil {
		t.Fatalf("ping right after the signal: %v", err)
	}
	if sup.Ready("other") != nil {
		t.Fatal("a slot that does not exist has a ready signal")
	}
	// Ensure on the live worker starts nothing; the signal stays given.
	if err := sup.Ensure(context.Background(), "sb-ready", sock); err != nil || !readyWithin(sup.Ready("sb-ready"), 0) {
		t.Fatalf("ensure again: %v", err)
	}
}

// A byte from a worker that does not serve is only a byte: the slot says
// ready, and a ping still fails, so the driver keeps polling (waitWorker).
func TestSupervisorReadyWithoutServing(t *testing.T) {
	sup, sock := readySupervisor(t, "early")
	if !readyWithin(sup.Ready("sb-ready"), 20*time.Second) {
		t.Fatal("no signal")
	}
	if err := NewClient(sock).Ping("sb-ready"); err == nil {
		t.Fatal("a worker that never listened answered")
	}
}

// A worker that serves without saying so is found by polling; its signal
// never comes.
func TestSupervisorServesWithoutSignal(t *testing.T) {
	sup, sock := readySupervisor(t, "silent")
	c := NewClient(sock)
	ok := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if c.Ping("sb-ready") == nil {
			ok = true
			break
		}
	}
	if !ok {
		t.Fatal("the worker never answered")
	}
	if readyWithin(sup.Ready("sb-ready"), 100*time.Millisecond) {
		t.Fatal("a worker that never wrote was taken as ready")
	}
}

// A worker that holds the pipe and never writes costs sandboxd one parked
// watcher, which ends with the slot.
func TestSupervisorReadyNeverWritten(t *testing.T) {
	base := readyWatchers.Load()
	sup, _ := readySupervisor(t, "never")
	if readyWithin(sup.Ready("sb-ready"), 200*time.Millisecond) {
		t.Fatal("ready without a byte")
	}
	if readyWatchers.Load() != base+1 {
		t.Fatalf("watchers %d, want %d", readyWatchers.Load(), base+1)
	}
	if err := sup.Stop("sb-ready"); err != nil {
		t.Fatal(err)
	}
	waitWatchers(t, base)
}

// An adopted worker was started by another sandboxd: there is no pipe to
// wait on, and it is polled.
func TestSupervisorReadyAdopted(t *testing.T) {
	sup := NewSupervisor(nil)
	if !sup.Adopt("sb-adopted", "/x.sock", blockedProc{}) {
		t.Fatal("not adopted")
	}
	if sup.Ready("sb-adopted") != nil {
		t.Fatal("an adopted worker has a ready signal")
	}
}

// blockedProc is a process that never ends.
type blockedProc struct{}

func (blockedProc) Pid() int                    { return 1 }
func (blockedProc) Signal(syscall.Signal) error { return errors.New("not signalled") }
func (blockedProc) Done() <-chan struct{}       { return make(chan struct{}) }
func (blockedProc) Close() error                { return nil }

// ReadyPollSleepOr ends at the signal, at the step, or when ctx ends.
func TestReadyPollSleepOr(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	if ReadyPollSleepOr(context.Background(), 0, closed) {
		t.Fatal("attempt 0 does not wait, so no signal ends it")
	}
	if !ReadyPollSleepOr(context.Background(), 5, closed) {
		t.Fatal("the signal did not end the wait")
	}
	start := time.Now()
	if ReadyPollSleepOr(context.Background(), 1, nil) || time.Since(start) < time.Millisecond {
		t.Fatal("a nil signal changed the wait")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ReadyPollSleepOr(ctx, 9, make(chan struct{})) {
		t.Fatal("a cancelled wait reported the signal")
	}
}

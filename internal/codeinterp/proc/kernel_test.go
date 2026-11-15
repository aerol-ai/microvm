package proc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

func TestFindMarker(t *testing.T) {
	prefix := []byte("\x1eabc:")
	cases := []struct {
		name             string
		in               string
		start, end, keep int
		seq              uint64
	}{
		{name: "none", in: "hello", start: -1, keep: 5},
		{name: "whole", in: "hi\x1eabc:12\x1etail", start: 2, end: 10, seq: 12},
		{name: "prefix only at end", in: "hi\x1eab", start: -1, keep: 2},
		{name: "digits cut", in: "hi\x1eabc:1", start: -1, keep: 2},
		{name: "lone RS", in: "x\x1e", start: -1, keep: 1},
		// The closing RS may start the next marker, so it waits.
		{name: "other nonce", in: "\x1exyz:1\x1e", start: -1, keep: 6},
		{name: "no digits", in: "\x1eabc:\x1e", start: -1, keep: 5},
		{name: "letter in seq", in: "\x1eabc:1z\x1eq", start: -1, keep: 9},
		{name: "after a false start", in: "\x1e\x1eabc:3\x1e", start: 1, end: 8, seq: 3},
		{name: "seq too long", in: "\x1eabc:" + strings.Repeat("9", 21) + "\x1e", start: -1, keep: 26},
		{name: "seq overflows", in: "\x1eabc:" + strings.Repeat("9", 20) + "\x1e", start: -1, keep: 25},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, seq, keep := findMarker([]byte(tc.in), prefix)
			if start != tc.start || (start >= 0 && (end != tc.end || seq != tc.seq)) || (start < 0 && keep != tc.keep) {
				t.Fatalf("findMarker(%q) = %d,%d,%d,%d; want start %d end %d seq %d keep %d",
					tc.in, start, end, seq, keep, tc.start, tc.end, tc.seq, tc.keep)
			}
		})
	}
}

func TestCompleteUTF8(t *testing.T) {
	e := "é"    // 2 bytes
	euro := "€" // 3 bytes
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"a" + e, 3},
		{"a" + e[:1], 1},
		{"a" + euro[:2], 1},
		{"a" + euro, 4},
		{"\x80\x80\x80\x80\x80", 5}, // invalid, never complete: send as is
		{"a\xff", 2},
	}
	for _, tc := range cases {
		if got := completeUTF8([]byte(tc.in)); got != tc.want {
			t.Errorf("completeUTF8(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestKernelRunsAndKeepsOrder(t *testing.T) {
	k := launchFake(t, "")
	// stdout and stderr are two pipes; only a SYNC orders one against the
	// other.
	out, ev := execute(t, k, "out a\nsync\nerr b\nresult\nout c\nerror\ntext hi\nstatus error", nil)
	if out.Status != "error" || out.Died {
		t.Fatalf("outcome = %+v", out)
	}
	want := []string{"count:1", "out:a", "err:b", "result:42:true", "out:c", "error:ValueError:bad value", "result:hi:true"}
	if got := ev.trace(); !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %q, want %q", got, want)
	}
	for _, e := range ev.list() {
		if e.Kind == codeinterp.EventResult && e.Bundle["application/json"] != nil {
			// UseNumber keeps all 20 digits.
			n := e.Bundle["application/json"].(map[string]any)["n"].(json.Number)
			if n.String() != "12345678901234567890" {
				t.Fatalf("json number = %s", n)
			}
		}
		if e.Kind == codeinterp.EventError && e.ErrTraceback != "Traceback: here" {
			t.Fatalf("traceback = %q", e.ErrTraceback)
		}
	}

	// State and counts carry over to the next run.
	_, ev = execute(t, k, "out again", nil)
	if got := ev.trace(); !reflect.DeepEqual(got, []string{"count:2", "out:again"}) {
		t.Fatalf("second run = %q", got)
	}
}

func TestKernelMarkersSplitAcrossReads(t *testing.T) {
	k := launchFake(t, "")
	_, ev := execute(t, k, "out before\nslowsync\nout after\nslowsync\nresult\nout \x1e\nutf8split", nil)
	if got := ev.stream(codeinterp.EventStdout); got != "beforeafter\x1eé\n" {
		t.Fatalf("stdout = %q", got)
	}
	for _, e := range ev.list() {
		if (e.Kind == codeinterp.EventStdout || e.Kind == codeinterp.EventStderr) && !utf8.ValidString(e.Text) {
			t.Fatalf("event split a character: %q", e.Text)
		}
		if strings.Contains(e.Text, string(k.marker[1:])) {
			t.Fatalf("a marker leaked into output: %q", e.Text)
		}
	}
}

func TestKernelLargeOutputArrivesWhole(t *testing.T) {
	k := launchFake(t, "")
	const n = 300 << 10
	_, ev := execute(t, k, "big 307200\nresult", nil)
	got := ev.stream(codeinterp.EventStdout)
	if len(got) != n {
		t.Fatalf("stdout length = %d, want %d", len(got), n)
	}
	lines := strings.Split(got, "\n")
	for i := 0; i < len(lines)-1; i++ {
		if want := fmt.Sprintf("%07d", i); lines[i] != want {
			t.Fatalf("line %d = %q, want %q", i, lines[i], want)
		}
	}
	trace := ev.trace()
	if trace[len(trace)-1] != "result:42:true" {
		t.Fatalf("result not after all output: %q", trace[len(trace)-3:])
	}
}

func TestKernelEnvPerRun(t *testing.T) {
	k := launchFake(t, "")
	_, ev := execute(t, k, "env", map[string]string{"B": "2", "A": "1"})
	if got := ev.stream(codeinterp.EventStdout); got != "A=1,B=2" {
		t.Fatalf("env = %q", got)
	}
	_, ev = execute(t, k, "env", nil)
	if got := ev.stream(codeinterp.EventStdout); got != "" {
		t.Fatalf("env leaked into the next run: %q", got)
	}
}

func TestKernelIgnoresStrayFrames(t *testing.T) {
	k := launchFake(t, "")
	out, ev := execute(t, k, "stdioframes\nbadresult", nil)
	if out.Status != "ok" {
		t.Fatalf("outcome = %+v", out)
	}
	if got := ev.trace(); !reflect.DeepEqual(got, []string{"count:1", "out:o", "err:e"}) {
		t.Fatalf("events = %q", got)
	}
}

func TestKernelInterrupt(t *testing.T) {
	k := launchFake(t, "")
	// An interrupt while idle is harmless.
	if err := k.Interrupt(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = k.Interrupt()
	}()
	out, _ := execute(t, k, "sleep", nil)
	if !out.Interrupted() || out.Died {
		t.Fatalf("outcome = %+v, want interrupted", out)
	}
	if out, _ := execute(t, k, "out still alive", nil); out.Status != "ok" {
		t.Fatalf("kernel did not survive the interrupt: %+v", out)
	}
}

// An interrupt that comes after the run was handed to the kernel, but
// before the driver read it, reaches an idle driver, which drops SIGINT on
// purpose. The kernel sends it again when the run's COUNT arrives.
func TestKernelInterruptBeforeTheDriverReadTheRun(t *testing.T) {
	// The driver sleeps 300ms after READY (and after each DONE) before it
	// reads, so the run below waits in the pipe meanwhile.
	k := launchFake(t, "slowread")
	done := make(chan codeinterp.Outcome, 1)
	go func() {
		out, _ := k.Execute(codeinterp.Request{Code: "sleep 5s"}, nil)
		done <- out
	}()
	waitUntilKernel(t, "run handed to the kernel", func() bool {
		k.mu.Lock()
		defer k.mu.Unlock()
		return k.run != nil
	})
	time.Sleep(50 * time.Millisecond)
	if err := k.Interrupt(); err != nil {
		t.Fatal(err)
	}
	select {
	case out := <-done:
		if !out.Interrupted() || out.Died {
			t.Fatalf("outcome = %+v, want interrupted", out)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the interrupt was lost: the run went on")
	}
	// The interrupt belonged to that run only.
	if out, _ := execute(t, k, "sleep 500ms", nil); out.Status != "ok" {
		t.Fatalf("next run = %+v, want ok", out)
	}
}

func waitUntilKernel(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// openFDs lists the descriptors below max this process has open. fstat
// answers EBADF for a closed one, on Linux and macOS alike.
func openFDs(max int) map[int]bool {
	fds := map[int]bool{}
	var st syscall.Stat_t
	for fd := 0; fd < max; fd++ {
		if syscall.Fstat(fd, &st) == nil {
			fds[fd] = true
		}
	}
	return fds
}

// When the third of startKernel's four pipes cannot be made, the two made
// before it were left open: every failed launch on a full descriptor table
// leaked four more. A lowered RLIMIT_NOFILE makes the third pipe fail.
func TestStartKernelClosesPipesWhenOneFails(t *testing.T) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Skipf("getrlimit: %v", err)
	}
	const probe = 4096
	before := openFDs(probe)
	// Room for exactly five new descriptors: /dev/null and two pipes. New
	// descriptors take the lowest free numbers, so count free numbers.
	limit, free := 0, 0
	for free < 5 {
		if !before[limit] {
			free++
		}
		limit++
	}
	low := lim
	low.Cur = uint64(limit)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &low); err != nil {
		t.Skipf("setrlimit: %v", err)
	}
	_, err := startKernel(exec.Command("true"), nil, "nonce")
	if rerr := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); rerr != nil {
		t.Fatalf("restore rlimit: %v", rerr)
	}
	if !errors.Is(err, syscall.EMFILE) {
		t.Fatalf("startKernel = %v, want EMFILE", err)
	}
	var leaked []int
	for fd := range openFDs(probe) {
		if !before[fd] {
			leaked = append(leaked, fd)
		}
	}
	if len(leaked) > 0 {
		t.Fatalf("descriptors left open after the failed start: %v", leaked)
	}
}

func TestKernelDiesMidRun(t *testing.T) {
	k := launchFake(t, "")
	out, ev := execute(t, k, "out partial\ndie", nil)
	if !out.Died {
		t.Fatalf("outcome = %+v, want died", out)
	}
	if got := ev.stream(codeinterp.EventStdout); got != "partial" {
		t.Fatalf("stdout = %q", got)
	}
	if got := ev.stream(codeinterp.EventStderr); got != "dying" {
		t.Fatalf("stderr = %q, want the last words", got)
	}
	waitClosed(t, k.Done(), "Done after death")
	if out, _ := execute(t, k, "out x", nil); !out.Died {
		t.Fatalf("run on a dead kernel = %+v", out)
	}
	if err := k.Interrupt(); err != nil {
		t.Fatalf("Interrupt on a dead kernel: %v", err)
	}
}

func TestKernelClosedEventStreamKillsDriver(t *testing.T) {
	k := launchFake(t, "")
	out, _ := execute(t, k, "closeevents", nil)
	if !out.Died {
		t.Fatalf("outcome = %+v, want died", out)
	}
	// The driver was alive with its event stream closed; nobody would ever
	// Close it, so the kernel killed it.
	waitClosed(t, k.Done(), "driver killed")
}

func TestKernelMarkerThatNeverComes(t *testing.T) {
	k := launchFake(t, "")
	out, ev := execute(t, k, "out last words\nsyncnomarker", nil)
	if !out.Died {
		t.Fatalf("outcome = %+v, want died", out)
	}
	if got := ev.stream(codeinterp.EventStdout); got != "last words" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestKernelStrayFrameAfterDeathIsDropped(t *testing.T) {
	k := launchFake(t, "")
	if out, _ := execute(t, k, "out x\nstrayexit", nil); out.Status != "ok" {
		t.Fatalf("outcome = %+v", out)
	}
	waitClosed(t, k.Done(), "driver exit")
	// No run will take the stray frame and nobody calls Close on a kernel
	// that died on its own: the event reader must still end.
	time.Sleep(exitDrain + 500*time.Millisecond)
	select {
	case fr, ok := <-k.frames:
		if ok {
			t.Fatalf("event reader still held a frame: %+v", fr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event reader did not end")
	}
}

func TestKernelBadSyncKillsDriver(t *testing.T) {
	k := launchFake(t, "")
	out, _ := execute(t, k, "badsync", nil)
	if !out.Died {
		t.Fatalf("outcome = %+v, want died", out)
	}
	waitClosed(t, k.Done(), "driver killed")
}

func TestKernelBackgroundChildDoesNotHoldRun(t *testing.T) {
	k := launchFake(t, "")
	start := time.Now()
	out, ev := execute(t, k, "bgexit", nil)
	if !out.Died {
		t.Fatalf("outcome = %+v, want died", out)
	}
	if elapsed := time.Since(start); elapsed > exitDrain+3*time.Second {
		t.Fatalf("run took %s with a child holding stdout", elapsed)
	}
	if got := ev.stream(codeinterp.EventStdout); got != "bye" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestKernelCloseKillsAndIsIdempotent(t *testing.T) {
	k := launchFake(t, "")
	done := make(chan codeinterp.Outcome, 1)
	go func() {
		out, _ := k.Execute(codeinterp.Request{Code: "ignore"}, nil)
		done <- out
	}()
	time.Sleep(100 * time.Millisecond)
	if err := k.Interrupt(); err != nil {
		t.Fatal(err)
	}
	if err := k.Close(); err != nil {
		t.Fatal(err)
	}
	if err := k.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case out := <-done:
		if !out.Died {
			t.Fatalf("outcome = %+v, want died", out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Execute did not end after Close")
	}
	waitClosed(t, k.Done(), "Done after Close")
	if !processGone(k.pid) {
		// Reaped by Wait: the pid must be gone.
		t.Fatalf("pid %d still exists", k.pid)
	}
}

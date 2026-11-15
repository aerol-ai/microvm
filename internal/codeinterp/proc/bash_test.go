package proc

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

func TestBashDriver(t *testing.T) {
	k, _ := launchLang(t, codeinterp.LangBash)

	// E2B's tests.
	if got := stdoutOf(t, k, "echo 'Hello, World!'"); got != "Hello, World!\n" {
		t.Fatalf("echo = %q", got)
	}
	out, ev := execute(t, k, "echo $FOO", map[string]string{"FOO": "bar"})
	if out.Status != "ok" || ev.stream(codeinterp.EventStdout) != "bar\n" {
		t.Fatalf("per-run env = %+v %q", out, ev.trace())
	}
	if got := stdoutOf(t, k, "echo ${FOO:-default}"); got != "default\n" {
		t.Fatalf("env after the run = %q", got)
	}
	// A variable the cell had keeps its value and stays unexported.
	mustRun(t, k, "KEEP=mine", "ok")
	if _, ev = execute(t, k, `echo "$KEEP"`, map[string]string{"KEEP": "run"}); ev.stream(codeinterp.EventStdout) != "run\n" {
		t.Fatalf("KEEP during the run = %q", ev.trace())
	}
	if got := stdoutOf(t, k, `echo "$KEEP"; sh -c 'echo "child:${KEEP:-unset}"'`); got != "mine\nchild:unset\n" {
		t.Fatalf("KEEP after the run = %q", got)
	}

	// cd, variables, arrays and functions persist: the cell runs in this
	// shell, and declare at the top of a cell is global.
	mustRun(t, k, "mkdir sub && cd sub; declare -a arr=(1 2 3); greet() { echo \"hi $1\"; }", "ok")
	if got := stdoutOf(t, k, "pwd; echo ${arr[1]}; greet you"); !strings.HasSuffix(got, "/sub\n2\nhi you\n") {
		t.Fatalf("persisted state = %q", got)
	}

	// A failed last command is the run's error, as in E2B's bash kernel;
	// earlier failures are not.
	mustRun(t, k, "false; echo fine", "ok")
	ev = mustRun(t, k, "echo before; false", "error")
	if e := lastEvent(ev); e.Kind != codeinterp.EventError || e.ErrName != "" || e.ErrValue != "1" || e.ErrTraceback != "" ||
		ev.stream(codeinterp.EventStdout) != "before\n" {
		t.Fatalf("failed command = %q %+v", ev.trace(), e)
	}
	// return ends the cell with its status; a stray break or continue ends
	// it too, without reaching the driver's loop.
	ev = mustRun(t, k, "echo a; return 4; echo b", "error")
	if ev.stream(codeinterp.EventStdout) != "a\n" || lastEvent(ev).ErrValue != "4" {
		t.Fatalf("return = %q", ev.trace())
	}
	for _, stray := range []string{"break", "continue"} {
		if got := stdoutOf(t, k, "echo a; "+stray+"; echo b"); got != "a\n" {
			t.Fatalf("%s = %q", stray, got)
		}
	}

	// The cell's set -u, its own fd 3 and 4, a function named printf and a
	// NUL byte in the code leave the protocol alone.
	mustRun(t, k, "set -u; printf() { echo shadowed; }", "ok")
	if got := stdoutOf(t, k, "echo ${arr[0]}"); got != "1\n" {
		t.Fatalf("after set -u = %q", got)
	}
	mustRun(t, k, "set +u; unset -f printf", "ok")
	if got := stdoutOf(t, k, "exec 3>/dev/null 4>/dev/null; echo fds"); got != "fds\n" {
		t.Fatalf("fd 3 and 4 = %q", got)
	}
	// A descriptor a cell opens with {var} stays the cell's in the next
	// one: the protocol descriptors, closed while a cell runs, sit where
	// such a descriptor never lands, so restoring them replaces nothing.
	mustRun(t, k, "exec {logfd}>fds.log; echo \"$logfd\" >&2", "ok")
	if got := stdoutOf(t, k, "echo kept >&\"$logfd\"; exec {logfd}>&-; cat fds.log"); got != "kept\n" {
		t.Fatalf("a cell's own descriptor across cells = %q", got)
	}
	if got := stdoutOf(t, k, "echo a\x00b"); got != "ab\n" {
		t.Fatalf("NUL = %q", got)
	}
	if got := stdoutOf(t, k, "echo next"); got != "next\n" {
		t.Fatalf("run after a NUL = %q", got)
	}
	// UTF-8 goes through; the driver's LC_ALL=C for reading frames does not
	// reach the cell.
	wantLC := os.Getenv("LC_ALL")
	if wantLC == "" {
		wantLC = "unset"
	}
	if got := stdoutOf(t, k, "printf '%s\\n' 'hé 你'; echo \"${LC_ALL:-unset}\""); got != "hé 你\n"+wantLC+"\n" {
		t.Fatalf("UTF-8 = %q", got)
	}

	// An interrupt unwinds functions and skips the rest of the cell.
	for _, code := range []string{
		"spin() { while :; do :; done; }\nspin\necho not-reached",
		"sleep 20; echo not-reached",
		"for i in 1 2 3; do sleep 20; done; echo not-reached",
	} {
		interruptAfter(k, 500*time.Millisecond)
		out, ev := execute(t, k, code, nil)
		if !out.Interrupted() || out.Died || ev.stream(codeinterp.EventStdout) != "" {
			t.Fatalf("interrupted %q = %+v %q", code, out, ev.trace())
		}
	}
	if got := stdoutOf(t, k, "greet again"); got != "hi again\n" {
		t.Fatalf("after interrupts = %q", got)
	}

	if out, _ := execute(t, k, "exit 7", nil); !out.Died {
		t.Fatalf("exit outcome = %+v", out)
	}
}

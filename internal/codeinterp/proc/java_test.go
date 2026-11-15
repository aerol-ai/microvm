package proc

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

func TestJavaDriver(t *testing.T) {
	k, cwd := launchLang(t, codeinterp.LangJava)

	// E2B's tests.
	if got := stdoutOf(t, k, `System.out.println("Hello, World!")`); got != "Hello, World!\n" {
		t.Fatalf("println = %q", got)
	}
	if got := valueOf(t, k, `System.getProperty("user.dir")`); !strings.HasPrefix(got, `main:"`) || !strings.HasSuffix(got, filepath.Base(cwd)+`"`) {
		t.Fatalf("user.dir = %q", got)
	}
	// A run's variables are System properties, as on E2B, and what
	// System.getenv returns.
	_, ev := execute(t, k, `System.getProperty("FOO") + "/" + System.getenv("FOO")`, map[string]string{"FOO": "bar"})
	if got := results(ev); len(got) != 1 || got[0] != `main:"bar/bar"` {
		t.Fatalf("per-run env = %q", ev.trace())
	}
	if got := valueOf(t, k, `System.getProperty("FOO", "default") + "/" + System.getenv("FOO")`); got != `main:"default/null"` {
		t.Fatalf("env after the run = %q", got)
	}

	// A cell is split into snippets; declarations of every kind stay, and
	// the jshell default imports are there.
	ev = mustRun(t, k, "List<Integer> xs = List.of(1, 2, 3);\nint sum(List<Integer> l) { return l.stream().mapToInt(i -> i).sum(); }\nclass Box { int v = 4; }\nsum(xs) + new Box().v", "ok")
	if got := results(ev); len(got) != 1 || got[0] != "main:10" {
		t.Fatalf("multi-snippet cell = %q", ev.trace())
	}
	if got := valueOf(t, k, "sum(xs)"); got != "main:6" {
		t.Fatalf("method from the last cell = %q", got)
	}
	if got := mustRun(t, k, "int y = 1;\nSystem.out.print(\"\")", "ok").trace(); len(got) != 1 {
		t.Fatalf("declarations and statements showed a value: %q", got)
	}
	if got := stdoutOf(t, k, `System.out.println("é 你")`); got != "é 你\n" {
		t.Fatalf("UTF-8 = %q", got)
	}

	ev = mustRun(t, k, "int z = y +\n  foo;", "error")
	if e := lastEvent(ev); e.ErrName != "CompilationError" || !strings.Contains(e.ErrValue, "cannot find symbol") ||
		!strings.Contains(e.ErrTraceback, "Error: cannot find symbol") || !strings.Contains(e.ErrTraceback, "\n  foo;\n  ^^^") {
		t.Fatalf("compile error = %+v", e)
	}
	// The run stops at the first failing snippet.
	ev = mustRun(t, k, "System.out.println(\"a\");\nint q = 1 / 0;\nSystem.out.println(\"b\");", "error")
	if e := lastEvent(ev); ev.stream(codeinterp.EventStdout) != "a\n" || e.ErrName != "ArithmeticException" || e.ErrValue != "/ by zero" {
		t.Fatalf("first failure = %q %+v", ev.trace(), e)
	}
	ev = mustRun(t, k, "void boom() { throw new IllegalStateException(\"boom\", new RuntimeException(\"root\")); }\nboom()", "error")
	if e := lastEvent(ev); e.ErrName != "IllegalStateException" || e.ErrValue != "boom" ||
		!strings.HasPrefix(e.ErrTraceback, "java.lang.IllegalStateException: boom\n\tat .boom(#") ||
		!strings.Contains(e.ErrTraceback, "Caused by: java.lang.RuntimeException: root") || strings.Contains(e.ErrTraceback, "jdk.jshell") {
		t.Fatalf("exception = %+v", e)
	}
	ev = mustRun(t, k, "void later() { notYet(); }\nlater()", "error")
	if e := lastEvent(ev); e.ErrName != "UnresolvedReferenceException" || !strings.Contains(e.ErrValue, "notYet()") {
		t.Fatalf("unresolved = %+v", e)
	}

	interruptAfter(k, 500*time.Millisecond)
	if out, ev := execute(t, k, "Thread.sleep(20000);\nSystem.out.println(\"not reached\");", nil); !out.Interrupted() || out.Died || ev.stream(codeinterp.EventStdout) != "" {
		t.Fatalf("interrupted sleep = %+v %q", out, ev.trace())
	}
	if got := valueOf(t, k, "sum(xs)"); got != "main:6" {
		t.Fatalf("state after the interrupt = %q", got)
	}

	if out, _ := execute(t, k, "System.exit(3)", nil); !out.Died {
		t.Fatalf("System.exit outcome = %+v", out)
	}
}

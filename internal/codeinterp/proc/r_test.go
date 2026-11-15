package proc

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

func TestRDriver(t *testing.T) {
	k, cwd := launchLang(t, codeinterp.LangR)

	// E2B's tests: print() writes to stdout; a visible value is printed as
	// the console does and sent as a display (not main) result.
	ev := mustRun(t, k, `print("Hello, World!")`, "ok")
	if ev.stream(codeinterp.EventStdout) != "[1] \"Hello, World!\"\n" || len(results(ev)) != 0 {
		t.Fatalf("print = %q", ev.trace())
	}
	if got := valueOf(t, k, "getwd()"); !strings.HasPrefix(got, `[1] "`) || !strings.HasSuffix(got, filepath.Base(cwd)+`"`) {
		t.Fatalf("getwd() = %q", got)
	}
	if _, ev = execute(t, k, "Sys.getenv('FOO')", map[string]string{"FOO": "bar"}); !reflect.DeepEqual(results(ev), []string{`[1] "bar"`}) {
		t.Fatalf("per-run env = %q", ev.trace())
	}
	if got := valueOf(t, k, "Sys.getenv('FOO', unset = 'default')"); got != `[1] "default"` {
		t.Fatalf("env after the run = %q", got)
	}

	// Every visible top-level value is shown, in order; invisible ones and
	// assignments are not.
	ev = mustRun(t, k, "1\ninvisible(2)\ny <- 3\ny\ndata.frame(a = 1:2)", "ok")
	if got := results(ev); !reflect.DeepEqual(got, []string{"[1] 1", "[1] 3", "  a\n1 1\n2 2"}) {
		t.Fatalf("visible values = %q", got)
	}
	// Quotes, backslashes, tabs and UTF-8 survive the JSON the driver writes.
	if got := valueOf(t, k, `cat("x\n"); "tab\there \"q\" \\ é"`); got != `[1] "tab\there \"q\" \\ `+"é"+`"` {
		t.Fatalf("escaped value = %q", got)
	}

	// Warnings and messages go to stderr at once, with the user's call.
	ev = mustRun(t, k, `f <- function() { warning("careful"); 5 }`+"\nf()\nmessage(\"note\")", "ok")
	if errs := ev.stream(codeinterp.EventStderr); !strings.Contains(errs, "Warning message:\nIn f() : careful\n") || !strings.Contains(errs, "note\n") {
		t.Fatalf("stderr = %q", errs)
	}
	if got := results(ev); !reflect.DeepEqual(got, []string{"[1] 5"}) {
		t.Fatalf("value after a warning = %q", got)
	}

	// Errors: the console's line, no driver call; parse errors too.
	if e := lastEvent(mustRun(t, k, `stop("top")`, "error")); e.ErrName != "ERROR" || e.ErrValue != "top" || e.ErrTraceback != "Error: top" {
		t.Fatalf("stop at the top = %+v", e)
	}
	if e := lastEvent(mustRun(t, k, "x <- (", "error")); e.ErrName != "ERROR" || !strings.Contains(e.ErrValue, "unexpected end of input") ||
		!strings.HasPrefix(e.ErrTraceback, "Error: ") {
		t.Fatalf("parse error = %+v", e)
	}
	// The run stops at the first error.
	ev = mustRun(t, k, "cat(\"a\\n\")\nlog(\"x\")\ncat(\"b\\n\")", "error")
	if e := lastEvent(ev); ev.stream(codeinterp.EventStdout) != "a\n" || e.ErrTraceback != `Error in log("x") : non-numeric argument to mathematical function` {
		t.Fatalf("first error = %q %+v", ev.trace(), e)
	}

	interruptAfter(k, 500*time.Millisecond)
	if out, ev := execute(t, k, "Sys.sleep(20); cat(\"not reached\\n\")", nil); !out.Interrupted() || out.Died || ev.stream(codeinterp.EventStdout) != "" {
		t.Fatalf("interrupted sleep = %+v %q", out, ev.trace())
	}
	if got := valueOf(t, k, "y"); got != "[1] 3" {
		t.Fatalf("state after the interrupt = %q", got)
	}

	if out, _ := execute(t, k, "quit(status = 3)", nil); !out.Died {
		t.Fatalf("quit outcome = %+v", out)
	}
}

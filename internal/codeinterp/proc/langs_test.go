package proc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	"github.com/aerol-ai/microvm/internal/codeinterp/drivers"
)

// launchLang starts a real kernel for lang, or skips when the sandbox-like
// test machine has no interpreter for it (or one too old for the driver).
func launchLang(t *testing.T, lang string) (*kernel, string) {
	t.Helper()
	d, ok := drivers.Lookup(lang)
	if !ok {
		t.Fatalf("no driver for %s", lang)
	}
	env := os.Environ()
	if _, err := findProgram(d, envValue(env, "PATH")); err != nil {
		t.Skipf("no %s interpreter: %v", lang, err)
	}
	cwd := t.TempDir()
	l := New(Config{Env: func() []string { return env }, DriverDir: t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), codeinterp.LaunchTimeout)
	defer cancel()
	k, err := l.Launch(ctx, codeinterp.Spec{Language: lang, Cwd: cwd})
	if err != nil {
		if strings.Contains(err.Error(), " or newer") {
			t.Skipf("%s interpreter too old: %v", lang, err)
		}
		t.Fatalf("Launch %s: %v", lang, err)
	}
	t.Cleanup(func() { _ = k.Close() })
	return k.(*kernel), cwd
}

// merged is trace with adjacent output of one stream joined: how a pipe
// cuts output into reads is not part of any driver's contract.
func merged(ev *events) []string {
	var out []string
	for _, s := range ev.trace() {
		if n := len(out); n > 0 && s[:4] == out[n-1][:4] && (s[:4] == "out:" || s[:4] == "err:") {
			out[n-1] += s[4:]
			continue
		}
		out = append(out, s)
	}
	return out
}

// results returns the text/plain of every result, with "main:" in front
// of a main one.
func results(ev *events) []string {
	var out []string
	for _, e := range ev.list() {
		if e.Kind == codeinterp.EventResult {
			text := fmt.Sprint(e.Bundle["text/plain"])
			if e.Main {
				text = "main:" + text
			}
			out = append(out, text)
		}
	}
	return out
}

// valueOf runs code, which must succeed, and returns its one result.
func valueOf(t *testing.T, k codeinterp.Kernel, code string) string {
	t.Helper()
	ev := mustRun(t, k, code, "ok")
	got := results(ev)
	if len(got) != 1 {
		t.Fatalf("run %q: results %q, want one (events %q)", code, got, ev.trace())
	}
	return got[0]
}

// stdoutOf runs code, which must succeed, and returns its stdout.
func stdoutOf(t *testing.T, k codeinterp.Kernel, code string) string {
	t.Helper()
	return mustRun(t, k, code, "ok").stream(codeinterp.EventStdout)
}

// interruptAfter interrupts the kernel's run once d has passed.
func interruptAfter(k *kernel, d time.Duration) {
	go func() {
		time.Sleep(d)
		_ = k.Interrupt()
	}()
}

func lastEvent(ev *events) codeinterp.Event {
	all := ev.list()
	if len(all) == 0 {
		return codeinterp.Event{}
	}
	return all[len(all)-1]
}

// largeLines is what every language's "large" snippet prints: 300 KiB of
// numbered lines, more than any pipe or read buffer holds.
const largeLines = 38400

func checkLargeOutput(t *testing.T, got string) {
	t.Helper()
	if len(got) != largeLines*8 {
		t.Fatalf("large output = %d bytes, want %d", len(got), largeLines*8)
	}
	for i, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if line != fmt.Sprintf("%07d", i) {
			t.Fatalf("large output line %d = %q", i, line)
		}
	}
}

// langCase is one language's code for the checks every driver must pass.
type langCase struct {
	lang string
	// set makes x 5 and prints nothing.
	set string
	// printX prints x and a newline; printErr prints "e" and a newline to
	// stderr.
	printX, printErr string
	// resultX ends with x * 2 as the cell's value, which the driver sends
	// as a result with text/plain result (main or not). Empty: the
	// language has no values (bash).
	resultX, result string
	main            bool
	// fail raises an error the driver reports as failName / failValue,
	// with failTB in the traceback. It runs after a printX line.
	fail, failName, failValue, failTB string
	// readEnv prints $RUN_VAR, or "unset" when it is not set.
	readEnv string
	// cwd prints the working directory.
	cwd string
	// busy loops for ever, counting in n; nPositive prints "yes" if n > 0.
	busy, nPositive string
	// large prints largeLines lines "%07d"; tail prints "tail".
	large, tail string
	// child starts "sleep 60" in the background and prints its pid.
	child string
	// listFDs runs "ls -l /proc/self/fd" as a child process and prints its
	// output: the descriptors a program the cell starts inherits.
	listFDs string
}

var langCases = []langCase{
	{
		lang:     codeinterp.LangJavaScript,
		set:      "let x = 5",
		printX:   "console.log(x)",
		printErr: "console.error('e')",
		resultX:  "x * 2", result: "10", main: true,
		fail: "throw new TypeError('bad')", failName: "TypeError", failValue: "bad", failTB: "TypeError: bad\n    at <cell>:2:7",
		readEnv:   "console.log(process.env.RUN_VAR ?? 'unset')",
		cwd:       "console.log(process.cwd())",
		busy:      "let n = 0; while (true) { n++ }",
		nPositive: "console.log(n > 0 ? 'yes' : 'no')",
		large:     "process.stdout.write(Array.from({ length: 38400 }, (_, i) => String(i).padStart(7, '0') + '\\n').join(''))",
		tail:      "console.log('tail')",
		child:     "const cp = require('node:child_process').spawn('sleep', ['60'], { stdio: 'ignore' }); console.log(cp.pid)",
		listFDs:   "process.stdout.write(require('node:child_process').execFileSync('ls', ['-l', '/proc/self/fd']).toString())",
	},
	{
		lang:     codeinterp.LangTypeScript,
		set:      "let x: number = 5",
		printX:   "console.log(x as number)",
		printErr: "console.error('e')",
		resultX:  "x * 2", result: "10", main: true,
		fail: "const why: string = 'bad'\nthrow new TypeError(why)", failName: "TypeError", failValue: "bad", failTB: "TypeError: bad\n    at <cell>:3:7",
		readEnv:   "console.log(process.env.RUN_VAR ?? 'unset')",
		cwd:       "console.log(process.cwd())",
		busy:      "let n: number = 0; while (true) { n++ }",
		nPositive: "console.log(n > 0 ? 'yes' : 'no')",
		large:     "process.stdout.write(Array.from({ length: 38400 }, (_, i: number) => String(i).padStart(7, '0') + '\\n').join(''))",
		tail:      "console.log('tail')",
		child:     "const cp = require('node:child_process').spawn('sleep', ['60'], { stdio: 'ignore' }); console.log(cp.pid)",
		listFDs:   "process.stdout.write(require('node:child_process').execFileSync('ls', ['-l', '/proc/self/fd']).toString())",
	},
	{
		lang:     codeinterp.LangBash,
		set:      "x=5",
		printX:   `echo "$x"`,
		printErr: "echo e >&2",
		fail:     "(exit 3)", failName: "", failValue: "3",
		readEnv:   `echo "${RUN_VAR:-unset}"`,
		cwd:       "pwd",
		busy:      "n=0; while :; do n=$((n + 1)); done",
		nPositive: "(( n > 0 )) && echo yes || echo no",
		large:     `for ((i = 0; i < 38400; i++)); do printf '%07d\n' "$i"; done`,
		tail:      "echo tail",
		child:     "sleep 60 >/dev/null 2>&1 & echo $!",
		listFDs:   "ls -l /proc/self/fd",
	},
	{
		lang:     codeinterp.LangR,
		set:      "x <- 5",
		printX:   `cat(x, "\n", sep = "")`,
		printErr: `cat("e\n", file = stderr())`,
		resultX:  "x * 2", result: "[1] 10", main: false,
		fail: `f <- function() stop("bad")` + "\nf()", failName: "ERROR", failValue: "bad", failTB: "Error in f() : bad",
		readEnv:   `cat(Sys.getenv("RUN_VAR", "unset"), "\n", sep = "")`,
		cwd:       `cat(getwd(), "\n", sep = "")`,
		busy:      "n <- 0; repeat { n <- n + 1 }",
		nPositive: `cat(if (n > 0) "yes" else "no", "\n", sep = "")`,
		large:     `cat(sprintf("%07d\n", 0:38399), sep = "")`,
		tail:      `cat("tail\n")`,
		child:     `system("sleep 60 >/dev/null 2>&1 & echo $!")`,
		listFDs:   `invisible(system("ls -l /proc/self/fd"))`,
	},
	{
		lang:     codeinterp.LangJava,
		set:      "int x = 5;",
		printX:   "System.out.println(x);",
		printErr: `System.err.println("e");`,
		resultX:  "x * 2", result: "10", main: true,
		fail: `Integer.parseInt("bad")`, failName: "NumberFormatException", failValue: `For input string: "bad"`,
		failTB:    "java.lang.NumberFormatException: For input string: \"bad\"\n\tat ",
		readEnv:   `System.out.println(System.getenv().getOrDefault("RUN_VAR", "unset"))`,
		cwd:       `System.out.println(System.getProperty("user.dir"))`,
		busy:      "long n = 0;\nwhile (true) { n++; }",
		nPositive: `System.out.println(n > 0 ? "yes" : "no")`,
		large:     `StringBuilder sb = new StringBuilder(); for (int i = 0; i < 38400; i++) sb.append(String.format("%07d%n", i)); System.out.print(sb);`,
		tail:      `System.out.println("tail")`,
		child:     `Process p = new ProcessBuilder("sleep", "60").start(); System.out.println(p.pid());`,
		listFDs:   `System.out.print(new String(new ProcessBuilder("ls", "-l", "/proc/self/fd").start().getInputStream().readAllBytes()));`,
	},
}

// TestLanguageDrivers runs the same checks against every driver whose
// interpreter is installed: state, ordering, results, errors, env, cwd,
// interrupts, large output and Close.
func TestLanguageDrivers(t *testing.T) {
	for _, tc := range langCases {
		t.Run(tc.lang, func(t *testing.T) {
			t.Parallel()
			k, cwd := launchLang(t, tc.lang)

			ev := mustRun(t, k, tc.set, "ok")
			if got := ev.trace(); len(got) != 1 || got[0] != "count:1" {
				t.Fatalf("set = %q", got)
			}
			if got := mustRun(t, k, tc.printX, "ok").stream(codeinterp.EventStdout); got != "5\n" {
				t.Fatalf("printX stdout = %q", got)
			}
			if got := mustRun(t, k, tc.printErr, "ok").stream(codeinterp.EventStderr); got != "e\n" {
				t.Fatalf("printErr stderr = %q", got)
			}

			if tc.resultX != "" {
				ev = mustRun(t, k, tc.printX+"\n"+tc.resultX, "ok")
				want := []string{"count:4", "out:5\n", fmt.Sprintf("result:%s:%v", tc.result, tc.main)}
				if got := merged(ev); strings.Join(got, "|") != strings.Join(want, "|") {
					t.Fatalf("output then result = %q, want %q", got, want)
				}
			} else {
				mustRun(t, k, tc.printX, "ok")
			}

			ev = mustRun(t, k, tc.printX+"\n"+tc.fail, "error")
			e := lastEvent(ev)
			if e.Kind != codeinterp.EventError || e.ErrName != tc.failName || e.ErrValue != tc.failValue ||
				!strings.Contains(e.ErrTraceback, tc.failTB) || ev.stream(codeinterp.EventStdout) != "5\n" {
				t.Fatalf("fail events = %q, last %+v", ev.trace(), e)
			}
			for _, leak := range []string{"_driver.", "aerolvm-codeinterp"} {
				if strings.Contains(e.ErrTraceback, leak) {
					t.Fatalf("traceback shows the driver: %q", e.ErrTraceback)
				}
			}

			out, ev := execute(t, k, tc.readEnv, map[string]string{"RUN_VAR": "v"})
			if out.Status != "ok" || ev.stream(codeinterp.EventStdout) != "v\n" {
				t.Fatalf("env run = %+v %q", out, ev.trace())
			}
			if got := mustRun(t, k, tc.readEnv, "ok").stream(codeinterp.EventStdout); got != "unset\n" {
				t.Fatalf("env after the run = %q", got)
			}

			if got := mustRun(t, k, tc.cwd, "ok").stream(codeinterp.EventStdout); !strings.HasSuffix(strings.TrimSpace(got), filepath.Base(cwd)) {
				t.Fatalf("cwd = %q, want %s", got, cwd)
			}

			// SIGINT to an idle kernel must not end it.
			if err := k.Interrupt(); err != nil {
				t.Fatal(err)
			}
			time.Sleep(200 * time.Millisecond)
			if got := mustRun(t, k, tc.printX, "ok").stream(codeinterp.EventStdout); got != "5\n" {
				t.Fatalf("after an idle interrupt = %q", got)
			}

			go func() {
				time.Sleep(time.Second)
				_ = k.Interrupt()
			}()
			out, ev = execute(t, k, tc.busy, nil)
			if !out.Interrupted() || out.Died {
				t.Fatalf("busy loop outcome = %+v (%q)", out, ev.trace())
			}
			if got := mustRun(t, k, tc.nPositive, "ok").stream(codeinterp.EventStdout); got != "yes\n" {
				t.Fatalf("state after the interrupt = %q", got)
			}

			ev = mustRun(t, k, tc.large+"\n"+tc.tail, "ok")
			got := ev.stream(codeinterp.EventStdout)
			if !strings.HasSuffix(got, "tail\n") {
				t.Fatalf("large output does not end with the tail: %q", got[max(0, len(got)-40):])
			}
			checkLargeOutput(t, strings.TrimSuffix(got, "tail\n"))

			ev = mustRun(t, k, tc.child, "ok")
			pid, err := strconv.Atoi(strings.TrimSpace(ev.stream(codeinterp.EventStdout)))
			if err != nil {
				t.Fatalf("child pid: %v (%q)", err, ev.trace())
			}
			if err := k.Close(); err != nil {
				t.Fatal(err)
			}
			waitClosed(t, k.Done(), "driver exit")
			deadline := time.Now().Add(10 * time.Second)
			for {
				if err := syscall.Kill(pid, 0); err == syscall.ESRCH || isZombie(pid) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("child %d survived Close", pid)
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

// The request and event pipes belong to the driver. A program a cell
// starts must not hold them: it could read the driver's requests or write
// frames, and one left running in the background kept the pipes open after
// the driver was gone. bash's descriptors from "exec {var}<&3" are not
// close-on-exec, and R kept 3 and 4 open after reopening them, so both
// leaked them to every child.
func TestDriverChildrenGetNoProtocolPipes(t *testing.T) {
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("needs /proc (Linux)")
	}
	cases := append([]langCase{{lang: codeinterp.LangPython, set: "x = 5", listFDs: "import os\nos.system('ls -l /proc/self/fd')"}}, langCases...)
	for _, tc := range cases {
		t.Run(tc.lang, func(t *testing.T) {
			t.Parallel()
			k, _ := launchLang(t, tc.lang)
			// A pipe's two ends share its inode, which /proc shows as
			// "pipe:[inode]"; the host's ends name the driver's pipes.
			var pipes []string
			for _, f := range []*os.File{k.reqW, k.evR} {
				info, err := f.Stat()
				if err != nil {
					t.Fatal(err)
				}
				pipes = append(pipes, fmt.Sprintf("pipe:[%d]", info.Sys().(*syscall.Stat_t).Ino))
			}
			// The driver itself holds them, so the check below can fail.
			var held strings.Builder
			entries, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", k.pid))
			for _, e := range entries {
				target, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", k.pid, e.Name()))
				held.WriteString(target + "\n")
			}
			for _, p := range pipes {
				if !strings.Contains(held.String(), p) {
					t.Fatalf("the driver holds no %s: %q", p, held.String())
				}
			}
			out := mustRun(t, k, tc.listFDs, "ok").stream(codeinterp.EventStdout)
			if !strings.Contains(out, " 0 -> ") {
				t.Fatalf("no descriptor list: %q", out)
			}
			for _, p := range pipes {
				if strings.Contains(out, p) {
					t.Errorf("a child holds the driver's %s:\n%s", p, out)
				}
			}
			// The context still works afterwards.
			mustRun(t, k, tc.set, "ok")
		})
	}
}

func TestLanguageCasesCoverEveryDriver(t *testing.T) {
	seen := map[string]bool{codeinterp.LangPython: true} // python_test.go
	for _, tc := range langCases {
		seen[tc.lang] = true
	}
	for _, lang := range drivers.Languages() {
		if !seen[lang] {
			t.Errorf("no langCases entry for the %s driver", lang)
		}
	}
}

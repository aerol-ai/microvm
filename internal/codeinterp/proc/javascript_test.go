package proc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

func TestJavaScriptDriver(t *testing.T) {
	k, cwd := launchLang(t, codeinterp.LangJavaScript)

	// Top-level declarations of every kind stay for the next run.
	mustRun(t, k, "let a = 1; const b = 2; var c = 3; function f() { return 4 } class K { v = 5 }", "ok")
	if got := valueOf(t, k, "a + b + c + f() + new K().v"); got != "main:15" {
		t.Fatalf("declarations = %q", got)
	}
	// Top-level await (E2B's test), whose declarations stay too.
	if got := valueOf(t, k, "await Promise.resolve('Hello World!')"); got != "main:'Hello World!'" {
		t.Fatalf("top-level await = %q", got)
	}
	mustRun(t, k, "const d = await Promise.resolve(6)", "ok")
	if got := valueOf(t, k, "d"); got != "main:6" {
		t.Fatalf("awaited declaration = %q", got)
	}
	// A promise the cell returns is awaited.
	if got := valueOf(t, k, "Promise.resolve(42)"); got != "main:42" {
		t.Fatalf("returned promise = %q", got)
	}
	if got := valueOf(t, k, "({ a: [1, 2] })"); got != "main:{ a: [ 1, 2 ] }" {
		t.Fatalf("object = %q", got)
	}
	if got := mustRun(t, k, "undefined", "ok").trace(); len(got) != 1 {
		t.Fatalf("undefined was shown: %q", got)
	}

	// Static imports work in a cell (E2B's test), and twice. The loader's
	// ExperimentalWarning went out before READY, not into a run.
	for i := 0; i < 2; i++ {
		ev := mustRun(t, k, "import { readFileSync } from 'fs'\nconsole.log(typeof readFileSync)", "ok")
		if ev.stream(codeinterp.EventStdout) != "function\n" || ev.stream(codeinterp.EventStderr) != "" {
			t.Fatalf("static import = %q", ev.trace())
		}
	}
	// Default, namespace and relative imports resolve against the cwd, as
	// does require.
	if err := os.WriteFile(filepath.Join(cwd, "mod.mjs"), []byte("export default 7\nexport const named = 8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "cjs.js"), []byte("module.exports = 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := valueOf(t, k, "import seven, * as ns from './mod.mjs'\nimport {\n  named as n2,\n} from './mod.mjs'\nimport 'node:path'\nseven + ns.named + n2 + require('./cjs.js')"); got != "main:32" {
		t.Fatalf("imports = %q", got)
	}
	if got := valueOf(t, k, "process.cwd()"); got != "main:'"+cwd+"'" && !strings.HasSuffix(got, filepath.Base(cwd)+"'") {
		t.Fatalf("cwd = %q", got)
	}

	ev := mustRun(t, k, "let q = ;", "error")
	if e := lastEvent(ev); e.ErrName != "SyntaxError" || e.ErrValue != "Unexpected token ';'" ||
		!strings.HasPrefix(e.ErrTraceback, "<cell>:1") || strings.Contains(e.ErrTraceback, "node:vm") {
		t.Fatalf("syntax error = %+v", e)
	}
	if e := lastEvent(mustRun(t, k, "throw 5", "error")); e.ErrName != "Error" || e.ErrValue != "5" || e.ErrTraceback != "Uncaught 5" {
		t.Fatalf("throw 5 = %+v", e)
	}
	if e := lastEvent(mustRun(t, k, "throw { get stack() { throw 1 } }", "error")); e.ErrValue != "unprintable thrown value" {
		t.Fatalf("hostile thrown value = %+v", e)
	}
	if e := lastEvent(mustRun(t, k, "await Promise.reject(new RangeError('rej'))", "error")); e.ErrName != "RangeError" || e.ErrValue != "rej" {
		t.Fatalf("rejected await = %+v", e)
	}

	// A timer's error from an earlier cell goes to stderr: it neither ends
	// the context nor becomes another run's error.
	mustRun(t, k, "setTimeout(() => { throw new Error('bg') }, 50); 1", "ok")
	ev = mustRun(t, k, "Promise.reject(new Error('unhandled'));\nawait new Promise(r => setTimeout(r, 300)); 2", "ok")
	if got := results(ev); len(got) != 1 || got[0] != "main:2" {
		t.Fatalf("run after a background error = %q", ev.trace())
	}
	if errs := ev.stream(codeinterp.EventStderr); !strings.Contains(errs, "Uncaught Error: bg") || !strings.Contains(errs, "Uncaught (in promise) Error: unhandled") {
		t.Fatalf("background errors on stderr = %q", errs)
	}

	// An interrupt ends a pending await; the context lives on.
	interruptAfter(k, 500*time.Millisecond)
	out, ev := execute(t, k, "await new Promise(r => setTimeout(r, 20000)); 'late'", nil)
	if !out.Interrupted() || out.Died || len(results(ev)) != 0 {
		t.Fatalf("interrupted await = %+v %q", out, ev.trace())
	}
	if got := valueOf(t, k, "a"); got != "main:1" {
		t.Fatalf("state after the interrupt = %q", got)
	}

	// The cell sees a REPL's argv and not the protocol's variables.
	if got := valueOf(t, k, "[process.argv.length, typeof process.env.AEROL_INTERP_NONCE]"); got != "main:[ 1, 'undefined' ]" {
		t.Fatalf("argv and env = %q", got)
	}

	out, _ = execute(t, k, "process.exit(3)", nil)
	if !out.Died {
		t.Fatalf("process.exit outcome = %+v", out)
	}
}

func TestTypeScriptDriver(t *testing.T) {
	k, _ := launchLang(t, codeinterp.LangTypeScript)

	// E2B's test.
	if got := stdoutOf(t, k, "const message: string = 'Hello, World!'; console.log(message)"); got != "Hello, World!\n" {
		t.Fatalf("stdout = %q", got)
	}
	if got := valueOf(t, k, "message.length"); got != "main:13" {
		t.Fatalf("declaration from the last cell = %q", got)
	}
	// Enums and namespaces need code, not just stripped types.
	if got := valueOf(t, k, "enum Color { Red, Green }\nColor.Green"); got != "main:1" {
		t.Fatalf("enum = %q", got)
	}
	if got := valueOf(t, k, "namespace NS { export const v = 2 }\nNS.v"); got != "main:2" {
		t.Fatalf("namespace = %q", got)
	}
	if got := valueOf(t, k, "interface P { x: number }\nfunction id<T>(v: T): T { return v }\nid<P>({ x: 3 }).x"); got != "main:3" {
		t.Fatalf("generics = %q", got)
	}
	if got := valueOf(t, k, "import type { Stats } from 'node:fs'\nconst v: number = await Promise.resolve(4); v"); got != "main:4" {
		t.Fatalf("await with types = %q", got)
	}
	// Stripped types leave positions alone: errors point at the TS source.
	ev := mustRun(t, k, "type T = { a: number }\nconst t: T = { a: 1 }\nthrow new Error('line 3')", "error")
	if e := lastEvent(ev); !strings.Contains(e.ErrTraceback, "<cell>:3:7") {
		t.Fatalf("error position = %+v", e)
	}
	if e := lastEvent(mustRun(t, k, "let broken: = 1", "error")); e.ErrName == "" || e.ErrValue == "" {
		t.Fatalf("type syntax error = %+v", e)
	}
}

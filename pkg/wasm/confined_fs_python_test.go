package wasm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pythonFixture is the standard CPython module the integration suite stages
// (integration-tests/fixtures/wasm/fetch.sh). It is large and gitignored, so
// the test skips without it; it runs wherever a developer has fetched it.
func pythonFixture(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("python fixture compile is slow; skipped in -short")
	}
	p, err := filepath.Abs(filepath.Join("..", "..", "integration-tests", "fixtures", "wasm", "python-3.12.0.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p); err != nil || st.Size() == 0 {
		t.Skip("python-3.12.0.wasm not fetched (integration-tests/fixtures/wasm/fetch.sh)")
	}
	return p
}

// The standard Python module runs with only /work mounted; its stdlib is
// embedded. A guest that plants a climbing symlink and reads through it must
// fail, while ordinary file work in /work keeps working.
func TestPythonGuestCannotLeaveWork(t *testing.T) {
	mod := pythonFixture(t)
	ctx := context.Background()
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })
	if err := eng.LoadModule(ctx, mod, LoadOptions{}); err != nil {
		t.Fatal(err)
	}
	fix := newEscapeFixture(t)
	run := func(script string) RunResult {
		t.Helper()
		res, err := eng.Run(ctx, Capabilities{
			Args:           []string{"python", "-c", script},
			Preopens:       []Preopen{{GuestPath: "/work", HostPath: fix.work}},
			WASIListenPort: WASIListenPortDisabled,
		}, "_start")
		if err != nil {
			t.Fatalf("python run: %v\nstdout:\n%s\nstderr:\n%s", err, res.Stdout, res.Stderr)
		}
		return res
	}

	// The reported escape verbatim, then deep enough to reach the host's
	// /etc from any temp dir.
	for _, target := range []string{"../../../../../../etc", strings.Repeat("../", 40) + "etc"} {
		res := run("import os; os.symlink('" + target + "','/work/x'); open('/work/x/hosts').read()")
		if res.ExitCode == 0 || !strings.Contains(res.Stderr, "PermissionError") {
			t.Fatalf("symlink to %s: exit=%d, want a PermissionError\nstdout:\n%s\nstderr:\n%s", target, res.ExitCode, res.Stdout, res.Stderr)
		}
		if _, err := os.Lstat(filepath.Join(fix.work, "x")); !os.IsNotExist(err) {
			t.Fatalf("the refused symlink exists on the host: %v", err)
		}
	}

	res := run(`
import os
def probe(name, f):
    try:
        r = f()
        print(name, "ok", r if isinstance(r, str) else "")
    except OSError as e:
        print(name, "err", type(e).__name__)
probe("read-planted-dir", lambda: open("/work/pre/canary.txt").read())
probe("read-planted-file", lambda: open("/work/prefile").read())
probe("read-planted-abs", lambda: open("/work/preabsdir/hosts").read())
probe("write-planted", lambda: open("/work/pre/planted", "w").write("x"))
probe("listdir-planted", lambda: ",".join(os.listdir("/work/pre")))
probe("hardlink-planted", lambda: os.link("/work/pre/canary.txt", "/work/hl"))
probe("rename-planted", lambda: os.rename("/work/pre/canary.txt", "/work/stolen"))
probe("remove-planted", lambda: os.remove("/work/pre/canary.txt"))
probe("write", lambda: open("/work/note.txt", "w").write("from python") and "")
probe("read", lambda: open("/work/note.txt").read())
probe("mkdir", lambda: os.mkdir("/work/pkg"))
probe("rename", lambda: os.rename("/work/note.txt", "/work/pkg/note.txt"))
probe("listdir", lambda: ",".join(sorted(os.listdir("/work/pkg"))))
probe("symlink-inside", lambda: os.symlink("pkg/note.txt", "/work/alias"))
probe("read-symlink", lambda: open("/work/alias").read())
probe("remove", lambda: os.remove("/work/pkg/note.txt"))
probe("rmdir", lambda: os.rmdir("/work/pkg"))
`)
	want := []string{
		"read-planted-dir err",
		"read-planted-file err",
		"read-planted-abs err",
		"write-planted err",
		"listdir-planted err",
		"hardlink-planted err",
		"rename-planted err",
		"remove-planted err",
		"write ok",
		"read ok from python",
		"mkdir ok",
		"rename ok",
		"listdir ok note.txt",
		"symlink-inside ok",
		"read-symlink ok from python",
		"remove ok",
		"rmdir ok",
	}
	lines := strings.Split(strings.TrimSpace(res.Stdout), "\n")
	if res.ExitCode != 0 || len(lines) != len(want) {
		t.Fatalf("probe: exit=%d\nstdout:\n%s\nstderr:\n%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	for i, w := range want {
		if !strings.HasPrefix(strings.TrimSpace(lines[i]), w) {
			t.Errorf("line %d = %q; want prefix %q", i, lines[i], w)
		}
	}
	fix.checkHostUntouched(t, res.Stdout)
}

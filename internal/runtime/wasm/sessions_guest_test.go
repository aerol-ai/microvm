package wasm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/internal/toolboxwire"
	"github.com/aerol-ai/microvm/pkg/models"
)

func guestSessionExec(t *testing.T, set *sessionSet, session string, argv []string, async bool) toolhost.CommandResult {
	t.Helper()
	res, err := set.exec(context.Background(), session, toolhost.SessionCommand{Text: strings.Join(argv, " "), Argv: argv}, async)
	if err != nil {
		t.Fatalf("exec %v: %v", argv, err)
	}
	return res
}

// Session commands run the sandbox's own module inside the engine, with
// the command line as argv: sync results, exit codes, /work, input to an
// async command, and kill on delete, on the stdio test guest.
func TestSessionsOnTheStdioGuest(t *testing.T) {
	d, id := streamDriver(t, Config{}, models.CreateSandboxRequest{})
	set, err := d.sessionsFor(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.create("s"); err != nil {
		t.Fatal(err)
	}

	res := guestSessionExec(t, set, "s", []string{"aerolstdio", "args", "hello world", "x"}, false)
	if res.ExitCode != 0 || res.Stdout != "hello world\nx\n" || res.Stderr != "" {
		t.Fatalf("args: %+v", res)
	}
	if res := guestSessionExec(t, set, "s", []string{"aerolstdio", "exit", "3"}, false); res.ExitCode != 3 {
		t.Fatalf("exit: %+v", res)
	}
	if res := guestSessionExec(t, set, "s", []string{"aerolstdio", "stderr", "oops"}, false); res.Stderr != "oops" || res.ExitCode != 0 {
		t.Fatalf("stderr: %+v", res)
	}
	// Commands share the sandbox's /work, not a shell's state.
	guestSessionExec(t, set, "s", []string{"aerolstdio", "write-work", "note.txt", "kept"}, false)
	inst, _ := d.instance(id)
	if b, err := os.ReadFile(filepath.Join(inst.workDir, "note.txt")); err != nil || string(b) != "kept" {
		t.Fatalf("/work file = %q %v", b, err)
	}

	// An async echo reads what /input sends while it runs, and a command
	// queued behind it waits.
	echo := guestSessionExec(t, set, "s", []string{"aerolstdio", "echo"}, true).ID
	queued := guestSessionExec(t, set, "s", []string{"aerolstdio", "args", "after"}, true).ID
	waitFor(t, "echo to run", func() bool {
		info, _ := set.command("s", echo)
		return info.Running
	})
	if err := set.input("s", echo, []byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "echoed input", func() bool {
		out, _, _ := set.logs("s", echo, toolboxwire.LogQuery{})
		return out.Text == "ping\n"
	})
	if info, _ := set.command("s", queued); info.Running || info.ExitCode != nil {
		t.Fatalf("queued command = %+v while echo runs", info)
	}

	// Deleting the session kills echo, which would read stdin forever,
	// and the queued command never runs.
	if err := set.delete("s"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "run slots to free", func() bool { return inst.streams.count() == 0 })
}

// Stopping the sandbox ends a session command still running.
func TestStopEndsSessionCommandOnTheGuest(t *testing.T) {
	d, id := streamDriver(t, Config{}, models.CreateSandboxRequest{})
	set, _ := d.sessionsFor(id)
	_, _ = set.create("s")
	cmd := guestSessionExec(t, set, "s", []string{"aerolstdio", "block"}, true).ID
	follow, err := set.follow("s", cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer follow.Close()
	if err := d.Stop(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-follow.Frames:
		for ok {
			_, ok = <-follow.Frames
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stop left the session command running")
	}
	if _, err := set.exec(context.Background(), "s", toolhost.SessionCommand{Argv: []string{"x"}}, false); !errors.Is(err, toolhost.ErrSessionStopped) {
		t.Fatalf("exec after stop = %v", err)
	}
}

// TestSessionRealPython runs `python -c "print(1)"` as a session command
// when the sandbox's own module is CPython for WASI, if the integration
// fixture has been fetched (integration-tests/fixtures/wasm/fetch.sh).
func TestSessionRealPython(t *testing.T) {
	python, err := filepath.Abs(filepath.Join("..", "..", "..", "integration-tests", "fixtures", "wasm", "python-3.12.0.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(python); err != nil {
		t.Skip("python-3.12.0.wasm not fetched; run integration-tests/fixtures/wasm/fetch.sh")
	}
	d, id := streamDriverWith(t, Config{DefaultWallTimeout: 2 * time.Minute}, models.CreateSandboxRequest{Image: "python.wasm"}, python)
	set, _ := d.sessionsFor(id)
	_, _ = set.create("py")
	// The toolhost splits `python -c "print(1)"` into this argv.
	res := guestSessionExec(t, set, "py", []string{"python", "-c", "print(1)"}, false)
	if res.ExitCode != 0 || res.Stdout != "1\n" {
		t.Fatalf("python -c: %+v", res)
	}
}

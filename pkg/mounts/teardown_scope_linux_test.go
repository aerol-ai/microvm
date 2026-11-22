//go:build linux

package mounts

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Teardown and the sweep stop mount tools that /proc lists, as root in the
// helper. These tests (review round 1 of PR 8) start a stand-in tool as the
// tools' user that leaves its own process group for another one of its
// session, plus processes of other users that only look like a tool, and
// check that teardown stops the tool and nothing else.

const scopeToolUID = 65520

// TestTeardownScopeToolProcess is the stand-in tool: it tries to move into
// process group TEARDOWN_JOIN_PGID, writes how that went to TEARDOWN_OUT,
// and waits.
func TestTeardownScopeToolProcess(t *testing.T) {
	g := os.Getenv("TEARDOWN_JOIN_PGID")
	if g == "" {
		t.Skip("helper process")
	}
	pg, _ := strconv.Atoi(g)
	result := "joined"
	if err := syscall.Setpgid(0, pg); err != nil {
		result = "refused: " + err.Error()
	}
	if err := os.WriteFile(os.Getenv("TEARDOWN_OUT"), []byte(result), 0o644); err != nil {
		os.Exit(3)
	}
	time.Sleep(time.Hour)
}

// scopeBinary is this test binary where the tools' user can run it.
func scopeBinary(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "teardown-scope-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "mounts.test")
	if err := os.WriteFile(bin, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// scopeProc is a process a test started, with its end.
type scopeProc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func startScopeProc(t *testing.T, cmd *exec.Cmd) *scopeProc {
	t.Helper()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &scopeProc{cmd: cmd, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-p.done })
	return p
}

// ended reports whether p ends within wait.
func (p *scopeProc) ended(wait time.Duration) bool {
	select {
	case <-p.done:
		return true
	default:
	}
	select {
	case <-p.done:
		return true
	case <-time.After(wait):
		return false
	}
}

// startScopeTool starts the stand-in tool with attr, marked for mark, and
// returns it once it has tried to join group join, with how that went.
func startScopeTool(t *testing.T, bin string, attr *syscall.SysProcAttr, mark string, join int) (*scopeProc, string) {
	t.Helper()
	out := filepath.Join(filepath.Dir(bin), fmt.Sprintf("out-%d", time.Now().UnixNano()))
	cmd := exec.Command(bin, "-test.run=^TestTeardownScopeToolProcess$")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", toolMarkEnv + "=" + mark, "TEARDOWN_JOIN_PGID=" + strconv.Itoa(join), "TEARDOWN_OUT=" + out}
	cmd.SysProcAttr = attr
	p := startScopeProc(t, cmd)
	for i := 0; i < 500; i++ {
		if raw, err := os.ReadFile(out); err == nil && len(raw) > 0 {
			return p, string(raw)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the stand-in tool never started")
	return nil, ""
}

// startOther starts a process that is not a tool: root's, in a group of its
// own, with argv and env as given.
func startOther(t *testing.T, env []string, argv ...string) *scopeProc {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	p := startScopeProc(t, cmd)
	t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	return p
}

// TestTeardownSignalsOnlyTools: in isolated mode, teardown of a sandbox's
// mounts stops its tool even after the tool left its process group, and
// stops nothing else: not the group the tool joined (another process's, or
// group 1), not a root process that carries the mount's marker, not a root
// process whose command line names the mount folder.
func TestTeardownSignalsOnlyTools(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	bin := scopeBinary(t)
	dir := filepath.Join(filepath.Dir(bin), "mounts")
	m := &Manager{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), tools: &ToolUser{UID: scopeToolUID, GID: scopeToolUID}}
	asTool := func() *syscall.SysProcAttr {
		return &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Uid: scopeToolUID, Gid: scopeToolUID, Groups: []uint32{}}}
	}

	// A tool that joined another process's group.
	victim := startOther(t, nil, "sleep", "3600")
	tool, joined := startScopeTool(t, bin, asTool(), dir+"/sb-1/0", victim.cmd.Process.Pid)
	t.Logf("tool join of group %d: %s", victim.cmd.Process.Pid, joined)
	// A root process with the mount's marker, and one whose command line
	// names the mount folder.
	marked := startOther(t, []string{toolMarkEnv + "=" + dir + "/sb-1/1"}, "sleep", "3600")
	named := startOther(t, nil, "sh", "-c", "sleep 3600", dir+"/sb-1/2")
	m.killToolsFor(dir + "/sb-1")
	if !tool.ended(5 * time.Second) {
		t.Error("the tool still runs")
	}
	if victim.ended(300 * time.Millisecond) {
		t.Error("the group the tool joined was stopped with it")
	}
	if marked.ended(0) {
		t.Error("a root process carrying the marker was stopped")
	}
	if named.ended(0) {
		t.Error("a root process naming the mount folder was stopped")
	}

	// A tool that joined group 1, where this test runs in it (a container's
	// init group): its teardown must not signal group 1.
	if pg, _ := syscall.Getpgid(0); pg != 1 {
		t.Logf("group 1 case skipped: this test runs in group %d", pg)
		return
	}
	victim2 := startOther(t, nil, "sleep", "3600")
	tool2, joined2 := startScopeTool(t, bin, asTool(), dir+"/sb-2/0", 1)
	t.Logf("tool join of group 1: %s", joined2)
	m.killToolsFor(dir + "/sb-2")
	if !tool2.ended(5 * time.Second) {
		t.Error("the tool in group 1 still runs")
	}
	if victim2.ended(300 * time.Millisecond) {
		t.Error("teardown signalled group 1")
	}
}

// TestToolCannotLeaveItsSession: a tool started as isolated tools start
// (toolProcAttr) leads a session of its own, so the kernel refuses its
// move into another process group, and teardown stops it alone.
func TestToolCannotLeaveItsSession(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	bin := scopeBinary(t)
	dir := filepath.Join(filepath.Dir(bin), "mounts")
	m := &Manager{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), tools: &ToolUser{UID: scopeToolUID, GID: scopeToolUID}}
	victim := startOther(t, nil, "sleep", "3600")
	tool, joined := startScopeTool(t, bin, toolProcAttr(m.tools), dir+"/sb-1/0", victim.cmd.Process.Pid)
	if !strings.HasPrefix(joined, "refused") {
		t.Fatalf("a tool in a session of its own moved into another group: %s", joined)
	}
	if pg, err := syscall.Getpgid(tool.cmd.Process.Pid); err != nil || pg != tool.cmd.Process.Pid {
		t.Fatalf("the tool's group is %d (%v), want its own", pg, err)
	}
	m.killToolsFor(dir + "/sb-1")
	if !tool.ended(5 * time.Second) {
		t.Error("the tool still runs")
	}
	if victim.ended(300 * time.Millisecond) {
		t.Error("another group was stopped with the tool")
	}
}

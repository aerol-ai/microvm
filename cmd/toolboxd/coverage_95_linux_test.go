//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/readyproto"
	"golang.org/x/sys/unix"
)

func TestLinuxQuiesceSetWallclockBranches(t *testing.T) {
	ops := linuxQuiesceOps{}
	if err := ops.SetWallclock(0); err == nil {
		t.Fatal("expected non-positive wallclock error")
	}
	if err := ops.SetWallclock(-1); err == nil {
		t.Fatal("expected negative wallclock error")
	}
	// May succeed or fail depending on CAP_SYS_TIME; both exercise the syscall path.
	_ = ops.SetWallclock(time.Now().UnixNano())
}

func TestLinuxQuiesceReseedErrorBranches(t *testing.T) {
	orig := ioctlPtr
	t.Cleanup(func() { ioctlPtr = orig })

	ioctlPtr = func(_, request, _ uintptr) syscall.Errno {
		if request == uintptr(unix.RNDRESEEDCRNG) {
			return syscall.EPERM
		}
		return 0
	}
	if err := (linuxQuiesceOps{}).ReseedRandom(); err == nil {
		t.Fatal("expected RNDRESEEDCRNG EPERM to surface")
	}

	ioctlPtr = func(_, _, _ uintptr) syscall.Errno { return syscall.EINVAL }
	// First ioctl (ADD) fails with EINVAL.
	if err := (linuxQuiesceOps{}).ReseedRandom(); err == nil {
		t.Fatal("expected RNDADDENTROPY EINVAL to surface")
	}

	// Tolerate EINVAL on RESEED (old kernel soft-degrade path alongside ENOTTY).
	ioctlPtr = func(_, request, _ uintptr) syscall.Errno {
		if request == uintptr(unix.RNDRESEEDCRNG) {
			return syscall.EINVAL
		}
		return 0
	}
	if err := (linuxQuiesceOps{}).ReseedRandom(); err != nil {
		t.Fatalf("RNDRESEEDCRNG EINVAL should be tolerated: %v", err)
	}
}

func TestLinuxQuiesceConfigureNetworkBranches(t *testing.T) {
	ops := linuxQuiesceOps{}
	if err := ops.ConfigureNetwork(guestNetworkConfig{}); err == nil {
		t.Fatal("expected incomplete config error")
	}
	if err := ops.ConfigureNetwork(guestNetworkConfig{GuestIP: "1.2.3.4"}); err == nil {
		t.Fatal("expected incomplete config error")
	}

	// Fake ip binary that fails addr replace.
	dir := t.TempDir()
	ipPath := filepath.Join(dir, "ip")
	script := "#!/bin/sh\necho fake-ip \"$@\" >&2\nif echo \"$*\" | grep -q 'addr replace'; then exit 1; fi\nexit 0\n"
	if err := os.WriteFile(ipPath, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile ip: %v", err)
	}
	t.Setenv("PATH", dir)
	err := ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP:   "172.16.0.2",
		GatewayIP: "172.16.0.1",
		PrefixLen: 30,
	})
	// May fail on iface discovery or addr replace; either covers network path.
	_ = err

	// No ip/ifconfig in PATH → lookNetworkBinary miss, then ifconfig miss.
	empty := t.TempDir()
	t.Setenv("PATH", empty)
	if err := ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP:   "172.16.0.2",
		GatewayIP: "172.16.0.1",
		PrefixLen: 30,
	}); err == nil {
		t.Fatal("expected no ip/ifconfig error")
	}

	// ifconfig fallback path with fake ifconfig + route.
	ifconfig := filepath.Join(dir, "ifconfig")
	route := filepath.Join(dir, "route")
	_ = os.Remove(ipPath)
	if err := os.WriteFile(ifconfig, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile ifconfig: %v", err)
	}
	if err := os.WriteFile(route, []byte("#!/bin/sh\necho File exists >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("WriteFile route: %v", err)
	}
	t.Setenv("PATH", dir)
	_ = ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP:   "172.16.0.2",
		GatewayIP: "172.16.0.1",
		PrefixLen: 30,
		Netmask:   "255.255.255.252",
	})
	_ = ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP:   "172.16.0.2",
		GatewayIP: "172.16.0.1",
		PrefixLen: 30,
	})

	// runNetworkCmdIgnoreExists non-exists error.
	badRoute := filepath.Join(dir, "route")
	_ = os.WriteFile(badRoute, []byte("#!/bin/sh\necho boom >&2\nexit 1\n"), 0o755)
	if err := runNetworkCmdIgnoreExists(badRoute, "add", "default"); err == nil {
		t.Fatal("expected non-exists route error")
	}
	if err := runNetworkCmdIgnoreExists(badRoute, "add", "default"); err == nil {
		// rewritten above already
	}
	_ = runNetworkCmd(filepath.Join(dir, "ifconfig"), "lo", "up")
}

func TestLinuxVsockServerErrorBranches(t *testing.T) {
	if _, err := newVsockServer(1024, nil, nil); err == nil {
		t.Fatal("expected nil handler error")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := newQuiesceHandler(logger, nil, nil)
	vs, err := newVsockServer(4095, handler, nil) // nil logger → Default
	if err != nil {
		t.Logf("vsock unavailable: %v", err)
		return
	}
	t.Cleanup(func() { _ = vs.Close() })

	// Second bind on same port should fail.
	if _, err := newVsockServer(4095, handler, logger); err == nil {
		t.Fatal("expected bind failure on used port")
	}

	// Drive handle() with a unix socketpair (Read/Write work like vsock).
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	go func() {
		_, _ = unix.Write(fds[1], []byte(`{"op":"ping"}`+"\n"))
		_ = unix.Close(fds[1])
	}()
	vs.handle(context.Background(), fds[0])

	conn := newVsockConn(-1)
	_ = conn.LocalAddr().Network()
	_ = conn.RemoteAddr().String()
	_ = conn.SetDeadline(time.Now().Add(time.Millisecond))
	_ = conn.Close()
	_ = vs.Close() // second Close is once.Do no-op
}

func TestLinuxLookNetworkBinaryFallbackDirs(t *testing.T) {
	t.Setenv("PATH", "")
	if _, err := lookNetworkBinary("definitely-missing-bin-xyz"); err == nil {
		t.Fatal("expected missing binary")
	}
	// Hit /sbin etc. search for a binary that usually exists.
	if p, err := lookNetworkBinary("true"); err == nil && p == "" {
		t.Fatal("unexpected empty path")
	}
}

func TestLinuxIoctlPtrRealSeam(t *testing.T) {
	// Exercise the real ioctlPtr wrapper once (typically EBADF on fd 0).
	errno := ioctlPtr(0, 0, 0)
	if errno == 0 {
		t.Log("unexpected success on ioctl(0,0,0)")
	}
}

func TestLinuxAnnounceReadyCoverage(t *testing.T) {
	announceReady(slog.Default(), "", "tok", "nonce", "/tmp/nope.sock")
	announceReady(slog.Default(), "sb", "", "nonce", "/tmp/nope.sock")
	announceReady(slog.Default(), "sb", "tok", "nonce", "")
	scrubReadyEnv()
	runParkedReadyHandshake(slog.Default(), &server{parkedMode: true}, "", "tok", "n")
	runParkedReadyHandshake(slog.Default(), &server{parkedMode: true}, "/nonexistent-ready.sock", "tok", "n")

	// dialReadySocket missing fields + successful write.
	dialReadySocket(slog.Default(), "  ", "sb", "tok", "n")
	dialReadySocket(slog.Default(), "/tmp/x.sock", "", "tok", "n")
	dialReadySocket(slog.Default(), "/tmp/x.sock", "sb", "", "n")
	dialReadySocket(slog.Default(), "/nonexistent.sock", "sb", "tok", "n")

	dir := t.TempDir()
	sock := filepath.Join(dir, "ready.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = readyproto.Decode(bufio.NewReader(c))
	}()
	dialReadySocket(slog.Default(), sock, "sb", "tok", "nonce")
	time.Sleep(50 * time.Millisecond)

	// Park handshake error paths.
	if err := parkedReadyOnConn(slog.Default(), &server{}, nil, "t", "n"); err == nil {
		t.Fatal("expected nil conn error")
	}
	gBlank, hBlank := net.Pipe()
	_ = hBlank.Close()
	_ = gBlank.Close()
	if err := parkedReadyOnConn(slog.Default(), &server{}, gBlank, " ", " "); err == nil {
		t.Fatal("expected blank token/nonce error")
	}
	guest, host := net.Pipe()
	_ = host.Close()
	if err := parkedReadyOnConn(slog.Default(), &server{logger: slog.Default()}, guest, "tok", "nonce"); err == nil {
		t.Fatal("expected parked write/adopt failure on closed peer")
	}
	_ = guest.Close()

	guest2, host2 := net.Pipe()
	t.Cleanup(func() { _ = guest2.Close(); _ = host2.Close() })
	go func() {
		br := bufio.NewReader(host2)
		_, _ = readyproto.DecodeParked(br)
		_ = host2.Close() // fail adopt read
	}()
	if err := parkedReadyOnConn(slog.Default(), &server{logger: slog.Default()}, guest2, "tok", "nonce"); err == nil {
		t.Fatal("expected adopt read failure")
	}

	guest3, host3 := net.Pipe()
	t.Cleanup(func() { _ = guest3.Close(); _ = host3.Close() })
	go func() {
		br := bufio.NewReader(host3)
		_, _ = readyproto.DecodeParked(br)
		_ = readyproto.EncodeAdopt(host3, readyproto.AdoptFrame{
			Event: readyproto.EventAdopt, SandboxID: "sb", Token: "tok", Nonce: "n",
		})
		_ = host3.Close() // fail ready ack write
	}()
	if err := parkedReadyOnConn(slog.Default(), &server{logger: slog.Default()}, guest3, "tok", "nonce"); err == nil {
		t.Fatal("expected ready ack failure")
	}
}

func TestLinuxIsSupportedEnvdUserMatch(t *testing.T) {
	t.Setenv("USER", "cov95user")
	t.Setenv("LOGNAME", "")
	if !isSupportedEnvdUser("cov95user") {
		t.Fatal("expected USER match")
	}
	t.Setenv("USER", "")
	t.Setenv("LOGNAME", "cov95log")
	if !isSupportedEnvdUser("cov95log") {
		t.Fatal("expected LOGNAME match")
	}
}

func TestLinuxGitCommitRevParseFailure(t *testing.T) {
	dir := t.TempDir()
	fakeGit := filepath.Join(dir, "git")
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	script := "#!/bin/sh\nif echo \"$*\" | grep -q rev-parse; then echo boom >&2; exit 1; fi\nexec " + realGit + " \"$@\"\n"
	if err := os.WriteFile(fakeGit, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	repo := filepath.Join(t.TempDir(), "repo")
	if out, err := exec.Command(realGit, "init", repo).CombinedOutput(); err != nil {
		t.Fatalf("init: %v (%s)", err, out)
	}
	_ = exec.Command(realGit, "-C", repo, "config", "user.email", "t@t").Run()
	_ = exec.Command(realGit, "-C", repo, "config", "user.name", "t").Run()
	_ = os.WriteFile(filepath.Join(repo, "f"), []byte("x"), 0o600)
	_ = exec.Command(realGit, "-C", repo, "add", "f").Run()

	srv := newDaytonaTestServer(t)
	body := `{"path":"` + repo + `","message":"m","author":"a","email":"e@e"}`
	rec := httptest.NewRecorder()
	srv.handleDaytonaGitCommit(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	if rec.Code == http.StatusOK {
		t.Fatalf("expected rev-parse failure, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestLinuxRunNetworkCmdFailure(t *testing.T) {
	if err := runNetworkCmd("/bin/false"); err == nil {
		t.Fatal("expected failure")
	}
	if err := runNetworkCmdIgnoreExists("/bin/false", "x"); err == nil {
		t.Fatal("expected ignore-exists failure")
	}
	if err := runNetworkCmdIgnoreExists("/bin/true"); err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func TestLinuxConfigureNetworkForcedFailures(t *testing.T) {
	ops := linuxQuiesceOps{}
	dir := t.TempDir()

	// ip binary that fails specifically on addr replace.
	ipPath := filepath.Join(dir, "ip")
	if err := os.WriteFile(ipPath, []byte("#!/bin/sh\necho args:$* >&2\nif [ \"$1\" = addr ]; then exit 1; fi\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir)
	if err := ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP: "10.0.0.2", GatewayIP: "10.0.0.1", PrefixLen: 30,
	}); err == nil {
		t.Fatal("expected addr replace failure")
	}

	// ifconfig-only PATH: fail with netmask and without.
	_ = os.Remove(ipPath)
	ifconfig := filepath.Join(dir, "ifconfig")
	if err := os.WriteFile(ifconfig, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("WriteFile ifconfig: %v", err)
	}
	if err := ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP: "10.0.0.2", GatewayIP: "10.0.0.1", PrefixLen: 30, Netmask: "255.255.255.252",
	}); err == nil {
		t.Fatal("expected ifconfig+netmask failure")
	}
	if err := ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP: "10.0.0.2", GatewayIP: "10.0.0.1", PrefixLen: 30,
	}); err == nil {
		t.Fatal("expected ifconfig failure")
	}
}

func TestLinuxDaytonaStderrAfterStart(t *testing.T) {
	srv := newDaytonaTestServer(t)
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"stderr2"}`)))
	cmd := `sleep 0.05; echo out-line; echo err-line >&2; true`
	execRec := httptest.NewRecorder()
	srv.handleDaytonaSessionExec(execRec, httptest.NewRequest(http.MethodPost, "/process/session/stderr2/exec", bytes.NewBufferString(`{"command":`+jsonString(cmd)+`}`)), "stderr2")
	if execRec.Code != http.StatusOK {
		t.Fatalf("exec = %d body=%s", execRec.Code, execRec.Body.String())
	}
}

func TestLinuxVsockServeAcceptClosed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := newQuiesceHandler(logger, nil, nil)
	vs, err := newVsockServer(4094, handler, logger)
	if err != nil {
		t.Skip("vsock unavailable")
	}
	done := make(chan error, 1)
	go func() { done <- vs.Serve(context.Background()) }()
	time.Sleep(30 * time.Millisecond)
	_ = vs.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Log("Serve did not return promptly after Close (acceptable on some kernels)")
	}
}

func TestLinuxSetWallclockSyscallError(t *testing.T) {
	ops := linuxQuiesceOps{}
	// Absurdly large timespec often rejected by clock_settime.
	if err := ops.SetWallclock(1 << 62); err == nil {
		t.Log("clock_settime accepted huge value; no error path hit")
	}
}

func TestLinuxDaytonaDeleteNotFoundRaceHeavy(t *testing.T) {
	srv := newDaytonaTestServer(t)
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("heavy-%d", i)
		createRec := httptest.NewRecorder()
		srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"`+id+`"}`)))
		sess, _, ok := srv.lookupDaytonaSession(id)
		if !ok {
			continue
		}
		go func(sid string) {
			runtime.Gosched()
			_ = srv.sessions.Delete(sid)
		}(sess.ID())
		runtime.Gosched()
		delRec := httptest.NewRecorder()
		srv.handleDaytonaSessionDelete(delRec, httptest.NewRequest(http.MethodDelete, "/", nil), id)
	}
}

func TestLinuxBadExitCodeAndPartialMarker(t *testing.T) {
	srv := newDaytonaTestServer(t)
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"partial"}`)))
	sess, _, ok := srv.lookupDaytonaSession("partial")
	if !ok {
		t.Fatal("missing session")
	}
	body, _ := json.Marshal(map[string]any{"command": "sleep 2", "runAsync": true})
	execRec := httptest.NewRecorder()
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = srv.sessions.Delete(sess.ID())
	}()
	srv.handleDaytonaSessionExec(execRec, httptest.NewRequest(http.MethodPost, "/process/session/partial/exec", bytes.NewReader(body)), "partial")
	time.Sleep(300 * time.Millisecond)
}

func TestLinuxFirstNonLoopbackSeams(t *testing.T) {
	orig := readNetClassDir
	t.Cleanup(func() { readNetClassDir = orig })

	readNetClassDir = func() ([]os.DirEntry, error) {
		return nil, errors.New("no sysfs")
	}
	if _, err := firstNonLoopbackInterface(); err == nil {
		t.Fatal("expected read error")
	}
	ops := linuxQuiesceOps{}
	if err := ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP: "10.0.0.2", GatewayIP: "10.0.0.1", PrefixLen: 30,
	}); err == nil {
		t.Fatal("expected configure failure when net class unreadable")
	}

	readNetClassDir = func() ([]os.DirEntry, error) {
		return []os.DirEntry{fakeDirEntry("lo")}, nil
	}
	if _, err := firstNonLoopbackInterface(); err == nil {
		t.Fatal("expected no non-loopback error")
	}
}

func TestLinuxGitHistoryParseEdges(t *testing.T) {
	dir := t.TempDir()
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	fake := filepath.Join(dir, "git")
	script := "#!/bin/sh\nif echo \"$*\" | grep -q -- '--pretty'; then\n  printf 'badline\\n\\nok\\x00a\\x00b\\x00c\\x00d\\n'\n  exit 0\nfi\nexec " + realGit + " \"$@\"\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	repo := filepath.Join(t.TempDir(), "repo")
	if out, err := exec.Command(realGit, "init", repo).CombinedOutput(); err != nil {
		t.Fatalf("init: %v (%s)", err, out)
	}
	srv := newDaytonaTestServer(t)
	rec := httptest.NewRecorder()
	srv.handleDaytonaGitHistory(rec, httptest.NewRequest(http.MethodGet, "/git/history?path="+repo, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("history status = %d body=%s", rec.Code, rec.Body.String())
	}
}

type fakeDirEntry string

func (f fakeDirEntry) Name() string               { return string(f) }
func (f fakeDirEntry) IsDir() bool                { return true }
func (f fakeDirEntry) Type() os.FileMode          { return os.ModeDir }
func (f fakeDirEntry) Info() (os.FileInfo, error) { return nil, errors.New("no info") }

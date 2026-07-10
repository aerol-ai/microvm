package main

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
)

// The listener must bind before the session manager's filesystem setup and
// before the user command's fork/exec: readiness is announced right after
// bind, and both of those belong off the time-to-ready path. This pins the
// startup order so a refactor can't silently put them back in front.
func TestMainStartupListensBeforeSessionsAndUserCommand(t *testing.T) {
	oldArgs := os.Args
	oldSessionsNewFn := sessionsNewFn
	oldStartReaperFn := startReaperFn
	oldStartUserCommandFn := startUserCommandFn
	oldForwardShutdownSignalsFn := forwardShutdownSignalsFn
	oldServeHTTPFn := serveHTTPFn
	oldNetListenFn := netListenFn
	oldNewVsockServerFn := newVsockServerFn
	defer func() {
		os.Args = oldArgs
		sessionsNewFn = oldSessionsNewFn
		startReaperFn = oldStartReaperFn
		startUserCommandFn = oldStartUserCommandFn
		forwardShutdownSignalsFn = oldForwardShutdownSignalsFn
		serveHTTPFn = oldServeHTTPFn
		netListenFn = oldNetListenFn
		newVsockServerFn = oldNewVsockServerFn
	}()

	var order []string
	startReaperFn = func(*slog.Logger) {}
	forwardShutdownSignalsFn = func(*slog.Logger, *http.Server) {}
	netListenFn = func(network, addr string) (net.Listener, error) {
		order = append(order, "listen")
		return net.Listen("tcp", "127.0.0.1:0")
	}
	sessionsNewFn = func(logger *slog.Logger, cfg sessions.Config) (*sessions.Manager, error) {
		order = append(order, "sessions")
		return sessions.New(logger, sessions.Config{
			SandboxID:    cfg.SandboxID,
			RecordingDir: t.TempDir(),
		})
	}
	startUserCommandFn = func(*slog.Logger, []string) {
		order = append(order, "usercmd")
	}
	serveHTTPFn = func(_ *http.Server, ln net.Listener) error {
		ln.Close()
		return http.ErrServerClosed
	}
	newVsockServerFn = func(uint32, VsockHandler, *slog.Logger) (vsockServerAPI, error) {
		return nil, http.ErrServerClosed
	}

	os.Args = []string{"toolboxd", "echo", "hello"}
	main()

	want := []string{"listen", "sessions", "usercmd"}
	if len(order) != len(want) {
		t.Fatalf("startup calls = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("startup order = %v, want %v", order, want)
		}
	}
}

// In parked mode the user command must not be exec'd at startup — it is
// deferred until the adopt handshake delivers the sandbox identity.
func TestMainStartupParkedDefersUserCommand(t *testing.T) {
	oldArgs := os.Args
	oldSessionsNewFn := sessionsNewFn
	oldStartReaperFn := startReaperFn
	oldStartUserCommandFn := startUserCommandFn
	oldForwardShutdownSignalsFn := forwardShutdownSignalsFn
	oldServeHTTPFn := serveHTTPFn
	oldNetListenFn := netListenFn
	oldNewVsockServerFn := newVsockServerFn
	defer func() {
		os.Args = oldArgs
		sessionsNewFn = oldSessionsNewFn
		startReaperFn = oldStartReaperFn
		startUserCommandFn = oldStartUserCommandFn
		forwardShutdownSignalsFn = oldForwardShutdownSignalsFn
		serveHTTPFn = oldServeHTTPFn
		netListenFn = oldNetListenFn
		newVsockServerFn = oldNewVsockServerFn
	}()

	t.Setenv("SB_POOL_PARKED", "1")

	userCmdCalled := false
	startReaperFn = func(*slog.Logger) {}
	forwardShutdownSignalsFn = func(*slog.Logger, *http.Server) {}
	netListenFn = func(string, string) (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	}
	sessionsNewFn = func(logger *slog.Logger, cfg sessions.Config) (*sessions.Manager, error) {
		return sessions.New(logger, sessions.Config{
			SandboxID:    cfg.SandboxID,
			RecordingDir: t.TempDir(),
		})
	}
	startUserCommandFn = func(*slog.Logger, []string) {
		userCmdCalled = true
	}
	serveHTTPFn = func(_ *http.Server, ln net.Listener) error {
		ln.Close()
		return http.ErrServerClosed
	}
	newVsockServerFn = func(uint32, VsockHandler, *slog.Logger) (vsockServerAPI, error) {
		return nil, http.ErrServerClosed
	}

	os.Args = []string{"toolboxd", "sleep", "infinity"}
	main()

	if userCmdCalled {
		t.Fatal("parked mode must defer the user command until adopt, but it was started at boot")
	}
}

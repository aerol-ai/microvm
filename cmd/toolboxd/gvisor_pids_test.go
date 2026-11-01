package main

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/gvisorpids"
)

// stubGvisorApply swaps the cgroupfs write for a recorder.
func stubGvisorApply(t *testing.T, path string, err error) *[]int64 {
	t.Helper()
	old := gvisorPidsApplyFn
	t.Cleanup(func() { gvisorPidsApplyFn = old })
	var calls []int64
	gvisorPidsApplyFn = func(root string, limit int64) (string, error) {
		if root != "/" {
			t.Errorf("Apply root = %q, want /", root)
		}
		calls = append(calls, limit)
		return path, err
	}
	return &calls
}

func TestApplyGvisorPidsLimit(t *testing.T) {
	cases := []struct {
		name      string
		env       string
		applyErr  error
		wantCalls []int64
		wantLog   string
	}{
		{"unset is a no-op (runc, Firecracker)", "", nil, nil, ""},
		{"applied", "1024", nil, []int64{1024}, "gvisor pids limit applied"},
		{"surrounding space is trimmed", " 2048\n", nil, []int64{2048}, "gvisor pids limit applied"},
		{"not a number", "lots", nil, nil, "not a positive number"},
		{"zero", "0", nil, nil, "not a positive number"},
		{"negative", "-7", nil, nil, "not a positive number"},
		// A non-root image USER cannot write pids.max: logged, the sandbox
		// still starts.
		{"apply fails", "1024", os.ErrPermission, []int64{1024}, "gvisor pids limit not applied"},
		{"no cgroup mount", "1024", gvisorpids.ErrNoPidsController, []int64{1024}, "gvisor pids limit not applied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := stubGvisorApply(t, "/sys/fs/cgroup/pids/pids.max", tc.applyErr)
			t.Setenv(gvisorpids.EnvVar, tc.env)
			var logs bytes.Buffer
			applyGvisorPidsLimit(slog.New(slog.NewTextHandler(&logs, nil)))

			if len(*calls) != len(tc.wantCalls) || (len(tc.wantCalls) > 0 && (*calls)[0] != tc.wantCalls[0]) {
				t.Fatalf("Apply calls = %v, want %v", *calls, tc.wantCalls)
			}
			if tc.wantLog == "" && logs.Len() != 0 {
				t.Fatalf("unexpected log: %s", logs.String())
			}
			if !strings.Contains(logs.String(), tc.wantLog) {
				t.Fatalf("log %q does not contain %q", logs.String(), tc.wantLog)
			}
			if _, ok := os.LookupEnv(gvisorpids.EnvVar); ok {
				t.Fatalf("%s left in toolboxd's environment; user commands would inherit it", gvisorpids.EnvVar)
			}
		})
	}
}

// The cap must be in place before the listener binds (readiness is pushed
// right after bind, and sandboxd hands the sandbox out then) and before the
// user command forks; otherwise the first exec can fork past it.
func TestMainAppliesGvisorPidsLimitBeforeReady(t *testing.T) {
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
	old := gvisorPidsApplyFn
	t.Cleanup(func() { gvisorPidsApplyFn = old })
	gvisorPidsApplyFn = func(string, int64) (string, error) {
		order = append(order, "pids")
		return "/sys/fs/cgroup/pids/pids.max", nil
	}
	t.Setenv(gvisorpids.EnvVar, "1024")
	startReaperFn = func(*slog.Logger) {}
	forwardShutdownSignalsFn = func(*slog.Logger, *http.Server) {}
	netListenFn = func(network, addr string) (net.Listener, error) {
		order = append(order, "listen")
		return net.Listen("tcp", "127.0.0.1:0")
	}
	sessionsNewFn = func(logger *slog.Logger, cfg sessions.Config) (*sessions.Manager, error) {
		return nil, errors.New("sessions off in this test")
	}
	startUserCommandFn = func(*slog.Logger, []string) { order = append(order, "usercmd") }
	serveHTTPFn = func(_ *http.Server, ln net.Listener) error {
		ln.Close()
		return http.ErrServerClosed
	}
	newVsockServerFn = func(uint32, VsockHandler, *slog.Logger) (vsockServerAPI, error) {
		return nil, http.ErrServerClosed
	}

	os.Args = []string{"toolboxd", "echo", "hello"}
	main()

	if want := "pids,listen,usercmd"; strings.Join(order, ",") != want {
		t.Fatalf("startup order = %v, want %s", order, want)
	}
}

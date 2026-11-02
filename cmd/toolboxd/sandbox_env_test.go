package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sandboxenv"
	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/models"
)

// envCanary stands in for a secret: tests assert it reaches the children that
// should see it and never a log line or an error.
const envCanary = "bank-canary-5c1e9d"

// withSandboxEnv swaps the process-wide sandbox env for one test.
func withSandboxEnv(t *testing.T, env map[string]string) {
	t.Helper()
	old := sandboxEnv
	sandboxEnv = &sandboxenv.Store{}
	if _, err := sandboxEnv.Replace(env); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sandboxEnv = old })
}

// sendVsock writes one op on the host end and decodes the ack.
func sendVsock(t *testing.T, host *pipeConn, dec *json.Decoder, op VsockOp, data any) VsockResponse {
	t.Helper()
	msg := VsockMessage{Op: op}
	if data != nil {
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		msg.Data = raw
	}
	line, _ := json.Marshal(msg)
	if _, err := host.Write(append(line, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
	var resp VsockResponse
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	return resp
}

// TestVsockSetEnvAppliesAndRePushConverges is the guest half of the
// Firecracker env fix: the host's set_env lands in the agent's store, a
// re-delivered push (a retry after a lost ack) leaves the same env rather
// than appending, and a different push replaces it.
func TestVsockSetEnvAppliesAndRePushConverges(t *testing.T) {
	store := &sandboxenv.Store{}
	h := newQuiesceHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	h.env = store
	host, guest := newPipePair()
	done := runHandlerInBackground(t, guest, h)
	dec := json.NewDecoder(host)

	env := map[string]string{"BANK_SECRET": envCanary, "REGION": "eu"}
	for i := 0; i < 3; i++ {
		if resp := sendVsock(t, host, dec, OpSetEnv, map[string]any{"env": env}); !resp.Ok {
			t.Fatalf("push %d ack = %+v, want ok", i, resp)
		}
	}
	if got := store.Environ(nil); !slices.Equal(got, []string{"BANK_SECRET=" + envCanary, "REGION=eu"}) {
		t.Fatalf("after 3 identical pushes env = %v, want each key once", got)
	}
	if resp := sendVsock(t, host, dec, OpSetEnv, map[string]any{"env": map[string]string{"REGION": "us"}}); !resp.Ok {
		t.Fatalf("replace ack = %+v", resp)
	}
	if got := store.Environ(nil); !slices.Equal(got, []string{"REGION=us"}) {
		t.Fatalf("after replace env = %v, want [REGION=us]", got)
	}
	closePipeWriter(host)
	<-done
}

// An agent without an env store answers set_env the way a pre-set_env agent
// does, "unknown op", which the host turns into a failed create instead of a
// sandbox missing its secrets.
func TestVsockSetEnvWithoutStoreIsUnknownOp(t *testing.T) {
	host, guest := newPipePair()
	done := runHandlerInBackground(t, guest, &recordingHandler{})
	resp := sendVsock(t, host, json.NewDecoder(host), OpSetEnv, map[string]any{"env": map[string]string{"A": "1"}})
	if resp.Ok || !strings.Contains(resp.Error, `unknown op "set_env"`) {
		t.Fatalf("ack = %+v, want unknown op", resp)
	}
	closePipeWriter(host)
	<-done
}

// The env is secrets: no log line and no error the host could log may carry a
// key or a value, on success or on any refusal.
func TestQuiesceHandlerSetEnvNeverLogsTheEnv(t *testing.T) {
	var logs bytes.Buffer
	h := newQuiesceHandler(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), nil, nil)
	ctx := context.Background()

	if err := h.OnSetEnv(ctx, json.RawMessage(`{"env":{"K":"v"}}`)); err == nil || !strings.Contains(err.Error(), "no sandbox env store") {
		t.Fatalf("nil store err = %v", err)
	}
	h.env = &sandboxenv.Store{}

	ok, _ := json.Marshal(map[string]any{"env": map[string]string{"BANK_SECRET": envCanary}})
	if err := h.OnSetEnv(ctx, ok); err != nil {
		t.Fatalf("OnSetEnv: %v", err)
	}
	if !strings.Contains(logs.String(), "keys=1") {
		t.Fatalf("expected a key-count log line, got %q", logs.String())
	}
	var errs []string
	for _, raw := range []string{
		``,
		`{"env":"` + envCanary + `"}`,
		`{"env":{"TOKEN=` + envCanary + `":"v"}}`,
		`{"env":{"K":"` + envCanary + `\u0000"}}`,
		`{"env":{"K":` + envCanary + `}}`,
	} {
		err := h.OnSetEnv(ctx, json.RawMessage(raw))
		if err == nil {
			t.Fatalf("OnSetEnv(%q) accepted a bad payload", raw)
		}
		errs = append(errs, err.Error())
	}
	if strings.Contains(logs.String(), envCanary) {
		t.Fatalf("a log line carries the env: %q", logs.String())
	}
	for _, e := range errs {
		if strings.Contains(e, envCanary) {
			t.Fatalf("an error carries the env: %q", e)
		}
	}
	// The refused pushes left the accepted env in place.
	if got := h.env.Environ(nil); !slices.Equal(got, []string{"BANK_SECRET=" + envCanary}) {
		t.Fatalf("env after refused pushes = %v", got)
	}
}

// TestHandleExecSeesSandboxEnvWithPerExecPrecedence: /process/execute (the
// path the bank test's `printenv BANK_SECRET` takes) sees the pushed env, and
// an exec's own env still wins, as on a container.
func TestHandleExecSeesSandboxEnvWithPerExecPrecedence(t *testing.T) {
	withSandboxEnv(t, map[string]string{"BANK_SECRET": envCanary, "SHARED": "sandbox"})
	s := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), allowedPorts: map[int]struct{}{}}
	run := func(env map[string]string) string {
		t.Helper()
		body, _ := json.Marshal(models.ExecRequest{Command: `printf '%s|%s' "$BANK_SECRET" "$SHARED"`, Env: env, TimeoutSeconds: 10})
		rr := httptest.NewRecorder()
		s.handleExec(rr, httptest.NewRequest(http.MethodPost, "/process/execute", bytes.NewReader(body)))
		var res models.ExecResult
		if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil || rr.Code != http.StatusOK {
			t.Fatalf("status %d: %s (%v)", rr.Code, rr.Body.String(), err)
		}
		return res.Stdout
	}
	if got, want := run(nil), envCanary+"|sandbox"; got != want {
		t.Fatalf("exec output = %q, want %q", got, want)
	}
	if got, want := run(map[string]string{"SHARED": "exec"}), envCanary+"|exec"; got != want {
		t.Fatalf("per-exec env did not win: %q, want %q", got, want)
	}
}

// Every other child-env site: the streaming exec, Daytona code-run and git.
func TestChildEnvSitesSeeSandboxEnv(t *testing.T) {
	withSandboxEnv(t, map[string]string{"BANK_SECRET": envCanary, "SHARED": "sandbox"})

	// Streaming exec (also the SSH and `aerolvm exec` path): the request's
	// env goes after the sandbox env, and os/exec keeps the last value.
	env := mergeEnvForExec(map[string]string{"SHARED": "exec"})
	if i, j := slices.Index(env, "SHARED=sandbox"), slices.Index(env, "SHARED=exec"); i < 0 || j < i {
		t.Fatalf("mergeEnvForExec order wrong (sandbox at %d, exec at %d): %v", i, j, env)
	}
	if !slices.Contains(env, "BANK_SECRET="+envCanary) {
		t.Fatalf("mergeEnvForExec lacks the sandbox env: %v", env)
	}

	s := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), allowedPorts: map[int]struct{}{}}
	body, _ := json.Marshal(daytonaCodeRunRequest{Language: "sh", Code: `printf '%s|%s' "$BANK_SECRET" "$SHARED"`, Envs: map[string]string{"SHARED": "run"}, Timeout: 10})
	rr := httptest.NewRecorder()
	s.handleDaytonaCodeRun(rr, httptest.NewRequest(http.MethodPost, "/process/code-run", bytes.NewReader(body)))
	var res daytonaCodeRunResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("code-run status %d: %s (%v)", rr.Code, rr.Body.String(), err)
	}
	if want := envCanary + "|run"; res.Result != want {
		t.Fatalf("code-run output = %q, want %q", res.Result, want)
	}

	if _, err := exec.LookPath("git"); err == nil {
		// git reads config from GIT_CONFIG_COUNT/KEY/VALUE; a value pushed
		// as sandbox env must reach git like any other child.
		withSandboxEnv(t, map[string]string{"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "aerolvm.envtest", "GIT_CONFIG_VALUE_0": envCanary})
		out, err := runGitNoRepo("config", "--get", "aerolvm.envtest")
		if err != nil || strings.TrimSpace(out) != envCanary {
			t.Fatalf("git did not see the sandbox env: %q, %v", out, err)
		}
	}
}

// runMainCapturingWiring runs main() with its seams stubbed and returns the
// vsock handler and sessions config main built, so a test can drive the
// guest agent exactly as the Firecracker host does.
func runMainCapturingWiring(t *testing.T) (VsockHandler, sessions.Config) {
	t.Helper()
	oldArgs := os.Args
	oldSessionsNewFn := sessionsNewFn
	oldStartReaperFn := startReaperFn
	oldForwardShutdownSignalsFn := forwardShutdownSignalsFn
	oldServeHTTPFn := serveHTTPFn
	oldNetListenFn := netListenFn
	oldNewVsockServerFn := newVsockServerFn
	t.Cleanup(func() {
		os.Args = oldArgs
		sessionsNewFn = oldSessionsNewFn
		startReaperFn = oldStartReaperFn
		forwardShutdownSignalsFn = oldForwardShutdownSignalsFn
		serveHTTPFn = oldServeHTTPFn
		netListenFn = oldNetListenFn
		newVsockServerFn = oldNewVsockServerFn
	})

	var sessCfg sessions.Config
	var handler VsockHandler
	startReaperFn = func(*slog.Logger) {}
	forwardShutdownSignalsFn = func(*slog.Logger, *http.Server) {}
	netListenFn = func(string, string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	sessionsNewFn = func(logger *slog.Logger, cfg sessions.Config) (*sessions.Manager, error) {
		sessCfg = cfg
		cfg.RecordingDir = t.TempDir()
		return sessions.New(logger, cfg)
	}
	newVsockServerFn = func(_ uint32, h VsockHandler, _ *slog.Logger) (vsockServerAPI, error) {
		handler = h
		return nil, http.ErrServerClosed
	}
	serveHTTPFn = func(_ *http.Server, ln net.Listener) error {
		ln.Close()
		return http.ErrServerClosed
	}
	os.Args = []string{"toolboxd"}
	main()
	if handler == nil {
		t.Fatal("main did not build a vsock handler")
	}
	return handler, sessCfg
}

// TestSetEnvOverVsockReachesExec is UC-331 in miniature: the host pushes
// BANK_SECRET over vsock to the agent main() builds, and `printenv
// BANK_SECRET` through /process/execute prints it. On origin/main the agent
// answered set_env with "unknown op" and printenv printed nothing.
func TestSetEnvOverVsockReachesExec(t *testing.T) {
	withSandboxEnv(t, nil)
	handler, _ := runMainCapturingWiring(t)
	raw, _ := json.Marshal(map[string]any{"env": map[string]string{"BANK_SECRET": envCanary}})
	if err := dispatchVsock(context.Background(), VsockMessage{Op: "set_env", Data: raw}, handler); err != nil {
		t.Fatalf("set_env through main's handler: %v", err)
	}
	s := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), allowedPorts: map[int]struct{}{}}
	body, _ := json.Marshal(models.ExecRequest{Command: "printenv BANK_SECRET", TimeoutSeconds: 10})
	rr := httptest.NewRecorder()
	s.handleExec(rr, httptest.NewRequest(http.MethodPost, "/process/execute", bytes.NewReader(body)))
	var res models.ExecResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s (%v)", rr.Code, rr.Body.String(), err)
	}
	if got := strings.TrimSpace(res.Stdout); got != envCanary {
		t.Fatalf("printenv BANK_SECRET = %q, want the pushed value", got)
	}
}

// TestMainWiresSandboxEnvIntoSessions: the store main's vsock handler
// writes is the one sessions (terminals, SSH, envd, Daytona sessions) take
// their base env from, and a session's own env still wins.
func TestMainWiresSandboxEnvIntoSessions(t *testing.T) {
	withSandboxEnv(t, nil)
	handler, sessCfg := runMainCapturingWiring(t)
	if sessCfg.BaseEnv == nil {
		t.Fatal("main did not wire the sessions base env")
	}
	raw, _ := json.Marshal(map[string]any{"env": map[string]string{"BANK_SECRET": envCanary}})
	if err := dispatchVsock(context.Background(), VsockMessage{Op: OpSetEnv, Data: raw}, handler); err != nil {
		t.Fatalf("set_env through main's handler: %v", err)
	}
	if !slices.Contains(sessCfg.BaseEnv(), "BANK_SECRET="+envCanary) {
		t.Fatal("sessions' base env lacks the env pushed over vsock")
	}

	mgr, err := sessions.New(slog.New(slog.NewTextHandler(io.Discard, nil)), sessions.Config{
		SandboxID: "sb-env", RecordingDir: t.TempDir(), BaseEnv: sessCfg.BaseEnv,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Close)
	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Command: `printf '%s|%s' "$BANK_SECRET" "$SHARED"`, Env: map[string]string{"SHARED": "session"},
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-sess.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("session did not exit")
	}
	if got, want := string(sess.Replay()), envCanary+"|session"; !strings.Contains(got, want) {
		t.Fatalf("session output = %q, want %q", got, want)
	}
}

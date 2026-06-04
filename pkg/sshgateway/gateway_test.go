package sshgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// encodeString writes an SSH-format string (uint32 length + bytes).
func encodeString(s string) []byte {
	buf := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(s)))
	copy(buf[4:], s)
	return buf
}

func encodeUint32(n uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], n)
	return buf[:]
}

func TestParsePTYRequest(t *testing.T) {
	payload := bytes.Join([][]byte{
		encodeString("xterm-256color"),
		encodeUint32(120), // cols
		encodeUint32(40),  // rows
		encodeUint32(0),   // pixwidth
		encodeUint32(0),   // pixheight
		encodeString(""),  // modes
	}, nil)

	term, rows, cols, ok := parsePTYRequest(payload)
	if !ok {
		t.Fatal("parsePTYRequest returned !ok")
	}
	if term != "xterm-256color" {
		t.Errorf("term = %q, want xterm-256color", term)
	}
	if rows != 40 || cols != 120 {
		t.Errorf("rows/cols = %d/%d, want 40/120", rows, cols)
	}
}

func TestParseEnvRequest(t *testing.T) {
	payload := append(encodeString("LANG"), encodeString("en_US.UTF-8")...)
	name, value, ok := parseEnvRequest(payload)
	if !ok {
		t.Fatal("parseEnvRequest returned !ok")
	}
	if name != "LANG" || value != "en_US.UTF-8" {
		t.Errorf("got %q=%q, want LANG=en_US.UTF-8", name, value)
	}
}

func TestParseExecRequest(t *testing.T) {
	payload := encodeString("ls -la /workspace")
	cmd, ok := parseExecRequest(payload)
	if !ok {
		t.Fatal("parseExecRequest returned !ok")
	}
	if cmd != "ls -la /workspace" {
		t.Errorf("cmd = %q", cmd)
	}
}

func TestParseWindowChange(t *testing.T) {
	payload := bytes.Join([][]byte{
		encodeUint32(80),
		encodeUint32(24),
		encodeUint32(0),
		encodeUint32(0),
	}, nil)
	rows, cols, ok := parseWindowChange(payload)
	if !ok {
		t.Fatal("parseWindowChange returned !ok")
	}
	if rows != 24 || cols != 80 {
		t.Errorf("rows/cols = %d/%d, want 24/80", rows, cols)
	}
}

func TestParseShortPayloads(t *testing.T) {
	if _, _, _, ok := parsePTYRequest([]byte{0, 0, 0, 5, 'x'}); ok {
		t.Error("pty-req should reject truncated payload")
	}
	if _, _, ok := parseEnvRequest([]byte{0, 0, 0, 1}); ok {
		t.Error("env should reject truncated payload")
	}
	if _, ok := parseExecRequest(nil); ok {
		t.Error("exec should reject empty payload")
	}
	if _, _, ok := parseWindowChange([]byte{0, 0}); ok {
		t.Error("window-change should reject short payload")
	}
}

func TestAllowEnvVar(t *testing.T) {
	allowed := []string{"TERM", "LANG", "LC_ALL", "LC_TIME"}
	for _, name := range allowed {
		if !allowEnvVar(name) {
			t.Errorf("allowEnvVar(%q) = false, want true", name)
		}
	}
	if allowEnvVar("LD_PRELOAD") {
		t.Error("allowEnvVar should reject LD_PRELOAD")
	}
}

func TestDemuxDockerStream(t *testing.T) {
	// Two frames: stdout "hi", stderr "err".
	frame := func(stream byte, payload string) []byte {
		out := make([]byte, 8+len(payload))
		out[0] = stream
		binary.BigEndian.PutUint32(out[4:8], uint32(len(payload)))
		copy(out[8:], payload)
		return out
	}
	input := bytes.NewReader(append(append(frame(1, "hi"), make([]byte, 8)...), frame(2, "err")...))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	demuxDockerStream(&fakeChannel{stdout: stdout, stderr: stderr}, input)

	if stdout.String() != "hi" {
		t.Errorf("stdout = %q, want hi", stdout.String())
	}
	if stderr.String() != "err" {
		t.Errorf("stderr = %q, want err", stderr.String())
	}
}

func TestParseSSHUser(t *testing.T) {
	cases := []struct {
		name             string
		raw              string
		wantID, wantMode string
		wantSession      string
		wantOK           bool
	}{
		{name: "empty", raw: "   ", wantOK: false},
		{name: "id-only-default-session", raw: "sb-1", wantID: "sb-1", wantMode: "session", wantSession: "default", wantOK: true},
		{name: "named-session", raw: "sb-1+prod", wantID: "sb-1", wantMode: "session", wantSession: "prod", wantOK: true},
		{name: "legacy-exec", raw: "sb-1+exec", wantID: "sb-1", wantMode: "exec", wantSession: "", wantOK: true},
		{name: "missing-id", raw: "+abc", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, mode, sess, ok := parseSSHUser(tc.raw)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if id != tc.wantID || mode != tc.wantMode || sess != tc.wantSession {
				t.Fatalf("got (%q,%q,%q), want (%q,%q,%q)", id, mode, sess, tc.wantID, tc.wantMode, tc.wantSession)
			}
		})
	}
}

func TestKeysEqual(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id")
	signer, err := LoadOrGenerateHostKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey: %v", err)
	}
	otherSigner, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey(other): %v", err)
	}

	if keysEqual(nil, signer.PublicKey()) {
		t.Fatal("keysEqual(nil, key) = true, want false")
	}
	if keysEqual(signer.PublicKey(), nil) {
		t.Fatal("keysEqual(key, nil) = true, want false")
	}
	if !keysEqual(signer.PublicKey(), signer.PublicKey()) {
		t.Fatal("keysEqual(key, key) = false, want true")
	}
	if keysEqual(signer.PublicKey(), otherSigner.PublicKey()) {
		t.Fatal("keysEqual(key, other) = true, want false")
	}
}

func TestLoadOrGenerateHostKeyExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_key")
	first, err := LoadOrGenerateHostKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey(first): %v", err)
	}
	second, err := LoadOrGenerateHostKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey(second): %v", err)
	}
	if !keysEqual(first.PublicKey(), second.PublicKey()) {
		t.Fatal("reloaded host key does not match the original key")
	}
}

func TestNewAndStart(t *testing.T) {
	t.Run("new-validates-required-fields", func(t *testing.T) {
		if _, err := New(nil, Config{ListenAddr: "127.0.0.1:0", HostKeyPath: filepath.Join(t.TempDir(), "k")}, nil, nil); err == nil {
			t.Fatalf("expected error for nil logger")
		}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		if _, err := New(logger, Config{HostKeyPath: filepath.Join(t.TempDir(), "k")}, nil, nil); err == nil {
			t.Fatalf("expected error for empty listen address")
		}
	})

	t.Run("new-success-and-start-shutdown", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		g, err := New(logger, Config{
			ListenAddr:  "127.0.0.1:0",
			HostKeyPath: filepath.Join(t.TempDir(), "host_key"),
		}, &fakeLookup{}, nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() {
			errCh <- g.Start(ctx)
		}()
		time.Sleep(25 * time.Millisecond)
		cancel()

		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("Start returned error after cancel: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("Start did not return after context cancellation")
		}
	})

	t.Run("start-listen-error", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		defer listener.Close()
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		g := &Gateway{logger: logger, listenOn: listener.Addr().String()}
		if err := g.Start(context.Background()); err == nil {
			t.Fatalf("expected Start to fail when the address is already in use")
		}
	})
}

func TestPublicKeyCallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	keyPath := filepath.Join(t.TempDir(), "id")
	signer, err := LoadOrGenerateHostKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey: %v", err)
	}
	otherSigner, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey(other): %v", err)
	}

	authorized := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	lookup := &fakeLookup{sandbox: &models.Sandbox{
		ID:           "sb-1",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-1",
		SSHPublicKey: authorized,
	}}
	g := &Gateway{logger: logger, svc: lookup}
	cb := g.publicKeyCallback(context.Background())

	t.Run("success-session-mode", func(t *testing.T) {
		perms, err := cb(fakeConnMetadata{user: "sb-1+prod"}, signer.PublicKey())
		if err != nil {
			t.Fatalf("publicKeyCallback: %v", err)
		}
		if perms == nil || perms.Extensions["sandbox_id"] != "sb-1" {
			t.Fatalf("unexpected permissions: %+v", perms)
		}
		if perms.Extensions["mode"] != "session" || perms.Extensions["session_name"] != "prod" {
			t.Fatalf("unexpected mode/session in permissions: %+v", perms.Extensions)
		}
	})

	t.Run("success-exec-mode", func(t *testing.T) {
		perms, err := cb(fakeConnMetadata{user: "sb-1+exec"}, signer.PublicKey())
		if err != nil {
			t.Fatalf("publicKeyCallback: %v", err)
		}
		if perms.Extensions["mode"] != "exec" {
			t.Fatalf("mode = %q, want exec", perms.Extensions["mode"])
		}
	})

	t.Run("deny-mismatched-key", func(t *testing.T) {
		if _, err := cb(fakeConnMetadata{user: "sb-1"}, otherSigner.PublicKey()); err == nil {
			t.Fatalf("expected permission denied for mismatched key")
		}
	})

	t.Run("deny-non-running-sandbox", func(t *testing.T) {
		lookup.sandbox.Status = models.SandboxStatusStopped
		defer func() { lookup.sandbox.Status = models.SandboxStatusStarted }()
		if _, err := cb(fakeConnMetadata{user: "sb-1"}, signer.PublicKey()); err == nil {
			t.Fatalf("expected permission denied for non-running sandbox")
		}
	})

	t.Run("deny-empty-username", func(t *testing.T) {
		if _, err := cb(fakeConnMetadata{user: "   "}, signer.PublicKey()); err == nil {
			t.Fatalf("expected permission denied for empty username")
		}
	})

	t.Run("deny-missing-sandbox", func(t *testing.T) {
		lookup.err = os.ErrNotExist
		defer func() { lookup.err = nil }()
		if _, err := cb(fakeConnMetadata{user: "sb-1"}, signer.PublicKey()); err == nil {
			t.Fatalf("expected permission denied when sandbox lookup fails")
		}
	})

	t.Run("deny-invalid-stored-key", func(t *testing.T) {
		lookup.sandbox.SSHPublicKey = "not-a-key"
		defer func() { lookup.sandbox.SSHPublicKey = authorized }()
		if _, err := cb(fakeConnMetadata{user: "sb-1"}, signer.PublicKey()); err == nil {
			t.Fatalf("expected permission denied for invalid stored key")
		}
	})

	t.Run("deny-empty-container-id", func(t *testing.T) {
		lookup.sandbox.ContainerID = ""
		defer func() { lookup.sandbox.ContainerID = "ctr-1" }()
		if _, err := cb(fakeConnMetadata{user: "sb-1"}, signer.PublicKey()); err == nil {
			t.Fatalf("expected permission denied for empty container id")
		}
	})
}

func TestFindOrCreateSession(t *testing.T) {
	newGatewayWithServer := func(t *testing.T, listBody string, postStatus int, postBody string, wantAuth string) (*Gateway, *models.Sandbox, *http.Request, *http.Request) {
		t.Helper()
		var getReq *http.Request
		var postReq *http.Request
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				getReq = r.Clone(r.Context())
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(listBody))
			case http.MethodPost:
				postReq = r.Clone(r.Context())
				w.WriteHeader(postStatus)
				_, _ = w.Write([]byte(postBody))
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		t.Cleanup(srv.Close)

		host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
		if err != nil {
			t.Fatalf("SplitHostPort: %v", err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatalf("Atoi: %v", err)
		}

		g := &Gateway{toolboxPort: port}
		sb := &models.Sandbox{ContainerIP: host, ToolboxToken: wantAuth}
		return g, sb, getReq, postReq
	}

	t.Run("returns-running-session-from-list", func(t *testing.T) {
		list := `{"sessions":[{"id":"s-1","name":"build","status":"running"}]}`
		g, sb, _, _ := newGatewayWithServer(t, list, http.StatusCreated, `{"id":"new"}`, "tok")
		id, err := g.findOrCreateSession(context.Background(), sb, "build", &sessionState{ptyCols: 120, ptyRows: 40})
		if err != nil {
			t.Fatalf("findOrCreateSession: %v", err)
		}
		if id != "s-1" {
			t.Fatalf("id = %q, want s-1", id)
		}
	})

	t.Run("creates-when-missing", func(t *testing.T) {
		list := `{"sessions":[]}`
		postBody := `{"id":"created","name":"dev","status":"running"}`
		var seenPOST []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(list))
				return
			}
			seenPOST, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(postBody))
		}))
		t.Cleanup(srv.Close)

		host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)
		g := &Gateway{toolboxPort: port}
		sb := &models.Sandbox{ContainerIP: host, ToolboxToken: "tok"}
		id, err := g.findOrCreateSession(context.Background(), sb, "dev", &sessionState{ptyCols: 100, ptyRows: 30})
		if err != nil {
			t.Fatalf("findOrCreateSession: %v", err)
		}
		if id != "created" {
			t.Fatalf("id = %q, want created", id)
		}

		var req models.CreateSessionRequest
		if err := json.Unmarshal(seenPOST, &req); err != nil {
			t.Fatalf("decode post body: %v", err)
		}
		if req.Name != "dev" || !req.PTY || req.Cols != 100 || req.Rows != 30 {
			t.Fatalf("unexpected create request: %+v", req)
		}
	})

	t.Run("errors-on-list-decode", func(t *testing.T) {
		g, sb, _, _ := newGatewayWithServer(t, `{bad-json`, http.StatusCreated, `{"id":"x"}`, "")
		if _, err := g.findOrCreateSession(context.Background(), sb, "x", &sessionState{}); err == nil {
			t.Fatalf("expected decode sessions error")
		}
	})

	t.Run("errors-on-create-status", func(t *testing.T) {
		g, sb, _, _ := newGatewayWithServer(t, `{"sessions":[]}`, http.StatusUnauthorized, `{"error":"denied"}`, "")
		if _, err := g.findOrCreateSession(context.Background(), sb, "x", &sessionState{}); err == nil {
			t.Fatalf("expected create session status error")
		}
	})
}

func TestHandleSessionSandboxUnavailableWritesErrorAndExit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stderr := &bytes.Buffer{}
	g := &Gateway{logger: logger, svc: &fakeLookup{err: os.ErrNotExist}}
	requests := make(chan *ssh.Request)
	close(requests)
	g.handleSession(context.Background(), "sb-1", "exec", "", &fakeChannel{stdout: io.Discard, stderr: stderr}, requests)
	if !bytes.Contains(stderr.Bytes(), []byte("sandbox unavailable")) {
		t.Fatalf("stderr = %q, want sandbox unavailable", stderr.String())
	}
}

func TestRunExecFailurePaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("create-failure", func(t *testing.T) {
		stderr := &bytes.Buffer{}
		channel := &fakeChannel{stdout: io.Discard, stderr: stderr}
		g := &Gateway{logger: logger, svc: &fakeLookup{}, dockerCli: &fakeDockerExec{createErr: errors.New("boom")}}
		g.runExec(context.Background(), channel, "sb-1", "ctr-1", []string{"sh"}, &sessionState{})
		if !bytes.Contains(stderr.Bytes(), []byte("failed to start session")) {
			t.Fatalf("stderr = %q, want failed to start session", stderr.String())
		}
		if got := channel.exitStatus(); got != 1 {
			t.Fatalf("exit status = %d, want 1", got)
		}
	})

	t.Run("start-failure", func(t *testing.T) {
		stderr := &bytes.Buffer{}
		channel := &fakeChannel{stdout: io.Discard, stderr: stderr}
		g := &Gateway{logger: logger, svc: &fakeLookup{}, dockerCli: &fakeDockerExec{createID: "exec-1", startErr: errors.New("boom")}}
		g.runExec(context.Background(), channel, "sb-1", "ctr-1", []string{"sh"}, &sessionState{})
		if !bytes.Contains(stderr.Bytes(), []byte("failed to attach session")) {
			t.Fatalf("stderr = %q, want failed to attach session", stderr.String())
		}
		if got := channel.exitStatus(); got != 1 {
			t.Fatalf("exit status = %d, want 1", got)
		}
	})
}

func TestAttachToSessionDialFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/sessions" {
			_, _ = w.Write([]byte(`{"sessions":[{"id":"sess-1","name":"prod","status":"running"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	channel := &fakeChannel{stdout: stdout, stderr: stderr}
	g := &Gateway{logger: logger, toolboxPort: port}
	code := g.attachToSession(context.Background(), channel, &models.Sandbox{ContainerIP: host}, "prod", &sessionState{})
	if code != 1 {
		t.Fatalf("attachToSession exit code = %d, want 1", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("attach dial failed")) {
		t.Fatalf("stderr = %q, want attach dial failed", stderr.String())
	}
}

func TestAttachToSessionCloseWithoutExit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/sessions":
			_, _ = w.Write([]byte(`{"sessions":[{"id":"sess-1","name":"default","status":"running"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/sessions/sess-1/attach":
			upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			_ = conn.Close()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	channel := &fakeChannel{stdout: stdout, stderr: stderr}
	g := &Gateway{logger: logger, toolboxPort: port}
	code := g.attachToSession(context.Background(), channel, &models.Sandbox{ContainerIP: host}, "", &sessionState{})
	if code != 1 {
		t.Fatalf("attachToSession exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected channel output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestHandleConnExecModeOverTCP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	signerPath := filepath.Join(t.TempDir(), "host_key")
	signer, err := LoadOrGenerateHostKey(signerPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey: %v", err)
	}
	authorized := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	dockerCli := &fakeDockerExec{
		createID:     "exec-1",
		startSession: newTestExecSession(t, "hello over tcp"),
		inspectCode:  7,
	}
	lookup := &fakeLookup{sandbox: &models.Sandbox{
		ID:           "sb-1",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-1",
		SSHPublicKey: authorized,
	}}
	g := &Gateway{logger: logger, svc: lookup, dockerCli: dockerCli, signer: signer}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		g.handleConn(context.Background(), conn)
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	clientConfig := &ssh.ClientConfig{
		User:            "sb-1",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	clientConnSSH, chans, reqs, err := ssh.NewClientConn(clientConn, listener.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	client := ssh.NewClient(clientConnSSH, chans, reqs)
	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}
	exitCh := captureExitStatus(requests)

	if ok, err := channel.SendRequest("pty-req", true, bytes.Join([][]byte{
		encodeString("xterm-256color"),
		encodeUint32(120),
		encodeUint32(40),
		encodeUint32(0),
		encodeUint32(0),
		encodeString(""),
	}, nil)); err != nil || !ok {
		t.Fatalf("pty-req failed: ok=%v err=%v", ok, err)
	}
	if ok, err := channel.SendRequest("exec", true, encodeString("printf hello")); err != nil || !ok {
		t.Fatalf("exec failed: ok=%v err=%v", ok, err)
	}
	_ = channel.CloseWrite()
	stdout, err := io.ReadAll(channel)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if string(stdout) != "hello over tcp" {
		t.Fatalf("stdout = %q, want hello over tcp", string(stdout))
	}
	if got := waitForExitStatus(t, exitCh); got != 7 {
		t.Fatalf("exit status = %d, want 7", got)
	}
	_ = channel.Close()
	_ = client.Close()
	_ = clientConn.Close()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}
	if dockerCli.createContainerID != "ctr-1" || !dockerCli.createTTY {
		t.Fatalf("ExecCreate args = %+v", dockerCli)
	}
	if dockerCli.inspectExecID != "exec-1" {
		t.Fatalf("ExecInspect execID = %q, want exec-1", dockerCli.inspectExecID)
	}
}

func TestHandleConnRejectsNonSessionChannel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	signerPath := filepath.Join(t.TempDir(), "host_key")
	signer, err := LoadOrGenerateHostKey(signerPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey: %v", err)
	}
	lookup := &fakeLookup{sandbox: &models.Sandbox{
		ID:           "sb-1",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-1",
		SSHPublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
	}}
	g := &Gateway{logger: logger, svc: lookup, signer: signer}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		g.handleConn(context.Background(), conn)
	}()
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	clientConfig := &ssh.ClientConfig{
		User:            "sb-1",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	clientConnSSH, chans, reqs, err := ssh.NewClientConn(clientConn, listener.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	client := ssh.NewClient(clientConnSSH, chans, reqs)
	if _, _, err := client.OpenChannel("weird", nil); err == nil {
		t.Fatal("expected non-session channel to be rejected")
	}
	_ = client.Close()
	_ = clientConn.Close()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}
}

func TestHandleConnHandshakeFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := &Gateway{logger: logger}
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleConn(context.Background(), serverConn)
	}()
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handshake failure")
	}
}

func TestHandleSessionRequestBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := &Gateway{logger: logger, svc: &fakeLookup{sandbox: &models.Sandbox{
		ID:          "sb-1",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-1",
	}}}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request, 6)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleSession(context.Background(), "sb-1", "session", "prod", channel, requests)
	}()
	requests <- &ssh.Request{Type: "pty-req", Payload: []byte{0, 0, 0, 1, 'x'}}
	requests <- &ssh.Request{Type: "env", Payload: []byte{0, 0, 0, 1}}
	requests <- &ssh.Request{Type: "window-change", Payload: []byte{0, 0}}
	requests <- &ssh.Request{Type: "subsystem"}
	requests <- &ssh.Request{Type: "bogus"}
	close(requests)
	waitForDone(t, done)
}

func TestHandleSessionShellFallbackExec(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dockerCli := &fakeDockerExec{createID: "exec-1", startSession: newTestExecSession(t, "fallback shell"), inspectCode: 0}
	g := &Gateway{logger: logger, svc: &fakeLookup{sandbox: &models.Sandbox{
		ID:          "sb-1",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-1",
	}}, dockerCli: dockerCli}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	channel := &fakeChannel{stdout: stdout, stderr: stderr}
	requests := make(chan *ssh.Request, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleSession(context.Background(), "sb-1", "session", "prod", channel, requests)
	}()
	requests <- &ssh.Request{Type: "pty-req", Payload: bytes.Join([][]byte{
		encodeString("xterm-256color"),
		encodeUint32(80),
		encodeUint32(24),
		encodeUint32(0),
		encodeUint32(0),
		encodeString(""),
	}, nil)}
	requests <- &ssh.Request{Type: "shell"}
	close(requests)
	waitForDone(t, done)
	if stdout.String() != "fallback shell" {
		t.Fatalf("stdout = %q, want fallback shell", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if dockerCli.startExecID != "exec-1" || !dockerCli.startTTY {
		t.Fatalf("ExecStart args = %+v", dockerCli)
	}
}

func TestHandleSessionExecWithoutPTY(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	frame := func(stream byte, payload string) []byte {
		out := make([]byte, 8+len(payload))
		out[0] = stream
		binary.BigEndian.PutUint32(out[4:8], uint32(len(payload)))
		copy(out[8:], payload)
		return out
	}
	muxStream := append(frame(1, "std-out"), frame(2, "std-err")...)
	local, remote := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = remote.Close()
	})
	go func() {
		_, _ = io.Copy(io.Discard, remote)
	}()
	dockerCli := &fakeDockerExec{createID: "exec-1", startSession: &docker.ExecSession{ID: "exec-1", Conn: local, Reader: bufio.NewReader(bytes.NewReader(muxStream))}, inspectCode: 0}
	g := &Gateway{logger: logger, svc: &fakeLookup{sandbox: &models.Sandbox{
		ID:          "sb-1",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-1",
	}}, dockerCli: dockerCli}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	channel := &fakeChannel{stdout: stdout, stderr: stderr}
	requests := make(chan *ssh.Request, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleSession(context.Background(), "sb-1", "exec", "", channel, requests)
	}()
	requests <- &ssh.Request{Type: "exec", Payload: encodeString("printf hello")}
	close(requests)
	waitForDone(t, done)
	if stdout.String() != "std-out" {
		t.Fatalf("stdout = %q, want std-out", stdout.String())
	}
	if stderr.String() != "std-err" {
		t.Fatalf("stderr = %q, want std-err", stderr.String())
	}
	if dockerCli.startTTY {
		t.Fatal("expected non-PTY exec start")
	}
}

func TestHandleConnExecMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dockerCli := &fakeDockerExec{
		createID:     "exec-1",
		startSession: newTestExecSession(t, "hello from exec"),
		inspectCode:  7,
	}
	lookup := &fakeLookup{sandbox: &models.Sandbox{
		ID:          "sb-1",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-1",
	}}
	g := &Gateway{logger: logger, svc: lookup, dockerCli: dockerCli}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	channel := &fakeChannel{stdout: stdout, stderr: stderr}
	requests := make(chan *ssh.Request, 4)
	done := make(chan struct{})
	go func() {
		g.handleSession(context.Background(), "sb-1", "exec", "", channel, requests)
		close(done)
	}()

	requests <- &ssh.Request{Type: "pty-req", Payload: bytes.Join([][]byte{
		encodeString("xterm-256color"),
		encodeUint32(120),
		encodeUint32(40),
		encodeUint32(0),
		encodeUint32(0),
		encodeString(""),
	}, nil)}
	requests <- &ssh.Request{Type: "env", Payload: append(encodeString("LANG"), encodeString("en_US.UTF-8")...)}
	requests <- &ssh.Request{Type: "window-change", Payload: bytes.Join([][]byte{
		encodeUint32(120),
		encodeUint32(40),
		encodeUint32(0),
		encodeUint32(0),
	}, nil)}
	requests <- &ssh.Request{Type: "exec", Payload: encodeString("printf hello")}
	close(requests)
	waitForDone(t, done)
	if stdout.String() != "hello from exec" {
		t.Fatalf("stdout = %q, want hello from exec", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if got := channel.exitStatus(); got != 7 {
		t.Fatalf("exit status = %d, want 7", got)
	}
	if dockerCli.createContainerID != "ctr-1" || !dockerCli.createTTY {
		t.Fatalf("ExecCreate args = %+v", dockerCli)
	}
	if dockerCli.resizeExecID != "exec-1" || dockerCli.resizeHeight != 40 || dockerCli.resizeWidth != 120 {
		t.Fatalf("ExecResize args = %+v", dockerCli)
	}
	if dockerCli.inspectExecID != "exec-1" {
		t.Fatalf("ExecInspect execID = %q, want exec-1", dockerCli.inspectExecID)
	}
	if len(dockerCli.createEnv) != 2 {
		t.Fatalf("ExecCreate env = %#v, want TERM plus LANG", dockerCli.createEnv)
	}
}

func TestHandleConnSessionModeAttach(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	getAuthCh := make(chan string, 1)
	postAuthCh := make(chan string, 1)
	postBodyCh := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/sessions":
			getAuthCh <- r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sessions":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/sessions":
			postAuthCh <- r.Header.Get("Authorization")
			body, _ := io.ReadAll(r.Body)
			postBodyCh <- body
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"sess-1","name":"default","status":"running"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/sessions/sess-1/attach":
			upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.WriteMessage(websocket.BinaryMessage, append([]byte{streamFramePrefixStdout}, []byte("attached")...))
				_ = conn.WriteMessage(websocket.BinaryMessage, append([]byte{streamFramePrefixStderr}, []byte("warn")...))
				_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"exit","code":13}`))
			}()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	lookup := &fakeLookup{sandbox: &models.Sandbox{
		ID:           "sb-1",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-1",
		ContainerIP:  host,
		ToolboxToken: "tok",
	}}
	g := &Gateway{logger: logger, svc: lookup, toolboxPort: port}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	channel := &fakeChannel{stdout: stdout, stderr: stderr}
	requests := make(chan *ssh.Request, 2)
	done := make(chan struct{})
	go func() {
		g.handleSession(context.Background(), "sb-1", "session", "prod", channel, requests)
		close(done)
	}()

	requests <- &ssh.Request{Type: "pty-req", Payload: bytes.Join([][]byte{
		encodeString("xterm-256color"),
		encodeUint32(120),
		encodeUint32(40),
		encodeUint32(0),
		encodeUint32(0),
		encodeString(""),
	}, nil)}
	requests <- &ssh.Request{Type: "shell"}
	close(requests)
	waitForDone(t, done)

	if got := <-getAuthCh; got != "Bearer tok" {
		t.Fatalf("GET auth = %q, want Bearer tok", got)
	}
	if got := <-postAuthCh; got != "Bearer tok" {
		t.Fatalf("POST auth = %q, want Bearer tok", got)
	}
	var createReq models.CreateSessionRequest
	if err := json.Unmarshal(<-postBodyCh, &createReq); err != nil {
		t.Fatalf("unmarshal create request: %v", err)
	}
	if createReq.Name != "prod" || !createReq.PTY || createReq.Cols != 120 || createReq.Rows != 40 {
		t.Fatalf("create request = %+v", createReq)
	}
	if stdout.String() != "attached" {
		t.Fatalf("stdout = %q, want attached", stdout.String())
	}
	if stderr.String() != "warn" {
		t.Fatalf("stderr = %q, want warn", stderr.String())
	}
	if got := channel.exitStatus(); got != 13 {
		t.Fatalf("exit status = %d, want 13", got)
	}
}

func waitForDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handleSession")
	}
}

func captureExitStatus(reqs <-chan *ssh.Request) <-chan uint32 {
	exitCh := make(chan uint32, 1)
	go func() {
		defer close(exitCh)
		for req := range reqs {
			if req.Type != "exit-status" || len(req.Payload) != 4 {
				continue
			}
			exitCh <- binary.BigEndian.Uint32(req.Payload)
			return
		}
	}()
	return exitCh
}

func waitForExitStatus(t *testing.T, exitCh <-chan uint32) uint32 {
	t.Helper()
	select {
	case code, ok := <-exitCh:
		if !ok {
			t.Fatal("exit status channel closed without a value")
		}
		return code
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for exit status")
		return 0
	}
}

func newTestExecSession(t *testing.T, output string) *docker.ExecSession {
	t.Helper()
	local, remote := net.Pipe()
	go func() {
		_, _ = io.Copy(io.Discard, remote)
	}()
	t.Cleanup(func() {
		_ = local.Close()
		_ = remote.Close()
	})
	return &docker.ExecSession{
		ID:     "exec-1",
		Conn:   local,
		Reader: bufio.NewReader(bytes.NewReader([]byte(output))),
	}
}

// fakeChannel is the smallest ssh.Channel surface we need for demuxDockerStream.
type fakeChannel struct {
	stdout   io.Writer
	stderr   io.Writer
	requests []recordedRequest
}

func (f fakeChannel) Read(p []byte) (int, error)  { return 0, io.EOF }
func (f fakeChannel) Write(p []byte) (int, error) { return f.stdout.Write(p) }
func (f fakeChannel) Close() error                { return nil }
func (f fakeChannel) CloseWrite() error           { return nil }
func (f fakeChannel) Stderr() io.ReadWriter       { return stderrAdapter{w: f.stderr} }

type recordedRequest struct {
	name      string
	wantReply bool
	payload   []byte
}

func (f *fakeChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	f.requests = append(f.requests, recordedRequest{name: name, wantReply: wantReply, payload: append([]byte(nil), payload...)})
	return true, nil
}

func (f *fakeChannel) exitStatus() uint32 {
	for _, req := range f.requests {
		if req.name != "exit-status" || len(req.payload) != 4 {
			continue
		}
		return binary.BigEndian.Uint32(req.payload)
	}
	return 0
}

type stderrAdapter struct{ w io.Writer }

func (s stderrAdapter) Read([]byte) (int, error)    { return 0, io.EOF }
func (s stderrAdapter) Write(p []byte) (int, error) { return s.w.Write(p) }

type fakeLookup struct {
	sandbox *models.Sandbox
	err     error
}

func (f *fakeLookup) GetSandbox(context.Context, string) (*models.Sandbox, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.sandbox, nil
}

func (f *fakeLookup) TouchSandbox(context.Context, string) error { return nil }

type fakeConnMetadata struct{ user string }

func (f fakeConnMetadata) User() string          { return f.user }
func (f fakeConnMetadata) SessionID() []byte     { return []byte("sid") }
func (f fakeConnMetadata) ClientVersion() []byte { return []byte("ssh-2.0-test") }
func (f fakeConnMetadata) ServerVersion() []byte { return []byte("ssh-2.0-server") }
func (f fakeConnMetadata) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}
}
func (f fakeConnMetadata) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
}

type fakeDockerExec struct {
	createContainerID string
	createCmd         []string
	createEnv         []string
	createWorkdir     string
	createTTY         bool
	createErr         error
	createID          string

	startExecID  string
	startTTY     bool
	startErr     error
	startSession *docker.ExecSession

	resizeExecID string
	resizeHeight int
	resizeWidth  int
	resizeErr    error

	inspectExecID  string
	inspectCode    int
	inspectRunning bool
	inspectErr     error
}

func (f *fakeDockerExec) ExecCreate(ctx context.Context, containerID string, cmd []string, env []string, workdir string, tty bool) (string, error) {
	f.createContainerID = containerID
	f.createCmd = append([]string(nil), cmd...)
	f.createEnv = append([]string(nil), env...)
	f.createWorkdir = workdir
	f.createTTY = tty
	if f.createErr != nil {
		return "", f.createErr
	}
	if f.createID != "" {
		return f.createID, nil
	}
	return "exec-1", nil
}

func (f *fakeDockerExec) ExecStart(ctx context.Context, execID string, tty bool) (*docker.ExecSession, error) {
	f.startExecID = execID
	f.startTTY = tty
	if f.startErr != nil {
		return nil, f.startErr
	}
	if f.startSession == nil {
		return nil, io.EOF
	}
	return f.startSession, nil
}

func (f *fakeDockerExec) ExecResize(ctx context.Context, execID string, height, width int) error {
	f.resizeExecID = execID
	f.resizeHeight = height
	f.resizeWidth = width
	return f.resizeErr
}

func (f *fakeDockerExec) ExecInspect(ctx context.Context, execID string) (int, bool, error) {
	f.inspectExecID = execID
	if f.inspectErr != nil {
		return 0, false, f.inspectErr
	}
	return f.inspectCode, f.inspectRunning, nil
}

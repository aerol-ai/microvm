package sshgateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
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

	"github.com/aerol-ai/microvm/pkg/models"
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
	input := bytes.NewReader(append(frame(1, "hi"), frame(2, "err")...))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	demuxDockerStream(fakeChannel{stdout: stdout, stderr: stderr}, input)

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

// fakeChannel is the smallest ssh.Channel surface we need for demuxDockerStream.
type fakeChannel struct {
	stdout io.Writer
	stderr io.Writer
}

func (f fakeChannel) Read(p []byte) (int, error)  { return 0, io.EOF }
func (f fakeChannel) Write(p []byte) (int, error) { return f.stdout.Write(p) }
func (f fakeChannel) Close() error                { return nil }
func (f fakeChannel) CloseWrite() error           { return nil }
func (f fakeChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (f fakeChannel) Stderr() io.ReadWriter { return stderrAdapter{w: f.stderr} }

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

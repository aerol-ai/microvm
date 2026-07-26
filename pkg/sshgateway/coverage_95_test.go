package sshgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

func TestAttachToSessionSuccessPath(t *testing.T) {
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
			defer conn.Close()
			_, _, _ = conn.ReadMessage() // stdin
			_ = conn.WriteMessage(websocket.BinaryMessage, append([]byte{streamFramePrefixStderr}, []byte("err")...))
			_ = conn.WriteMessage(websocket.BinaryMessage, append([]byte{streamFramePrefixStdout}, []byte("ok")...))
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"exit","code":7}`))
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
	state := &sessionState{wantPTY: true, ptyCols: 120, ptyRows: 40}
	code := g.attachToSession(context.Background(), channel, localSessionEndpoint(host, port, "tok"), "default", state, nil)
	if code != 7 {
		t.Fatalf("exit code = %d, want 7", code)
	}
	if stdout.String() != "ok" || stderr.String() != "err" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestAttachToSessionResizeForwarding(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gotResize := make(chan struct{}, 1)
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
			defer conn.Close()
			for {
				mt, data, err := conn.ReadMessage()
				if err != nil {
					return
				}
				if mt == websocket.TextMessage && bytes.Contains(data, []byte(`"resize"`)) {
					gotResize <- struct{}{}
					_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"exit","code":0}`))
					return
				}
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	g := &Gateway{logger: logger, toolboxPort: port}
	resize := make(chan [2]uint32, 2)
	resize <- [2]uint32{0, 0}
	resize <- [2]uint32{100, 40}
	close(resize)
	code := g.attachToSession(context.Background(), channel, localSessionEndpoint(host, port, ""), "default", &sessionState{}, resize)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	select {
	case <-gotResize:
	default:
		t.Fatal("expected resize forwarded")
	}
}

func TestAttachToSessionWSSDialerBranch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/sessions" {
			_, _ = w.Write([]byte(`{"sessions":[{"id":"sess-1","name":"default","status":"running"}]}`))
		}
	}))
	t.Cleanup(srv.Close)
	g := &Gateway{logger: logger}
	ep := sessionEndpoint{
		baseURL: srv.URL + "/sessions",
		wsURL:   "wss://" + strings.TrimPrefix(srv.URL, "http://") + "/sessions/sess-1/attach",
	}
	code := g.attachToSession(context.Background(), &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}, ep, "default", &sessionState{}, nil)
	if code != 1 {
		t.Fatalf("code = %d, want dial failure", code)
	}
}

func TestFindOrCreateSessionExecSkipsList(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			listed = true
		}
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"id":"exec-sess","name":"exec","status":"running"}`))
		}
	}))
	t.Cleanup(srv.Close)
	g := &Gateway{}
	state := &sessionState{execCommand: "echo hi", wantPTY: false}
	id, err := g.findOrCreateSession(context.Background(), sessionEndpoint{baseURL: srv.URL}, "exec", state)
	if err != nil {
		t.Fatalf("findOrCreateSession: %v", err)
	}
	if id != "exec-sess" || listed {
		t.Fatalf("id=%q listed=%v", id, listed)
	}
}

func TestFindOrCreateSessionCreateAndDecodeErrors(t *testing.T) {
	g := &Gateway{}
	state := &sessionState{}

	t.Run("create-status-error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`{"sessions":[]}`))
				return
			}
			w.WriteHeader(http.StatusBadRequest)
		}))
		t.Cleanup(srv.Close)
		if _, err := g.findOrCreateSession(context.Background(), sessionEndpoint{baseURL: srv.URL}, "dev", state); err == nil {
			t.Fatal("expected create status error")
		}
	})

	t.Run("decode-created-session", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`{"sessions":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{`))
		}))
		t.Cleanup(srv.Close)
		if _, err := g.findOrCreateSession(context.Background(), sessionEndpoint{baseURL: srv.URL}, "dev", state); err == nil {
			t.Fatal("expected decode error")
		}
	})
}

func TestHandleRemoteSessionWindowChangeAndDrain(t *testing.T) {
	baseURL, _, _ := ownerSessionStub(t, "sb-remote", "sess-r", 3, nil)
	g := &Gateway{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteBaseURL: baseURL,
		remotePAT:     "pat",
	}

	t.Run("window-change-after-start", func(t *testing.T) {
		channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
		requests := make(chan *ssh.Request, 4)
		done := make(chan struct{})
		go func() {
			defer close(done)
			g.handleRemoteSession(context.Background(), "sb-remote", "default", channel, requests)
		}()
		requests <- &ssh.Request{Type: "shell"}
		time.Sleep(30 * time.Millisecond)
		requests <- &ssh.Request{Type: "window-change", Payload: bytes.Join([][]byte{
			encodeUint32(100), encodeUint32(40), encodeUint32(0), encodeUint32(0),
		}, nil)}
		close(requests)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
	})

	t.Run("client-close-drains-started-session", func(t *testing.T) {
		channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
		requests := make(chan *ssh.Request, 1)
		done := make(chan struct{})
		go func() {
			defer close(done)
			g.handleRemoteSession(context.Background(), "sb-remote", "default", channel, requests)
		}()
		requests <- &ssh.Request{Type: "shell"}
		time.Sleep(30 * time.Millisecond)
		close(requests)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
	})
}

func TestHandleSessionRemoteOwnedAndLookupErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	baseURL, _, _ := ownerSessionStub(t, "sb-remote", "sess-r", 0, nil)
	g := &Gateway{
		logger:        logger,
		remoteBaseURL: strings.TrimSuffix(baseURL, "/v1/sandboxes/sb-remote/sessions"),
	}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleSession(context.Background(), "sb-remote", "session", "default", true, channel, requests)
	}()
	requests <- &ssh.Request{Type: "shell"}
	close(requests)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	g2 := &Gateway{logger: logger, svc: &fakeLookup{err: io.EOF}}
	stderr := &bytes.Buffer{}
	requests2 := make(chan *ssh.Request)
	close(requests2)
	g2.handleSession(context.Background(), "sb-missing", "exec", "", false, &fakeChannel{stdout: io.Discard, stderr: stderr}, requests2)
	if !strings.Contains(stderr.String(), "sandbox unavailable") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestPumpStreamsCloseWriteAndDemuxZeroFrame(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := &Gateway{logger: logger}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	execConn, peer := net.Pipe()
	t.Cleanup(func() { _ = execConn.Close(); _ = peer.Close() })
	go func() { _, _ = peer.Write([]byte("x")); _ = peer.Close() }()
	session := &docker.ExecSession{
		Conn:   &closeWriteConn{Conn: execConn},
		Reader: bufio.NewReader(strings.NewReader("")),
	}
	done := make(chan struct{})
	go func() {
		g.pumpStreams(channel, session, true)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
	demuxDockerStream(channel, bytes.NewReader(make([]byte, 8)))
}

type closeWriteConn struct {
	net.Conn
}

func (c *closeWriteConn) CloseWrite() error { return nil }

func TestFetchRemoteSandboxNetworkError(t *testing.T) {
	g := &Gateway{remoteBaseURL: "http://127.0.0.1:1"}
	if _, err := g.fetchRemoteSandbox(context.Background(), "sb-1", "fwd"); err == nil {
		t.Fatal("expected network error")
	}
}

func TestNewPropagatesHostKeyError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	if _, err := New(logger, Config{
		ListenAddr:  "127.0.0.1:0",
		HostKeyPath: dir,
	}, nil, nil); err == nil {
		t.Fatal("expected host key error when path is a directory")
	}
}

func TestStartAcceptLoopContinues(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	g, err := New(logger, Config{
		ListenAddr:  addr,
		HostKeyPath: filepath.Join(t.TempDir(), "host_key"),
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- g.Start(ctx) }()
	time.Sleep(30 * time.Millisecond)
	conn, err := net.Dial("tcp", addr)
	if err == nil {
		_ = conn.Close()
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestAttachToSessionInvalidControlMessage(t *testing.T) {
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
			defer conn.Close()
			_ = conn.WriteMessage(websocket.BinaryMessage, []byte{0x01})
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`not-json`))
			_ = conn.Close()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	g := &Gateway{logger: logger, toolboxPort: port}
	code := g.attachToSession(context.Background(), &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}},
		localSessionEndpoint(host, port, ""), "default", &sessionState{}, nil)
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
}

func TestFindOrCreateSessionListDecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{`))
	}))
	t.Cleanup(srv.Close)
	g := &Gateway{}
	if _, err := g.findOrCreateSession(context.Background(), sessionEndpoint{baseURL: srv.URL}, "dev", &sessionState{}); err == nil {
		t.Fatal("expected list decode error")
	}
}

func TestHandleRemoteSessionEnvRequest(t *testing.T) {
	baseURL, _, calls := ownerSessionStub(t, "sb-remote", "sess-r", 0, nil)
	g := &Gateway{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteBaseURL: baseURL,
		remotePAT:     "pat",
	}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request, 3)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleRemoteSession(context.Background(), "sb-remote", "default", channel, requests)
	}()
	requests <- &ssh.Request{Type: "env", Payload: append(encodeString("LANG"), encodeString("C.UTF-8")...)}
	requests <- &ssh.Request{Type: "shell"}
	close(requests)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
	if len(*calls) == 0 {
		t.Fatal("expected remote session calls")
	}
}

type readableChannel struct {
	fakeChannel
	data []byte
}

func (r *readableChannel) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestAttachToSessionStdinPump(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var got []byte
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
			defer conn.Close()
			_, data, _ := conn.ReadMessage()
			got = append([]byte(nil), data...)
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"exit","code":0}`))
		}
	}))
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	g := &Gateway{logger: logger, toolboxPort: port}
	ch := &readableChannel{
		fakeChannel: fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}},
		data:        []byte("stdin-data"),
	}
	code := g.attachToSession(context.Background(), ch, localSessionEndpoint(host, port, ""), "default", &sessionState{}, nil)
	if code != 0 || string(got) != "stdin-data" {
		t.Fatalf("code=%d got=%q", code, got)
	}
}

func TestHandleRemoteSessionDuplicateStart(t *testing.T) {
	baseURL, _, _ := ownerSessionStub(t, "sb-remote", "sess-r", 0, nil)
	g := &Gateway{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteBaseURL: baseURL,
		remotePAT:     "pat",
	}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request, 3)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleRemoteSession(context.Background(), "sb-remote", "default", channel, requests)
	}()
	requests <- &ssh.Request{Type: "shell"}
	requests <- &ssh.Request{Type: "shell"}
	close(requests)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandleSessionExecValidationAndSubsystem(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := &Gateway{
		logger: logger,
		svc:    &fakeLookup{sandbox: &models.Sandbox{ID: "sb-1", Status: models.SandboxStatusStarted, ContainerID: "ctr-1"}},
		dockerCli: &fakeDockerExec{
			createID:     "exec-1",
			startSession: newTestExecSession(t, ""),
			inspectCode:  0,
			inspectErr:   io.EOF,
		},
	}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request, 3)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleSession(context.Background(), "sb-1", "exec", "", false, channel, requests)
	}()
	requests <- &ssh.Request{Type: "exec", Payload: encodeString("   ")}
	requests <- &ssh.Request{Type: "exec", Payload: encodeString("echo ok")}
	close(requests)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestDemuxDockerStreamTruncatedPayload(t *testing.T) {
	header := []byte{1, 0, 0, 0, 10, 'o', 'n', 'l', 'y'} // claims 10 bytes, only 4 present
	stdout := &bytes.Buffer{}
	demuxDockerStream(&fakeChannel{stdout: stdout, stderr: &bytes.Buffer{}}, bytes.NewReader(header))
}

func TestFindOrCreateSessionRequestErrors(t *testing.T) {
	g := &Gateway{}
	if _, err := g.findOrCreateSession(context.Background(), sessionEndpoint{baseURL: "://bad"}, "dev", &sessionState{}); err == nil {
		t.Fatal("expected list request error")
	}
	state := &sessionState{execCommand: "echo hi"}
	if _, err := g.findOrCreateSession(context.Background(), sessionEndpoint{baseURL: "://bad"}, "exec", state); err == nil {
		t.Fatal("expected create request error")
	}
}

func TestDemuxDockerStreamZeroSizeFrameSkips(t *testing.T) {
	frame := func(stream byte, size uint32) []byte {
		out := make([]byte, 8)
		out[0] = stream
		binary.BigEndian.PutUint32(out[4:8], size)
		return out
	}
	payload := append(frame(1, 0), frame(1, 2)...)
	payload = append(payload, 'h', 'i')
	stdout := &bytes.Buffer{}
	demuxDockerStream(&fakeChannel{stdout: stdout}, bytes.NewReader(payload))
	if stdout.String() != "hi" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

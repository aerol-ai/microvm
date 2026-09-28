package sshgateway

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
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

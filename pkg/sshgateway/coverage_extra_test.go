package sshgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"golang.org/x/crypto/ssh"
)

func TestFetchRemoteSandboxBranches(t *testing.T) {
	g := &Gateway{remotePAT: "pat"}

	t.Run("non-2xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		g.remoteBaseURL = srv.URL
		sb, err := g.fetchRemoteSandbox(context.Background(), "sb-1", "fwd")
		if err != nil || sb != nil {
			t.Fatalf("non-2xx = %v, %v", sb, err)
		}
	})

	t.Run("decode-error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "{")
		}))
		defer srv.Close()
		g.remoteBaseURL = srv.URL
		if _, err := g.fetchRemoteSandbox(context.Background(), "sb-1", "fwd"); err == nil {
			t.Fatal("expected decode error")
		}
	})

	t.Run("success-with-pat", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer pat" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Header.Get(forwardIDHeader) != "fwd-9" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb-1", Status: models.SandboxStatusStarted})
		}))
		defer srv.Close()
		g.remoteBaseURL = srv.URL
		sb, err := g.fetchRemoteSandbox(context.Background(), "sb-1", "fwd-9")
		if err != nil || sb == nil || sb.ID != "sb-1" {
			t.Fatalf("success = %v, %v", sb, err)
		}
	})
}

func TestAuthorizeKeyErrors(t *testing.T) {
	signer, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "o"))
	if err != nil {
		t.Fatal(err)
	}
	authorized := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	if err := authorizeKey("", signer.PublicKey()); err == nil {
		t.Fatal("empty authorized key")
	}
	if err := authorizeKey("not-a-key", signer.PublicKey()); err == nil {
		t.Fatal("invalid authorized key")
	}
	if err := authorizeKey(authorized, other.PublicKey()); err == nil {
		t.Fatal("mismatched key")
	}
	if err := authorizeKey(authorized, signer.PublicKey()); err != nil {
		t.Fatalf("valid key: %v", err)
	}
}

func TestHandleRemoteSessionRequestErrors(t *testing.T) {
	baseURL, _, _ := ownerSessionStub(t, "sb-remote", "sess-r", 0, nil)
	g := &Gateway{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteBaseURL: baseURL,
	}

	t.Run("bad-pty", func(t *testing.T) {
		channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
		requests := make(chan *ssh.Request, 1)
		done := make(chan struct{})
		go func() {
			defer close(done)
			g.handleRemoteSession(context.Background(), "sb-remote", "default", channel, requests)
		}()
		requests <- &ssh.Request{Type: "pty-req", Payload: []byte{0}}
		requests <- &ssh.Request{Type: "shell"}
		close(requests)
		<-done
	})

	t.Run("bad-exec", func(t *testing.T) {
		channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
		requests := make(chan *ssh.Request, 1)
		done := make(chan struct{})
		go func() {
			defer close(done)
			g.handleRemoteSession(context.Background(), "sb-remote", "default", channel, requests)
		}()
		requests <- &ssh.Request{Type: "exec", Payload: []byte{0}}
		close(requests)
		<-done
	})

	t.Run("unknown-request-want-reply", func(t *testing.T) {
		channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
		requests := make(chan *ssh.Request, 1)
		done := make(chan struct{})
		go func() {
			defer close(done)
			g.handleRemoteSession(context.Background(), "sb-remote", "default", channel, requests)
		}()
		requests <- &ssh.Request{Type: "subsystem"}
		close(requests)
		<-done
	})

	t.Run("client-closes-after-start", func(t *testing.T) {
		channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
		requests := make(chan *ssh.Request, 2)
		done := make(chan struct{})
		go func() {
			defer close(done)
			g.handleRemoteSession(context.Background(), "sb-remote", "default", channel, requests)
		}()
		requests <- &ssh.Request{Type: "shell"}
		time.Sleep(50 * time.Millisecond)
		close(requests)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
	})
}

func TestAttachToSessionErrorPaths(t *testing.T) {
	g := &Gateway{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	state := &sessionState{}

	// Unreachable endpoint → findOrCreateSession fails.
	code := g.attachToSession(context.Background(), channel, sessionEndpoint{
		baseURL: "http://127.0.0.1:1/sessions",
		wsURL:   "ws://127.0.0.1:1/sessions",
	}, "default", state, nil)
	if code != 1 {
		t.Fatalf("attach code = %d, want 1", code)
	}
	if channel.stderr.(*bytes.Buffer).Len() == 0 {
		t.Fatal("expected stderr on attach failure")
	}
}

func TestLoadOrGenerateHostKeyWriteFailure(t *testing.T) {
	dir := t.TempDir()
	readonly := filepath.Join(dir, "ro")
	if err := os.Mkdir(readonly, 0o500); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(readonly, "nested", "host_key")
	if _, err := LoadOrGenerateHostKey(path); err == nil {
		t.Fatal("expected write failure in unwritable parent")
	}
}

func TestNewTrimsRemoteConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g, err := New(logger, Config{
		ListenAddr:       "127.0.0.1:0",
		HostKeyPath:      filepath.Join(t.TempDir(), "k"),
		RemoteAPIBaseURL: "http://127.0.0.1:8080///",
		RemoteAPIToken:   "  pat  ",
		ContainerEngine:  " containerd ",
	}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.remoteBaseURL != "http://127.0.0.1:8080" || g.remotePAT != "pat" || g.containerEngine != "containerd" {
		t.Fatalf("remote config not trimmed: %+v", g)
	}
}

func TestStartAcceptsAfterCancel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g, err := New(logger, Config{
		ListenAddr:  "127.0.0.1:0",
		HostKeyPath: filepath.Join(t.TempDir(), "k"),
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- g.Start(ctx) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestAttachToSessionWSSAndCreateErrors(t *testing.T) {
	g := &Gateway{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"sessions":[]}`))
	}))
	defer ts.Close()

	ep := sessionEndpoint{
		baseURL: ts.URL,
		wsURL:   "wss://" + strings.TrimPrefix(ts.URL, "https://"),
	}
	if code := g.attachToSession(context.Background(), channel, ep, "default", &sessionState{}, nil); code != 1 {
		t.Fatalf("create failure code = %d", code)
	}
}

func TestFindOrCreateSessionDecodeAndCreateErrors(t *testing.T) {
	g := &Gateway{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	t.Run("list-decode-error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "{")
		}))
		defer ts.Close()
		ep := sessionEndpoint{baseURL: ts.URL, wsURL: "ws://" + strings.TrimPrefix(ts.URL, "http://")}
		if _, err := g.findOrCreateSession(context.Background(), ep, "default", &sessionState{}); err == nil {
			t.Fatal("expected decode error")
		}
	})

	t.Run("create-status-error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`{"sessions":[]}`))
				return
			}
			w.WriteHeader(http.StatusTeapot)
		}))
		defer ts.Close()
		ep := sessionEndpoint{baseURL: ts.URL, wsURL: "ws://" + strings.TrimPrefix(ts.URL, "http://")}
		if _, err := g.findOrCreateSession(context.Background(), ep, "default", &sessionState{}); err == nil {
			t.Fatal("expected create status error")
		}
	})
}

func TestHandleRemoteSessionEnvAndWindowChange(t *testing.T) {
	baseURL, _, _ := ownerSessionStub(t, "sb-remote", "sess-r", 0, nil)
	g := &Gateway{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteBaseURL: baseURL,
	}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleRemoteSession(context.Background(), "sb-remote", "default", channel, requests)
	}()
	requests <- &ssh.Request{Type: "env", Payload: append(encodeString("LANG"), encodeString("C")...)}
	requests <- &ssh.Request{Type: "env", Payload: append(encodeString("LD_PRELOAD"), encodeString("x")...)}
	requests <- &ssh.Request{Type: "shell"}
	requests <- &ssh.Request{Type: "window-change", Payload: []byte{0, 0}}
	time.Sleep(50 * time.Millisecond)
	close(requests)
	<-done
}

func TestFetchRemoteSandboxRequestError(t *testing.T) {
	g := &Gateway{remoteBaseURL: "://bad-url"}
	if _, err := g.fetchRemoteSandbox(context.Background(), "sb", "fwd"); err == nil {
		t.Fatal("expected request construction error")
	}
}

func TestHandleSessionRemoteOwnedDelegates(t *testing.T) {
	baseURL, _, _ := ownerSessionStub(t, "sb-remote", "sess-r", 0, nil)
	g := &Gateway{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteBaseURL: baseURL,
		remotePAT:     "pat",
		svc:           &fakeLookup{sandbox: &models.Sandbox{ID: "sb-remote", Status: models.SandboxStatusStarted, ContainerID: "c"}},
	}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request, 2)
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
}

func TestAuthorizeLocalSSHBranches(t *testing.T) {
	signer, _ := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "k"))
	key := signer.PublicKey()
	authorized := string(ssh.MarshalAuthorizedKey(key))

	if err := authorizeLocalSSH(&models.Sandbox{Status: models.SandboxStatusStopped}, key); err == nil {
		t.Fatal("stopped sandbox")
	}
	if err := authorizeLocalSSH(&models.Sandbox{Status: models.SandboxStatusStarted}, key); err == nil {
		t.Fatal("missing container")
	}
	if err := authorizeLocalSSH(&models.Sandbox{
		Status: models.SandboxStatusStarted, ContainerID: "c", SSHPublicKey: authorized,
	}, key); err != nil {
		t.Fatalf("valid local auth: %v", err)
	}
}

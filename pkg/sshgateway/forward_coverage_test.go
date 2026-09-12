package sshgateway

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestHandleRemoteSessionRequestBranches(t *testing.T) {
	baseURL, _, _ := ownerSessionStub(t, "sb-remote", "sess-r", 0, nil)
	g := &Gateway{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteBaseURL: baseURL,
		remotePAT:     "pat",
	}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleRemoteSession(context.Background(), "sb-remote", "default", channel, requests)
	}()

	// Window-change before start updates the launch PTY snapshot.
	requests <- &ssh.Request{Type: "window-change", Payload: sshUint32s(80, 24, 0, 0)}
	requests <- &ssh.Request{Type: "pty-req", Payload: []byte{1}}
	requests <- &ssh.Request{Type: "pty-req", Payload: append(encodeString("xterm"), sshUint32s(100, 30, 0, 0)...)}
	requests <- &ssh.Request{Type: "env", Payload: append(encodeString("LANG"), encodeString("C")...)}
	requests <- &ssh.Request{Type: "shell"}
	// After start these must not restart the attach. WantReply stays false:
	// fake channels have no ssh mux, so Request.Reply would panic.
	requests <- &ssh.Request{Type: "pty-req", Payload: []byte{1}}
	requests <- &ssh.Request{Type: "env", Payload: append(encodeString("LANG"), encodeString("C")...)}
	requests <- &ssh.Request{Type: "exec", Payload: encodeString("echo hi")}
	requests <- &ssh.Request{Type: "unknown"}
	close(requests)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
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

func TestFetchRemoteSandboxNetworkError(t *testing.T) {
	g := &Gateway{remoteBaseURL: "http://127.0.0.1:1"}
	if _, err := g.fetchRemoteSandbox(context.Background(), "sb-1", "fwd"); err == nil {
		t.Fatal("expected network error")
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

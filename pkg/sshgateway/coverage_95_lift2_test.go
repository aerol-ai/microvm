package sshgateway

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"golang.org/x/crypto/ssh"
)

func sshUint32s(vals ...uint32) []byte {
	out := make([]byte, 0, 4*len(vals))
	for _, v := range vals {
		out = append(out, encodeUint32(v)...)
	}
	return out
}

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

func TestHandleSessionSubsystemAndUnknown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := &Gateway{
		logger: logger,
		svc:    &fakeLookup{sandbox: &models.Sandbox{ID: "sb-1", Status: models.SandboxStatusStarted, ContainerID: "ctr-1"}},
		dockerCli: &fakeDockerExec{
			createID:     "exec-1",
			startSession: newTestExecSession(t, ""),
			inspectCode:  0,
		},
	}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request, 5)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleSession(context.Background(), "sb-1", "exec", "", false, channel, requests)
	}()
	requests <- &ssh.Request{Type: "window-change", Payload: []byte{1}}
	requests <- &ssh.Request{Type: "window-change", Payload: sshUint32s(80, 24, 0, 0)}
	requests <- &ssh.Request{Type: "subsystem", Payload: encodeString("sftp")}
	requests <- &ssh.Request{Type: "unknown"}
	requests <- &ssh.Request{Type: "exec", Payload: encodeString("echo ok")}
	close(requests)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

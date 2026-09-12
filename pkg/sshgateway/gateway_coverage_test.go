package sshgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"golang.org/x/crypto/ssh"
)

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

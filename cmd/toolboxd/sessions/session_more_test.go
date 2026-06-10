package sessions

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

type memoryWriteCloser struct {
	bytes.Buffer
	closed bool
}

func (m *memoryWriteCloser) Close() error {
	m.closed = true
	return nil
}

func TestSessionSnapshotAndMetadataBranches(t *testing.T) {
	s := &Session{
		id:        "ses-1",
		name:      "demo",
		argv:      []string{"sh", "-c", "echo demo"},
		workdir:   "/tmp",
		createdAt: time.Unix(100, 0).UTC(),
		startedAt: time.Unix(101, 0).UTC(),
		buf:       newRing(8),
		doneCh:    make(chan struct{}),
	}

	snap := s.Snapshot()
	if snap.Status != "running" {
		t.Fatalf("running status = %q", snap.Status)
	}
	if snap.Recording {
		t.Fatal("expected recording=false when recorder is nil")
	}
	if pid := s.PID(); pid != 0 {
		t.Fatalf("PID = %d, want 0", pid)
	}
	if code, signal := s.ExitInfo(); code != -1 || signal != "" {
		t.Fatalf("ExitInfo running = (%d, %q), want (-1, \"\")", code, signal)
	}

	s.exited.Store(true)
	s.failed = true
	snap = s.Snapshot()
	if snap.Status != "failed" {
		t.Fatalf("failed status = %q", snap.Status)
	}
	s.failed = false
	s.exitSignal = "TERM"
	snap = s.Snapshot()
	if snap.Status != "killed" {
		t.Fatalf("killed status = %q", snap.Status)
	}
	s.exitSignal = ""
	snap = s.Snapshot()
	if snap.Status != "exited" {
		t.Fatalf("exited status = %q", snap.Status)
	}
}

func TestSessionIOAndSignalBranches(t *testing.T) {
	var nilSession *Session
	if pid := nilSession.PID(); pid != 0 {
		t.Fatalf("nil PID = %d, want 0", pid)
	}

	s := &Session{doneCh: make(chan struct{})}
	if _, err := s.Write([]byte("ignored")); err == nil {
		t.Fatal("expected Write without stdin to fail")
	}
	if err := s.CloseStdin(); err != nil {
		t.Fatalf("CloseStdin without stdin = %v", err)
	}
	if err := s.Signal("TERM"); err == nil {
		t.Fatal("expected Signal without process to fail")
	}

	closer := &memoryWriteCloser{}
	pipeSession := &Session{stdin: closer, doneCh: make(chan struct{})}
	if n, err := pipeSession.Write([]byte("abc")); err != nil || n != 3 {
		t.Fatalf("pipe Write = (%d, %v)", n, err)
	}
	if err := pipeSession.CloseStdin(); err != nil {
		t.Fatalf("pipe CloseStdin = %v", err)
	}
	if !closer.closed {
		t.Fatal("expected pipe stdin to be closed")
	}

	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer rd.Close()
	defer wr.Close()

	ptySession := &Session{ptmx: wr, doneCh: make(chan struct{})}
	if n, err := ptySession.Write([]byte("xyz")); err != nil || n != 3 {
		t.Fatalf("pty Write = (%d, %v)", n, err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(rd, buf); err != nil {
		t.Fatalf("read pty write: %v", err)
	}
	if string(buf) != "xyz" {
		t.Fatalf("pty payload = %q", string(buf))
	}
	if err := ptySession.CloseStdin(); err != nil {
		t.Fatalf("pty CloseStdin = %v", err)
	}

	if err := (&Session{cmd: &exec.Cmd{Process: &os.Process{Pid: 1234}}, doneCh: make(chan struct{})}).Signal("bogus"); err == nil {
		t.Fatal("expected unsupported signal to fail")
	}

	cmd := exec.Command("/bin/sh", "-c", "sleep 5")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	running := &Session{cmd: cmd, doneCh: make(chan struct{})}
	if err := running.Signal("TERM"); err != nil {
		t.Fatalf("running Signal: %v", err)
	}
	_ = cmd.Wait()
}

func TestSessionFinishAndFanoutBranches(t *testing.T) {
	s := &Session{
		buf:      newRing(16),
		recorder: nil,
		doneCh:   make(chan struct{}),
	}
	ch, cancel := s.Subscribe()
	defer cancel()
	s.fanout(StreamStdout, nil)
	s.fanout(StreamStdout, []byte("hello"))
	select {
	case frame, ok := <-ch:
		if !ok {
			t.Fatal("expected a frame before close")
		}
		if !bytes.Contains(frame.Data, []byte("hello")) {
			t.Fatalf("unexpected frame: %q", string(frame.Data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fanout frame")
	}
	s.finish(0, "", false)
	s.finish(1, "TERM", true)
	<-s.Done()
	if code, sig := s.ExitInfo(); code != 0 || sig != "" {
		t.Fatalf("ExitInfo after finish = (%d, %q)", code, sig)
	}
}

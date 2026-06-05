package firecracker

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestVMM_ExtraCoverage(t *testing.T) {
	// StderrTail with nil stderr
	v := &vmm{}
	if tail := v.StderrTail(); tail != "" {
		t.Errorf("expected empty tail, got %q", tail)
	}

	// Pid with nil cmd
	if pid := v.Pid(); pid != 0 {
		t.Errorf("expected 0 pid, got %d", pid)
	}

	// Wait before start
	if err := v.Wait(); err == nil || !strings.Contains(err.Error(), "Wait called before Start") {
		t.Errorf("expected Wait called before Start error, got %v", err)
	}

	// WaitSocket before start
	if err := v.WaitSocket(context.Background(), 1*time.Second); err == nil || !strings.Contains(err.Error(), "WaitSocket called before Start") {
		t.Errorf("expected WaitSocket called before Start error, got %v", err)
	}

	// Shutdown with nil cmd
	if err := v.Shutdown(context.Background(), 1*time.Second); err != nil {
		t.Errorf("expected no error for Shutdown on nil cmd, got %v", err)
	}

	// Kill with nil cmd
	if err := v.Kill(); err != nil {
		t.Errorf("expected no error for Kill on nil cmd, got %v", err)
	}

	// WaitSocket timeout
	v2 := &vmm{started: true, waitCh: make(chan struct{}), apiSocket: "/nonexistent/socket"}
	if err := v2.WaitSocket(context.Background(), 1*time.Millisecond); err == nil || !strings.Contains(err.Error(), "did not appear within") {
		t.Errorf("expected timeout error, got %v", err)
	}

	// WaitSocket ctx.Done
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := v2.WaitSocket(ctx, 1*time.Second); err == nil || err != context.Canceled {
		t.Errorf("expected context canceled, got %v", err)
	}

	// WaitSocket with process exit
	v3 := &vmm{started: true, waitCh: make(chan struct{}), stderr: newCappedBuffer(100), apiSocket: "/nonexistent/socket"}
	close(v3.waitCh)
	if err := v3.WaitSocket(context.Background(), 1*time.Second); err == nil || !strings.Contains(err.Error(), "firecracker exited before API socket bound") {
		t.Errorf("expected firecracker exited error, got %v", err)
	}

	// Shutdown with process exit before shutdown
	v4 := &vmm{cmd: &exec.Cmd{Process: &os.Process{Pid: 999999}}, waitCh: make(chan struct{})}
	close(v4.waitCh)
	if err := v4.Shutdown(context.Background(), 1*time.Second); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Kill with process exit
	if err := v4.Kill(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

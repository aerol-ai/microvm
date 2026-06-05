package firecracker

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVMM_EdgeCases(t *testing.T) {
	v := &vmm{
		sandboxID: "sb-edge",
		runDir:    "",
		apiSocket: "/fake/api.sock",
		cfg:       Config{RunDir: "/var/run/microvm"},
	}

	// StderrTail without Start
	if tail := v.StderrTail(); tail != "" {
		t.Errorf("expected empty string, got %q", tail)
	}

	// Shutdown without Start
	if err := v.Shutdown(context.Background(), time.Second); err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	// Kill without Start
	if err := v.Kill(); err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	// Wait before Start
	if err := v.Wait(); err == nil || !strings.Contains(err.Error(), "Wait called before Start") {
		t.Errorf("expected Wait called before Start error, got %v", err)
	}

	// WaitSocket before Start
	if err := v.WaitSocket(context.Background(), time.Second); err == nil || !strings.Contains(err.Error(), "WaitSocket called before Start") {
		t.Errorf("expected WaitSocket called before Start error, got %v", err)
	}

	// Cleanup without runDir
	if err := v.Cleanup(); err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	// Cleanup with invalid runDir
	v.runDir = "/outside/path"
	if err := v.Cleanup(); err == nil || !strings.Contains(err.Error(), "refusing to clean up path outside") {
		t.Errorf("expected refusing to clean up error, got %v", err)
	}

	// UseJailer validation for cleanup
	v.cfg.UseJailer = true
	v.cfg.JailerChrootBase = "/srv/jailer"
	v.runDir = "/var/run/microvm/sb-edge"
	if err := v.Cleanup(); err == nil || !strings.Contains(err.Error(), "refusing to clean up path outside") {
		t.Errorf("expected refusing to clean up error, got %v", err)
	}
}

func TestVMM_StartTwice(t *testing.T) {
	v := &vmm{
		sandboxID: "sb-edge2",
		runDir:    filepath.Join(t.TempDir(), "run"),
		apiSocket: filepath.Join(t.TempDir(), "api.sock"),
		cfg:       Config{FirecrackerBinary: "echo"},
	}
	v.started = true
	if err := v.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "Start called twice") {
		t.Errorf("expected Start called twice error, got %v", err)
	}
}

func TestVMM_Shutdown_AlreadyExited(t *testing.T) {
	v := &vmm{
		sandboxID: "sb-edge3",
		runDir:    filepath.Join(t.TempDir(), "run"),
		apiSocket: filepath.Join(t.TempDir(), "api.sock"),
		cfg:       Config{FirecrackerBinary: "echo"},
	}
	err := v.Start(context.Background())
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	// Wait for echo to exit
	v.Wait()

	// Now Shutdown should be a no-op
	if err := v.Shutdown(context.Background(), time.Second); err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	// Kill should also be a no-op
	if err := v.Kill(); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

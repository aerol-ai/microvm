package firecracker

import (
	"context"
	"testing"
	"time"
)

func TestVMM_ExtraPaths(t *testing.T) {
	v := &vmm{}

	// Shutdown with nil cmd
	if err := v.Shutdown(context.Background(), time.Second); err != nil {
		t.Errorf("expected nil for shutdown with nil cmd, got %v", err)
	}

	// Kill with nil cmd
	if err := v.Kill(); err != nil {
		t.Errorf("expected nil for kill with nil cmd, got %v", err)
	}

	// StderrTail with nil stderr
	if s := v.StderrTail(); s != "" {
		t.Errorf("expected empty string for nil stderr, got %q", s)
	}

	// Cleanup with empty runDir
	if err := v.Cleanup(); err != nil {
		t.Errorf("expected nil for cleanup with empty runDir, got %v", err)
	}
}

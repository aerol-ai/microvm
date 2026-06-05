package firecracker

import (
	"context"
	"strings"
	"testing"
)

func TestSandboxSnapshot_ExtraCoverage(t *testing.T) {
	d := &Driver{}
	// stopToSandboxSnapshot preconditions
	if err := d.stopToSandboxSnapshot(context.Background(), "test-sb"); err == nil || !strings.Contains(err.Error(), "TemplatesDir or RunDir must be configured") {
		t.Errorf("expected TemplatesDir/RunDir error, got %v", err)
	}

	d.cfg.RunDir = "/tmp/run"

	if err := d.stopToSandboxSnapshot(context.Background(), "test-sb"); err == nil || !strings.Contains(err.Error(), "TAP pool not registered") {
		t.Errorf("expected pool nil error, got %v", err)
	}

	d.pool = newFakePool()

	if err := d.stopToSandboxSnapshot(context.Background(), "test-sb"); err == nil || !strings.Contains(err.Error(), "TAP host manager not registered") {
		t.Errorf("expected tapHost nil error, got %v", err)
	}

	d.tapHost = &fakeTapHost{}

	// VMM not registered & no stopped snapshot
	if err := d.stopToSandboxSnapshot(context.Background(), "test-sb"); err == nil || !strings.Contains(err.Error(), "VMM is not registered") {
		t.Errorf("expected VMM not registered error, got %v", err)
	}

	// startFromSandboxSnapshot preconditions
	dStart := &Driver{}
	if _, err := dStart.startFromSandboxSnapshot(context.Background(), "test-sb"); err == nil || !strings.Contains(err.Error(), "TAP pool not registered") {
		t.Errorf("expected pool nil error, got %v", err)
	}

	dStart.pool = newFakePool()
	if _, err := dStart.startFromSandboxSnapshot(context.Background(), "test-sb"); err == nil || !strings.Contains(err.Error(), "TAP host manager not registered") {
		t.Errorf("expected tapHost nil error, got %v", err)
	}

	dStart.tapHost = &fakeTapHost{}
	if _, err := dStart.startFromSandboxSnapshot(context.Background(), "test-sb"); err == nil || !strings.Contains(err.Error(), "vsock dialer not registered") {
		t.Errorf("expected vsockDial nil error, got %v", err)
	}

	// sandboxSnapshotBase empty
	d3 := &Driver{}
	if _, err := d3.sandboxSnapshotBase(); err == nil || !strings.Contains(err.Error(), "TemplatesDir or RunDir must be configured") {
		t.Errorf("expected base error, got %v", err)
	}
}

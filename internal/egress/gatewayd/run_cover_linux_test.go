//go:build linux

package gatewayd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestRunStopsWhenHardeningFails(t *testing.T) {
	orig := unixPrctlNoDump
	t.Cleanup(func() { unixPrctlNoDump = orig })
	unixPrctlNoDump = func() error { return errors.New("prctl refused") }
	err := Run(context.Background(), Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "harden process") {
		t.Fatalf("Run = %v", err)
	}
}

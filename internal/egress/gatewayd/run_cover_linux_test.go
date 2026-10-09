//go:build linux

package gatewayd

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"strconv"
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

// TestSocketListenerUnchmoddable (CEO D22): a socket whose mode can't be set
// to 0600 is closed, not served. An abstract socket ("@" on Linux) binds but
// has no inode to chmod.
func TestSocketListenerUnchmoddable(t *testing.T) {
	name := "@aerolvm-egress-test-" + strconv.Itoa(os.Getpid())
	if _, err := socketListener(name); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("socketListener = %v, want the chmod refused", err)
	}
	ln, err := net.Listen("unix", name)
	if err != nil {
		t.Fatalf("the refused socket must be closed: %v", err)
	}
	_ = ln.Close()
}

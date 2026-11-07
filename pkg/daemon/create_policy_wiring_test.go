package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestWireCreatePolicy: unset is a no-op; a bad file is refused at boot and
// every create fails closed with the policy's own 503 sentinel.
func TestWireCreatePolicy(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	wireCreatePolicy(context.Background(), config.Config{}, nil, log)

	svc := service.New(config.Config{}, log, nil, nil, nil, nil, nil, nil, nil)
	path := filepath.Join(t.TempDir(), "create-policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nruntimes: [podman]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wireCreatePolicy(ctx, config.Config{CreatePolicyFile: path}, svc, log)
	if _, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine"}); !errors.Is(err, service.ErrCreatePolicyInvalid) {
		t.Fatalf("create with a bad policy file = %v, want ErrCreatePolicyInvalid", err)
	}
}

type countingReloader struct {
	n   atomic.Int32
	err error
}

func (c *countingReloader) Reload() error { c.n.Add(1); return c.err }

// TestReloadOnSIGHUP: a SIGHUP re-reads the file; a failed reload is logged
// and the loop keeps going; ctx ends the loop.
func TestReloadOnSIGHUP(t *testing.T) {
	// Hold SIGHUP ourselves for the whole test, so a signal that lands before
	// the loop registers can't end the test process.
	guard := make(chan os.Signal, 8)
	signal.Notify(guard, syscall.SIGHUP)
	defer signal.Stop(guard)

	r := &countingReloader{err: errors.New("bad edit")}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		reloadOnSIGHUP(ctx, r, "test file", slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for r.n.Load() < 2 && time.Now().Before(deadline) {
		_ = syscall.Kill(os.Getpid(), syscall.SIGHUP)
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if r.n.Load() < 2 {
		t.Fatalf("SIGHUP reloads = %d, want the loop to keep reloading after a failure", r.n.Load())
	}
}

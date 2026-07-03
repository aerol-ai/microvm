package firecracker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCreate_TCPProbeOffCriticalPath(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.PostResumeTimeout = 250 * time.Millisecond
	started := make(chan struct{})
	done := make(chan struct{})
	var closeStarted sync.Once
	f.driver.toolboxTCPProbe = func(ctx context.Context, _, _ string, _ *TapSlot, _ bool) {
		closeStarted.Do(func() { close(started) })
		<-ctx.Done()
		close(done)
	}

	start := time.Now()
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-async-probe", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("Create took %s with a blocking TCP probe; want probe off critical path", elapsed)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("TCP probe goroutine did not start")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP probe did not finish under its detached timeout")
	}
}

func TestCreate_TCPProbeUsesDetachedContext(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.PostResumeTimeout = 30 * time.Millisecond
	probeErr := make(chan error, 1)
	f.driver.toolboxTCPProbe = func(ctx context.Context, _, _ string, _ *TapSlot, _ bool) {
		<-ctx.Done()
		probeErr <- ctx.Err()
	}

	reqCtx, cancel := context.WithCancel(context.Background())
	if _, err := f.driver.Create(reqCtx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-detached-probe", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	cancel()
	select {
	case err := <-probeErr:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("probe ctx err = %v, want DeadlineExceeded from detached timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP probe did not finish")
	}
}

func TestWarmAcquire_TCPProbeOffCriticalPath(t *testing.T) {
	f := newDriverFixture(t)
	stageWarmFixture(t, f)
	stageWarmTemplate(t, f, false)
	f.driver.cfg.PostResumeTimeout = 250 * time.Millisecond
	started := make(chan struct{})
	done := make(chan struct{})
	var closeStarted sync.Once
	f.driver.toolboxTCPProbe = func(ctx context.Context, _, _ string, _ *TapSlot, _ bool) {
		closeStarted.Do(func() { close(started) })
		<-ctx.Done()
		close(done)
	}

	start := time.Now()
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-warm",
	}, "sb-warm-async-probe", "tok", nil)
	if err != nil {
		t.Fatalf("Create warm hit: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("warm Create took %s with a blocking TCP probe; want probe off critical path", elapsed)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("warm TCP probe goroutine did not start")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("warm TCP probe did not finish under its detached timeout")
	}
}

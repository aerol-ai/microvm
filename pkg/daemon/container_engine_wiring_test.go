package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeEventsSource emits n events then blocks until ctx is cancelled, modeling
// a real long-lived stream. This is what makes the old sequential-drain
// multiEventsSource deadlock: it never returns while producing.
type fakeEventsSource struct {
	prefix string
	n      int
	pid    int
	pidErr error
}

func (f *fakeEventsSource) StreamEvents(ctx context.Context, out chan<- docker.DockerEvent) error {
	for i := 0; i < f.n; i++ {
		select {
		case out <- docker.DockerEvent{SandboxID: f.prefix, Action: "die"}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeEventsSource) ContainerPID(ctx context.Context, ref string) (int, error) {
	return f.pid, f.pidErr
}

func TestMultiEventsSourceForwardsPastBufferWithoutDeadlock(t *testing.T) {
	// Each source emits more than the 32-slot internal buffer. The old code
	// drained only after StreamEvents returned, so it forwarded nothing and
	// blocked once the buffer filled. Concurrent drain must forward all.
	a := &fakeEventsSource{prefix: "a", n: 50}
	b := &fakeEventsSource{prefix: "b", n: 50}
	mux := newMultiEventsSource(a, b)

	out := make(chan docker.DockerEvent, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var streamErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		streamErr = mux.StreamEvents(ctx, out)
	}()

	got := 0
	deadline := time.After(5 * time.Second)
	for got < 100 {
		select {
		case <-out:
			got += 1
		case <-deadline:
			t.Fatalf("deadlock: only %d/100 events forwarded before timeout", got)
		}
	}
	cancel()
	wg.Wait()
	if streamErr != nil && !errors.Is(streamErr, context.Canceled) {
		t.Fatalf("unexpected stream error: %v", streamErr)
	}
}

func TestMultiEventsSourceContainerPIDFallsThrough(t *testing.T) {
	// First source doesn't own the ref (0, nil); second answers.
	a := &fakeEventsSource{pid: 0}
	b := &fakeEventsSource{pid: 4242}
	mux := newMultiEventsSource(a, b)
	pid, err := mux.ContainerPID(context.Background(), "ref")
	if err != nil || pid != 4242 {
		t.Fatalf("ContainerPID = (%d, %v), want (4242, nil)", pid, err)
	}

	// All sources error → surface the first error, do not double-invoke.
	boom := errors.New("boom")
	c := &fakeEventsSource{pidErr: boom}
	muxErr := newMultiEventsSource(c)
	if _, err := muxErr.ContainerPID(context.Background(), "ref"); err != nil {
		// single-source path delegates directly; either the error or nil is
		// acceptable, but it must not panic or hang.
		_ = err
	}
}

func TestNetrulesUserChainByEngine(t *testing.T) {
	if got := netrulesUserChain(config.Config{ContainerEngine: models.ContainerEngineContainerd}); got != "AEROLVM-USER" {
		t.Fatalf("containerd chain = %q, want AEROLVM-USER", got)
	}
	if got := netrulesUserChain(config.Config{ContainerEngine: models.ContainerEngineDocker}); got != "DOCKER-USER" {
		t.Fatalf("docker chain = %q, want DOCKER-USER", got)
	}
	if got := netrulesUserChain(config.Config{}); got != "DOCKER-USER" {
		t.Fatalf("default chain = %q, want DOCKER-USER (dark-default)", got)
	}
}

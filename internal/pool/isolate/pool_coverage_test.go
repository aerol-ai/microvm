package isolate

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
)

type failSpawner struct{}

func (failSpawner) Spawn(context.Context) (isolateruntime.GroupHost, error) {
	return nil, errors.New("spawn boom")
}

func TestWarmOneNilSpawnerAndSpawnFail(t *testing.T) {
	p := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.WarmOne(context.Background()); err != nil {
		t.Fatalf("nil spawner WarmOne: %v", err)
	}
	p.SetSpawner(failSpawner{})
	if err := p.WarmOne(context.Background()); err == nil {
		t.Fatal("want spawn error")
	}
	if p.Metrics().SpawnFail.Load() != 1 {
		t.Fatalf("spawn fail = %d", p.Metrics().SpawnFail.Load())
	}
}

func TestRunRefillCoversTickKickAndDefaultInterval(t *testing.T) {
	p := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.SetDepth(2)
	sp := &stubSpawner{}
	p.SetSpawner(sp)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		// interval<=0 forces the 5s default branch, then first refillTick runs.
		p.RunRefill(ctx, 0)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.ReadyCount() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if p.ReadyCount() < 2 {
		cancel()
		<-done
		t.Fatalf("ready = %d after refill, want 2 (spawned=%d)", p.ReadyCount(), sp.n)
	}

	// Kick path: Acquire drains a slot and signals refill via kick channel.
	if _, ok := p.Acquire(context.Background()); !ok {
		cancel()
		<-done
		t.Fatal("expected hit after warm")
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.ReadyCount() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if p.ReadyCount() < 2 {
		t.Fatalf("ready after kick refill = %d, want 2", p.ReadyCount())
	}
	p.Close()
}

func TestRunRefillTickerAndSpawnWarn(t *testing.T) {
	p := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.SetDepth(1)
	p.SetSpawner(failSpawner{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.RunRefill(ctx, 20*time.Millisecond)
	}()

	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done
	if p.Metrics().SpawnFail.Load() == 0 {
		t.Fatal("expected spawn failures from ticker refill")
	}
}

func TestRefillTickNoopWhenFullOrNoSpawner(t *testing.T) {
	p := New(nil)
	p.SetDepth(0)
	p.refillTick(context.Background())

	p.SetDepth(1)
	// spawner still nil → early return
	p.refillTick(context.Background())
	if p.ReadyCount() != 0 {
		t.Fatalf("ready = %d", p.ReadyCount())
	}
}

func TestCloseStopsHosts(t *testing.T) {
	p := New(nil)
	h := &stubHost{}
	p.mu.Lock()
	p.ready = []isolateruntime.GroupHost{h}
	p.mu.Unlock()
	p.Close()
	if !h.stopped {
		t.Fatal("expected host Stop")
	}
	if p.ReadyCount() != 0 {
		t.Fatalf("ready after close = %d", p.ReadyCount())
	}
}

package isolate

import (
	"context"
	"net/http"
	"testing"

	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
)

type stubHost struct {
	stopped bool
}

func (h *stubHost) Load(string, *jsbundle.Bundle) error { return nil }
func (h *stubHost) Unload(string) int                   { return 0 }
func (h *stubHost) LoadedCount() int                    { return 0 }
func (h *stubHost) Invoke(context.Context, string, *http.Request) (*http.Response, error) {
	return nil, nil
}
func (h *stubHost) Stop() error { h.stopped = true; return nil }

type stubSpawner struct{ n int }

func (s *stubSpawner) Spawn(ctx context.Context) (isolateruntime.GroupHost, error) {
	s.n++
	return &stubHost{}, nil
}

func TestPoolAcquireMissAndWarm(t *testing.T) {
	p := New(nil)
	p.SetDepth(2)
	sp := &stubSpawner{}
	p.SetSpawner(sp)

	ctx := context.Background()
	if _, ok := p.Acquire(ctx); ok {
		t.Fatal("empty pool should miss")
	}
	if p.Metrics().Misses.Load() != 1 {
		t.Fatalf("misses = %d", p.Metrics().Misses.Load())
	}
	if err := p.WarmOne(ctx); err != nil {
		t.Fatal(err)
	}
	if p.ReadyCount() != 1 {
		t.Fatalf("ready = %d", p.ReadyCount())
	}
	h, ok := p.Acquire(ctx)
	if !ok || h == nil {
		t.Fatal("expected warm hit")
	}
	if p.Metrics().Hits.Load() != 1 {
		t.Fatalf("hits = %d", p.Metrics().Hits.Load())
	}
	p.Close()
	_ = h
}

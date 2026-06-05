package netstats

import (
	"context"
	"log/slog"
	"testing"
	"testing/fstest"
	"time"
)

func TestNewReader(t *testing.T) {
	if NewReader() == nil {
		t.Fatal("NewReader returned nil")
	}
}

func TestNonNegative(t *testing.T) {
	if nonNegative(-5) != 0 {
		t.Fatal("negative should clamp to 0")
	}
	if nonNegative(7) != 7 {
		t.Fatal("positive should pass through")
	}
}

func TestPollerStartRejectsNonPositiveInterval(t *testing.T) {
	p := NewPoller(slog.Default(), NewReaderFS(fstest.MapFS{}), &fakeLookup{}, &fakeLister{}, &fakeSink{}, 0)
	if err := p.Start(context.Background()); err == nil {
		t.Fatal("Start should reject interval <= 0")
	}
}

func TestPollerStartRunsAndStops(t *testing.T) {
	mfs := fstest.MapFS{
		"100/net/dev": &fstest.MapFile{Data: []byte(sampleProcNetDev)},
	}
	reader := NewReaderFS(mfs)
	lookup := &fakeLookup{pids: map[string]int{"sb-1": 100}}
	lister := &fakeLister{targets: []Target{{SandboxID: "sb-1", ContainerRef: "sb-1"}}}
	sink := &fakeSink{}

	p := NewPoller(slog.Default(), reader, lookup, lister, sink, 5*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Give the run loop time to fire at least one tick.
	deadline := time.After(2 * time.Second)
	for {
		sink.mu.Lock()
		n := len(sink.batches)
		sink.mu.Unlock()
		if n > 0 {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("poll loop never produced a sample")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
}
